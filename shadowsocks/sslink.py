#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2026 shadowsocks contributors
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Print ss:// links (SIP002) and QR codes for a server config, to import
into clients such as the Android app or v2rayN."""

from __future__ import absolute_import, division, print_function, \
    with_statement

import argparse
import base64
import json
import socket
import subprocess
import sys

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

DEFAULT_CONFIG = '/etc/shadowsocks.json'


def make_link(host, port, method, password, name=None):
    method = method.lower()
    # SIP002 user info: base64url("method:password") without padding.
    # SIP002 also allows plain percent-encoded "method:password" for the 2022
    # ciphers, but the Android app only understands the base64 form, while
    # shadowsocks-rust, Xray, sing-box etc. accept both.
    user_info = base64.urlsafe_b64encode(
        ('%s:%s' % (method, password)).encode('utf-8'))
    user_info = user_info.decode('ascii').rstrip('=')
    if ':' in host and not host.startswith('['):
        host = '[%s]' % host
    link = 'ss://%s@%s:%d' % (user_info, host, int(port))
    if name:
        link += '#' + quote(name, safe='')
    return link


def links_from_config(config, host, name=None):
    method = config.get('method') or 'aes-256-gcm'
    if config.get('port_password'):
        servers = sorted(config['port_password'].items(),
                         key=lambda kv: int(kv[0]))
    else:
        ports = config.get('server_port', 8388)
        if not isinstance(ports, list):
            ports = [ports]
        servers = [(p, config.get('password', '')) for p in ports]
    result = []
    for port, password in servers:
        tag = '%s-%s' % (name, port) if name and len(servers) > 1 else name
        result.append((int(port), make_link(host, port, method, password,
                                            tag)))
    return result


def guess_host(config):
    server = config.get('server')
    if isinstance(server, list):
        server = server[0] if server else None
    if server and server not in ('0.0.0.0', '::', '127.0.0.1', '::1',
                                 'localhost'):
        return server
    # the address of the interface used to reach the internet; no packet is
    # actually sent
    for family, target in ((socket.AF_INET, '8.8.8.8'),
                           (socket.AF_INET6, '2001:4860:4860::8888')):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.connect((target, 53))
            addr = s.getsockname()[0]
            s.close()
            return addr
        except (OSError, socket.error):
            pass
    return None


def is_private(host):
    try:
        import ipaddress
        addr = ipaddress.ip_address(host if bytes != str else
                                    host.decode('utf-8'))
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False  # a host name


def print_qr(text):
    try:
        out = subprocess.check_output(['qrencode', '-t', 'ansiutf8', text])
        sys.stdout.write(out.decode('utf-8'))
        return True
    except (OSError, subprocess.CalledProcessError):
        pass
    try:
        import qrcode
        qr = qrcode.QRCode(border=2)
        qr.add_data(text)
        qr.print_ascii(invert=True)
        return True
    except ImportError:
        return False


def choose(links, answer=None, ask=None):
    """Pick the links to show a QR code for, like `pivpn -qr`.

    answer is a port, a 1-based index, 'all', or None to ask (if there is
    more than one port). Returns a list of (port, link), or None.
    """
    if answer is None:
        if len(links) == 1:
            return links
        if ask is None:
            if not sys.stdin.isatty():
                print('several ports in the config; pick one with '
                      '-qr PORT (or -qr all)', file=sys.stderr)
                return None
            ask = _input
        print('::  Server ports  ::')
        for i, (port, _) in enumerate(links, 1):
            print('  %d) %d' % (i, port))
        answer = ask('Please enter the index or port to show, '
                     'or "all": ')
    answer = str(answer).strip()
    if answer.lower() == 'all':
        return links
    if answer.isdigit():
        n = int(answer)
        for port, link in links:
            if port == n:
                return [(port, link)]
        if 1 <= n <= len(links):
            return [links[n - 1]]
    print('no such port or index: %s' % answer, file=sys.stderr)
    return None


def _input(prompt):
    try:
        return raw_input(prompt)  # noqa: F821 (Python 2)
    except NameError:
        return input(prompt)


def main():
    parser = argparse.ArgumentParser(
        prog='sslink',
        description='Print ss:// links for a shadowsocks server config, or '
                    'a QR code to scan with a client.',
        epilog='examples:  sslink            list the links of all ports\n'
               '           sslink -qr        QR code (asks which port if '
               'there are several)\n'
               '           sslink -qr 8389   QR code for port 8389\n'
               '           sslink -qr all    QR codes for all ports',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-qr', '--qr', nargs='?', const='', default=None,
                        metavar='PORT',
                        help='show a QR code for PORT (a port, its index in '
                             'the list or "all"); asks if omitted and there '
                             'are several ports')
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG,
                        help='config file (default: %(default)s)')
    parser.add_argument('-H', '--host',
                        help='public address or domain of the server '
                             '(default: guessed)')
    parser.add_argument('-n', '--name',
                        help='name shown in the client (default: host name)')
    args = parser.parse_args()

    try:
        with open(args.config, 'rb') as f:
            config = json.loads(f.read().decode('utf-8'))
    except (IOError, OSError, ValueError) as e:
        print('can not read %s: %s' % (args.config, e), file=sys.stderr)
        sys.exit(1)

    host = args.host or guess_host(config)
    if not host:
        print('can not guess the server address, use -H', file=sys.stderr)
        sys.exit(1)
    if not args.host and is_private(host):
        print('warning: %s is a private address; if the server is behind '
              'NAT, pass its public address with -H\n' % host,
              file=sys.stderr)
    name = args.name or socket.gethostname()

    links = links_from_config(config, host, name)
    if not links:
        print('no server ports found in %s' % args.config, file=sys.stderr)
        sys.exit(1)

    if args.qr is None:
        for port, link in links:
            print('port %d:\n%s\n' % (port, link))
        if len(links) == 1:
            print('run "sslink -qr" for a QR code', file=sys.stderr)
        else:
            print('run "sslink -qr" for a QR code (asks which port)',
                  file=sys.stderr)
    else:
        chosen = choose(links, args.qr or None)
        if not chosen:
            sys.exit(1)
        for port, link in chosen:
            print('\nport %d:' % port)
            if not print_qr(link):
                print('(install qrencode to show QR codes: '
                      'apt-get install qrencode)', file=sys.stderr)
            print(link)
    print('Keep these private: anyone with a link can use your server.',
          file=sys.stderr)


def test_links():
    psk = 'bVdvo2Ffq0cDNMn+0kXfR9Y2Z6YDoHn2bZyBq3Ow+6k='
    link = make_link('1.2.3.4', 8388, '2022-blake3-aes-256-gcm', psk,
                     'my vps')
    assert link == ('ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206YlZkdm8yRmZxMGNE'
                    'Tk1uKzBrWGZSOVkyWjZZRG9IbjJiWnlCcTNPdys2az0'
                    '@1.2.3.4:8388#my%20vps')
    assert android_parse(link) == ('2022-blake3-aes-256-gcm', psk,
                                   '1.2.3.4', 8388, 'my vps')
    # the example from SIP002
    assert make_link('192.168.100.1', 8888, 'aes-128-gcm', 'test') == \
        'ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888'
    assert make_link('::1', 8388, 'aes-128-gcm', 'test') == \
        'ss://YWVzLTEyOC1nY206dGVzdA@[::1]:8388'
    links = links_from_config({'port_password': {'8389': 'b', '8388': 'a'},
                               'method': 'aes-256-gcm'}, 'h', 'n')
    assert [p for p, _ in links] == [8388, 8389]
    assert links[0][1].endswith('@h:8388#n-8388')


def android_parse(link):
    """How the shadowsocks Android app reads a SIP002 link (Profile.kt:
    the user info is always base64 decoded), for tests."""
    from urllib.parse import urlsplit, unquote
    u = urlsplit(link)
    user_info = u.netloc.rsplit('@', 1)[0]
    decoded = base64.urlsafe_b64decode(user_info + '=' * (-len(user_info) % 4))
    method, password = decoded.decode('utf-8').split(':', 1)
    return method, password, u.hostname, u.port, unquote(u.fragment)


def test_choose():
    links = [(8388, 'a'), (8389, 'b'), (443, 'c')]
    assert choose(links, '8389') == [(8389, 'b')]
    assert choose(links, '2') == [(8389, 'b')]
    assert choose(links, 'all') == links
    assert choose(links, '9999') is None
    assert choose(links, ask=lambda prompt: '3') == [(443, 'c')]
    assert choose(links[:1]) == links[:1]


if __name__ == '__main__':
    main()
