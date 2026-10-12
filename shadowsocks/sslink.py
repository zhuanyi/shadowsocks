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
    if method.startswith('2022-'):
        # SIP002: AEAD-2022 user info is percent-encoded, not base64
        user_info = '%s:%s' % (method, quote(password, safe=''))
    else:
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


def main():
    parser = argparse.ArgumentParser(
        prog='sslink',
        description='Print ss:// links and QR codes for a shadowsocks '
                    'server config, to import into clients.')
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG,
                        help='config file (default: %(default)s)')
    parser.add_argument('-H', '--host',
                        help='public address or domain of the server '
                             '(default: guessed)')
    parser.add_argument('-n', '--name',
                        help='name shown in the client (default: host name)')
    parser.add_argument('--no-qr', action='store_true',
                        help='only print the links')
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
    qr_missing = False
    for port, link in links:
        print('port %d:\n%s\n' % (port, link))
        if not args.no_qr:
            if not print_qr(link):
                qr_missing = True
            print()
    if qr_missing:
        print('(install qrencode to show QR codes: apt-get install qrencode)',
              file=sys.stderr)
    print('Keep these private: anyone with a link can use your server.',
          file=sys.stderr)


def test_links():
    psk = 'bVdvo2Ffq0cDNMn+0kXfR9Y2Z6YDoHn2bZyBq3Ow+6k='
    link = make_link('1.2.3.4', 8388, '2022-blake3-aes-256-gcm', psk,
                     'my vps')
    assert link == ('ss://2022-blake3-aes-256-gcm:'
                    'bVdvo2Ffq0cDNMn%2B0kXfR9Y2Z6YDoHn2bZyBq3Ow%2B6k%3D'
                    '@1.2.3.4:8388#my%20vps')
    # the example from SIP002
    assert make_link('192.168.100.1', 8888, 'aes-128-gcm', 'test') == \
        'ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888'
    assert make_link('::1', 8388, 'aes-128-gcm', 'test') == \
        'ss://YWVzLTEyOC1nY206dGVzdA@[::1]:8388'
    links = links_from_config({'port_password': {'8389': 'b', '8388': 'a'},
                               'method': 'aes-256-gcm'}, 'h', 'n')
    assert [p for p, _ in links] == [8388, 8389]
    assert links[0][1].endswith('@h:8388#n-8388')


if __name__ == '__main__':
    main()
