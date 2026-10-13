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

"""Interactive editor for the ssserver config file, in the spirit of
`rclone config`: choose the cipher, the ports and their passwords (or let
it generate random keys), then save, restart the service and show QR codes.
"""

from __future__ import absolute_import, division, print_function, \
    with_statement

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time

from shadowsocks import sslink

DEFAULT_CONFIG = '/etc/shadowsocks.json'
SERVICE = 'shadowsocks-server'
SERVICE_USER = 'shadowsocks'

# (method, description); the first one is the default
METHODS = [
    ('2022-blake3-aes-256-gcm', 'recommended'),
    ('2022-blake3-aes-128-gcm', ''),
    ('2022-blake3-chacha20-poly1305', 'UDP needs libsodium'),
    ('chacha20-ietf-poly1305', 'AEAD, for clients without 2022 support, '
                               'e.g. the official Windows client'),
    ('aes-256-gcm', 'AEAD'),
    ('aes-128-gcm', 'AEAD'),
]


def key_len(method):
    """Key size in bytes for 2022 ciphers, None for password based ones."""
    if method == '2022-blake3-aes-128-gcm':
        return 16
    if method.startswith('2022-'):
        return 32
    return None


def generate_password(method):
    # same as `openssl rand -base64 N`
    return base64.b64encode(os.urandom(key_len(method) or 32)) \
        .decode('ascii')


def check_password(method, password):
    """Returns an error message, or None if the password can be used."""
    if not password:
        return 'the password can not be empty'
    n = key_len(method)
    if n is None:
        return None
    try:
        key = base64.b64decode(password.encode('ascii'), validate=True)
    except (ValueError, UnicodeError, TypeError):
        key = None
    if key is None or len(key) != n:
        return ('%s needs a base64 encoded %d byte key, like the output of '
                '`openssl rand -base64 %d`' % (method, n, n))
    return None


def parse_ports(text):
    ports = []
    for item in text.replace(' ', ',').split(','):
        if not item:
            continue
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise ValueError('not a valid port: %s' % item)
        if int(item) in ports:
            raise ValueError('port %s is listed twice' % item)
        ports.append(int(item))
    if not ports:
        raise ValueError('at least one port is needed')
    return ports


def ports_and_passwords(config):
    """[(port, password)] from either port_password or server_port."""
    if config.get('port_password'):
        return sorted(((int(p), pw) for p, pw in
                       config['port_password'].items()))
    ports = config.get('server_port', 8388)
    if not isinstance(ports, list):
        ports = [ports]
    return [(int(p), config.get('password', '')) for p in ports]


def set_ports_and_passwords(config, items):
    for k in ('server_port', 'password', 'port_password'):
        config.pop(k, None)
    items = sorted(items)
    passwords = set(pw for _, pw in items)
    if len(items) == 1:
        config['server_port'] = items[0][0]
        config['password'] = items[0][1]
    elif len(passwords) == 1:
        config['server_port'] = [p for p, _ in items]
        config['password'] = items[0][1]
    else:
        config['port_password'] = dict((str(p), pw) for p, pw in items)


class Configurator(object):
    def __init__(self, path, ask=None, out=None, installer=False):
        self.path = path
        self.ask = ask or _input
        self.out = out or print
        self.installer = installer

    # prompts

    def prompt(self, text, default=None):
        suffix = ' [%s]' % default if default not in (None, '') else ''
        answer = self.ask('%s%s: ' % (text, suffix)).strip()
        return answer if answer else (default or '')

    def confirm(self, text, default=True):
        hint = 'Y/n' if default else 'y/N'
        while True:
            answer = self.ask('%s [%s]: ' % (text, hint)).strip().lower()
            if not answer:
                return default
            if answer in ('y', 'yes'):
                return True
            if answer in ('n', 'no'):
                return False

    def choose_method(self, current=None):
        self.out('Encryption method:')
        default = 1
        for i, (method, desc) in enumerate(METHODS, 1):
            if method == current:
                default = i
            self.out('  %d) %-31s %s' % (i, method, desc))
        while True:
            answer = self.prompt('Choose a number or type a method',
                                 str(default))
            if answer.isdigit() and 1 <= int(answer) <= len(METHODS):
                return METHODS[int(answer) - 1][0]
            if answer.lower() in [m for m, _ in METHODS] or \
                    _is_known_method(answer.lower()):
                return answer.lower()
            self.out('  unknown method: %s' % answer)

    def ask_password(self, method, port, current=None):
        while True:
            if current:
                text = ('Password for port %d [press Enter to keep the '
                        'current one, "g" to generate a new one]' % port)
            else:
                text = ('Password for port %d [press Enter to generate '
                        'one]' % port)
            answer = self.ask(text + ': ').strip()
            if not answer and current:
                return current
            if not answer or answer.lower() == 'g':
                password = generate_password(method)
                self.out('  generated: %s' % password)
                return password
            error = check_password(method, answer)
            if error is None:
                return answer
            self.out('  %s; press Enter to generate one' % error)

    def ask_ports(self, default):
        while True:
            answer = self.prompt('Server port(s), separated by commas',
                                 default)
            try:
                return parse_ports(answer)
            except ValueError as e:
                self.out('  %s' % e)

    # flows

    def new_config(self, base=None):
        config = dict(base or {})
        self.out('')
        method = self.choose_method(config.get('method'))
        config['method'] = method
        self.out('')
        ports = self.ask_ports('8388')
        items = []
        for port in ports:
            items.append((port, self.ask_password(method, port)))
        set_ports_and_passwords(config, items)
        self.out('')
        config['server'] = self.prompt(
            'Listen address (0.0.0.0 = all IPv4 addresses)',
            config.get('server', '0.0.0.0'))
        while True:
            timeout = self.prompt('Timeout in seconds',
                                  str(config.get('timeout', 300)))
            if timeout.isdigit() and int(timeout) > 0:
                config['timeout'] = int(timeout)
                break
            self.out('  please enter a number of seconds')
        config.setdefault('fast_open', False)
        return config

    def edit_ports(self, config):
        method = config.get('method', 'aes-256-gcm')
        items = ports_and_passwords(config)
        while True:
            self.out('')
            self.out('Ports:')
            for i, (port, _) in enumerate(items, 1):
                self.out('  %d) %d' % (i, port))
            self.out('a) Add a port')
            self.out('p) Change the password of a port')
            self.out('d) Delete a port')
            self.out('b) Back')
            answer = self.prompt('a/p/d/b').lower()
            if answer == 'a':
                try:
                    port = parse_ports(self.prompt('New port'))[0]
                except ValueError as e:
                    self.out('  %s' % e)
                    continue
                if port in [p for p, _ in items]:
                    self.out('  port %d already exists' % port)
                    continue
                items.append((port, self.ask_password(method, port)))
            elif answer in ('p', 'd'):
                index = self._pick_port(items)
                if index is None:
                    continue
                port, password = items[index]
                if answer == 'p':
                    items[index] = (port, self.ask_password(method, port,
                                                            password))
                elif len(items) == 1:
                    self.out('  can not delete the only port')
                else:
                    del items[index]
            elif answer == 'b':
                set_ports_and_passwords(config, items)
                return config

    def _pick_port(self, items):
        answer = self.prompt('Port (or its number in the list)')
        if answer.isdigit():
            for i, (port, _) in enumerate(items):
                if port == int(answer):
                    return i
            if 1 <= int(answer) <= len(items):
                return int(answer) - 1
        self.out('  no such port: %s' % answer)
        return None

    def change_method(self, config):
        old = config.get('method', 'aes-256-gcm')
        method = self.choose_method(old)
        items = ports_and_passwords(config)
        bad = [p for p, pw in items if check_password(method, pw)]
        if bad:
            self.out('The current passwords can not be used with %s, which '
                     'needs base64 keys.' % method)
            if self.confirm('Generate new keys for all ports?'):
                items = [(p, generate_password(method)) for p, _ in items]
                for p, pw in items:
                    self.out('  port %d: %s' % (p, pw))
            else:
                items = [(p, self.ask_password(method, p) if p in bad else pw)
                         for p, pw in items]
        config['method'] = method
        set_ports_and_passwords(config, items)
        if method != old:
            self.out('Remember to change the method (and password) in every '
                     'client too.')
        return config

    def summary(self, config):
        self.out('')
        self.out('  method:  %s' % config.get('method'))
        self.out('  listen:  %s' % config.get('server', '0.0.0.0'))
        for port, password in ports_and_passwords(config):
            self.out('  port %-5d password: %s' % (port, password))

    def run(self):
        config = load(self.path)
        if config is None:
            self.out('No config found at %s, let\'s create one.' % self.path)
            config = self.new_config()
            return self.finish(config, {})
        original = json.loads(json.dumps(config))
        while True:
            self.out('')
            self.out('Current config %s:' % self.path)
            self.summary(config)
            self.out('')
            self.out('e) Edit ports and passwords')
            self.out('m) Change encryption method')
            self.out('n) New config (start over)')
            self.out('s) Save and quit')
            self.out('q) Quit without saving')
            answer = self.prompt('e/m/n/s/q').lower()
            if answer == 'e':
                config = self.edit_ports(config)
            elif answer == 'm':
                config = self.change_method(config)
            elif answer == 'n':
                config = self.new_config(
                    dict((k, v) for k, v in config.items()
                         if k not in ('server_port', 'password',
                                      'port_password')))
            elif answer == 's':
                return self.finish(config, original)
            elif answer == 'q':
                return False

    def finish(self, config, original):
        self.summary(config)
        self.out('')
        if config == original:
            self.out('Nothing changed.')
            return False
        if not self.confirm('Save to %s?' % self.path):
            self.out('Not saved.')
            return False
        backup = save(self.path, config)
        self.out('Saved %s.' % self.path)
        if backup:
            self.out('The previous version is in %s.' % backup)
        if self.installer:
            return True
        if service_installed() and \
                self.confirm('Restart %s now to use it?' % SERVICE):
            r = subprocess.call(['systemctl', 'restart', SERVICE])
            self.out('Restarted.' if r == 0 else
                     'Restart failed, see: journalctl -u %s' % SERVICE)
        if self.confirm('Show a QR code to scan with a client?'):
            show_qr(config, self)
        return True


def _is_known_method(method):
    try:
        from shadowsocks import encrypt
    except Exception:
        return False
    return method in encrypt.method_supported or encrypt.is_aead(method) or \
        encrypt.is_aead2022(method)


def _input(prompt):
    try:
        return raw_input(prompt)  # noqa: F821 (Python 2)
    except NameError:
        return input(prompt)


def load(path):
    try:
        with open(path, 'rb') as f:
            return json.loads(f.read().decode('utf-8'))
    except (IOError, OSError):
        return None


def save(path, config):
    """Writes the config readable by root and the service user only.
    Returns the path of the backup of the previous version, if any."""
    backup = None
    if os.path.exists(path):
        backup = '%s.bak-%s' % (path, time.strftime('%Y%m%d%H%M%S'))
        shutil.copy2(path, backup)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f, indent=4, sort_keys=True)
        f.write('\n')
    try:
        import grp
        gid = grp.getgrnam(SERVICE_USER).gr_gid
        os.chown(tmp, 0, gid)
        os.chmod(tmp, 0o640)
    except (ImportError, KeyError, OSError):
        pass
    os.rename(tmp, path)
    return backup


def service_installed():
    which = getattr(shutil, 'which', None)
    return bool(which and which('systemctl')) and \
        os.path.exists('/etc/systemd/system/%s.service' % SERVICE)


def show_qr(config, ui):
    host = sslink.guess_host(config) or ''
    host = ui.prompt('Server address to put in the link (public IP or '
                     'domain)', host)
    if not host:
        return
    links = sslink.links_from_config(config, host, sslink.socket.gethostname())
    chosen = sslink.choose(links, None, ui.ask)
    for port, link in chosen or []:
        ui.out('\nport %d:' % port)
        if not sslink.print_qr(link):
            ui.out('(install qrencode to show QR codes: '
                   'apt-get install qrencode)')
        ui.out(link)


def main():
    parser = argparse.ArgumentParser(
        prog='ssconfig',
        description='Create or edit the shadowsocks server config '
                    'interactively.')
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG,
                        help='config file (default: %(default)s)')
    parser.add_argument('--installer', action='store_true',
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    directory = os.path.dirname(os.path.abspath(args.config))
    if not os.access(directory, os.W_OK) or (
            os.path.exists(args.config) and
            not os.access(args.config, os.W_OK)):
        print('can not write %s, run it with sudo' % args.config,
              file=sys.stderr)
        sys.exit(1)
    try:
        saved = Configurator(args.config, installer=args.installer).run()
    except (KeyboardInterrupt, EOFError):
        print('\naborted, nothing saved')
        sys.exit(1)
    sys.exit(0 if saved else 2)


def _scripted(answers):
    answers = list(answers)
    output = []

    def ask(prompt):
        output.append(prompt)
        return answers.pop(0)
    return ask, output.append, output


def test_new_config():
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), 'ss.json')
    ask, out, output = _scripted([
        '',              # method: default (2022-blake3-aes-256-gcm)
        '8388, 443',     # ports
        '',              # 8388: generate
        'not a key',     # 443: rejected
        'bVdvo2Ffq0cDNMn+0kXfR9Y2Z6YDoHn2bZyBq3Ow+6k=',
        '', '',          # listen address, timeout
        'y',             # save
    ])
    assert Configurator(path, ask, out, installer=True).run()
    config = load(path)
    assert config['method'] == '2022-blake3-aes-256-gcm'
    items = dict(ports_and_passwords(config))
    assert items[443] == 'bVdvo2Ffq0cDNMn+0kXfR9Y2Z6YDoHn2bZyBq3Ow+6k='
    assert check_password(config['method'], items[8388]) is None
    assert any('needs a base64 encoded 32 byte key' in str(o)
               for o in output)
    assert oct(os.stat(path).st_mode & 0o777) in ('0o600', '0o640')


def test_edit_config():
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), 'ss.json')
    save(path, {'server': '0.0.0.0', 'server_port': 8388,
                'password': 'old password', 'method': 'aes-256-cfb',
                'workers': 2})
    ask, out, output = _scripted([
        'm', '1', 'y',   # 2022 method, generate new keys
        'e', 'a', '9000', '',   # add port 9000 with a generated key
        'b',
        's', 'y',        # save
    ])
    assert Configurator(path, ask, out, installer=True).run()
    config = load(path)
    assert config['method'] == '2022-blake3-aes-256-gcm'
    assert config['workers'] == 2
    items = dict(ports_and_passwords(config))
    assert sorted(items) == [8388, 9000]
    for pw in items.values():
        assert check_password(config['method'], pw) is None
    assert any(f.startswith('ss.json.bak-')
               for f in os.listdir(os.path.dirname(path)))


def test_helpers():
    assert parse_ports('8388, 443 9000') == [8388, 443, 9000]
    for bad in ('', '0', '70000', 'abc', '1,1'):
        try:
            parse_ports(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    assert check_password('aes-256-gcm', 'anything') is None
    assert check_password('2022-blake3-aes-128-gcm',
                          generate_password('2022-blake3-aes-128-gcm')) \
        is None
    assert check_password('2022-blake3-aes-256-gcm',
                          generate_password('2022-blake3-aes-128-gcm'))
    c = {}
    set_ports_and_passwords(c, [(2, 'a'), (1, 'a')])
    assert c == {'server_port': [1, 2], 'password': 'a'}
    set_ports_and_passwords(c, [(1, 'a'), (2, 'b')])
    assert c == {'port_password': {'1': 'a', '2': 'b'}}


if __name__ == '__main__':
    main()
