#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import json
import sys
import getopt
import logging
from shadowsocks.common import to_bytes, to_str, IPNetwork
from shadowsocks import encrypt


VERBOSE_LEVEL = 5

verbose = 0


def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[1] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)


def print_exception(e):
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()


def print_shadowsocks():
    version = ''
    try:
        from importlib.metadata import version as get_version
        version = get_version('shadowsocks')
    except Exception:
        try:
            import pkg_resources
            version = pkg_resources.get_distribution('shadowsocks').version
        except Exception:
            pass
    print('Shadowsocks %s' % version)


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def check_config(config, is_local):
    if config.get('daemon', None) in ('stop', 'status'):
        # no need to specify configuration for daemon stop / status
        return

    if is_local and not config.get('password', None):
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)

    if not is_local and not config.get('password', None) \
            and not config.get('port_password', None):
        logging.error('password or port_password not specified')
        print_help(is_local)
        sys.exit(2)

    if 'local_port' in config:
        config['local_port'] = int(config['local_port'])

    if 'server_port' in config and type(config['server_port']) != list:
        config['server_port'] = int(config['server_port'])

    if config.get('local_address', '') in [b'0.0.0.0']:
        logging.warning('warning: local set to listen on 0.0.0.0, '
                        'it\'s not safe')
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warning('warning: server set to listen on %s:%s, '
                        'are you sure?' %
                        (to_str(config['server']), config['server_port']))
    method = (config.get('method', '') or '').lower()
    if encrypt.is_aead2022(method):
        if config.get('port_password'):
            passwords = list(config['port_password'].values())
        else:
            passwords = [config['password']]
        for password in passwords:
            try:
                encrypt.aead2022.decode_psk(password, method)
            except ValueError as e:
                logging.error(e)
                sys.exit(2)
    elif not encrypt.is_aead(method):
        logging.warning('warning: %s is a legacy stream cipher: it has no '
                        'integrity protection and is easily detected and '
                        'blocked by active probing. Please switch both the '
                        'server and the clients to a modern cipher such as '
                        '2022-blake3-aes-256-gcm or chacha20-ietf-poly1305',
                        method)
    if config.get('timeout', 300) < 100:
        logging.warning('warning: your timeout %d seems too short' %
                        int(config.get('timeout')))
    if config.get('timeout', 300) > 600:
        logging.warning('warning: your timeout %d seems too long' %
                        int(config.get('timeout')))
    if config.get('password') in [b'mypassword']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        sys.exit(1)
    if config.get('user', None) is not None:
        if os.name != 'posix':
            logging.error('user can be used only on Unix')
            sys.exit(1)

    if encrypt.is_aead2022(method) and not config.get('password'):
        # port_password only; the keys have been checked above
        return
    encrypt.try_cipher(config['password'], config['method'])


def get_config(is_local):
    global verbose

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s')
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'user=',
                    'version']
    else:
        shortopts = 'hd:s:p:k:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'workers=',
                    'forbidden-ip=', 'user=', 'version']
    try:
        config_path = find_config()
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = json.loads(f.read().decode('utf8'),
                                        object_hook=_decode_dict)
                except ValueError as e:
                    logging.error('found an error in config.json: %s', e)
                    sys.exit(1)
        else:
            config = {}

        v_count = 0
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = to_bytes(value)
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = to_str(value)
            elif key == '-m':
                config['method'] = to_str(value)
            elif key == '-b':
                config['local_address'] = to_str(value)
            elif key == '-v':
                v_count += 1
                # '-vv' turns on more verbose mode
                config['verbose'] = v_count
            elif key == '-t':
                config['timeout'] = int(value)
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--workers':
                config['workers'] = int(value)
            elif key == '--user':
                config['user'] = to_str(value)
            elif key == '--forbidden-ip':
                config['forbidden_ip'] = to_str(value).split(',')
            elif key in ('-h', '--help'):
                if is_local:
                    print_local_help()
                else:
                    print_server_help()
                sys.exit(0)
            elif key == '--version':
                print_shadowsocks()
                sys.exit(0)
            elif key == '-d':
                config['daemon'] = to_str(value)
            elif key == '--pid-file':
                config['pid-file'] = to_str(value)
            elif key == '--log-file':
                config['log-file'] = to_str(value)
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
    except getopt.GetoptError as e:
        print(e, file=sys.stderr)
        print_help(is_local)
        sys.exit(2)

    if not config:
        logging.error('config not specified')
        print_help(is_local)
        sys.exit(2)

    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-gcm'))
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocks.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocks.log')
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)
    if is_local:
        if config.get('server', None) is None and \
                config.get('daemon', None) not in ('stop', 'status'):
            logging.error('server addr not specified')
            print_local_help()
            sys.exit(2)
        elif config.get('server', None) is not None:
            config['server'] = to_str(config['server'])
    else:
        config['server'] = to_str(config.get('server', '0.0.0.0'))
        try:
            config['forbidden_ip'] = \
                IPNetwork(config.get('forbidden_ip', '127.0.0.0/8,::1/128'))
        except Exception as e:
            logging.error(e)
            sys.exit(2)
    config['server_port'] = config.get('server_port', 8388)

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    check_config(config, is_local)

    return config


def print_help(is_local):
    if is_local:
        print_local_help()
    else:
        print_server_help()


def print_local_help():
    print('''usage: sslocal [OPTION]...
A fast, secure tunnel proxy.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address
  -p SERVER_PORT         server port, default: 8388
  -b LOCAL_ADDR          local binding address, default: 127.0.0.1
  -l LOCAL_PORT          local port, default: 1080
  -k PASSWORD            password (base64 key for 2022-* methods)
  -m METHOD              encryption method, default: aes-256-gcm
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart/status
                         daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/zhuanyi/shadowsocks>
''')


def print_server_help():
    print('''usage: ssserver [OPTION]...
A fast, secure tunnel proxy.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address, default: 0.0.0.0
  -p SERVER_PORT         server port, default: 8388
  -k PASSWORD            password (base64 key for 2022-* methods)
  -m METHOD              encryption method, default: aes-256-gcm
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS      number of workers, available on Unix/Linux
  --forbidden-ip IPLIST  comma seperated IP list forbidden to connect

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart/status
                         daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/zhuanyi/shadowsocks>
''')


def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv
