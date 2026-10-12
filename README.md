shadowsocks
===========

[![PyPI version]][PyPI]
[![Build Status]][Travis CI]
[![Coverage Status]][Coverage]

A fast tunnel proxy that helps you bypass firewalls.

Server
------

### Install (Debian / Ubuntu, systemd)

    git clone https://github.com/zhuanyi/shadowsocks.git
    cd shadowsocks
    sudo ./install.sh

The script installs shadowsocks into a virtualenv in `/opt/shadowsocks`,
links `ssserver` / `sslocal` into `/usr/local/bin`, creates
`/etc/shadowsocks.json` with a random password (if you don't have one yet)
and enables the `shadowsocks-server` systemd service. No source files need
patching any more, and it works with Python 3.8 - 3.13 and OpenSSL 1.1 / 3.x
(Debian 11, 12, 13; Ubuntu 20.04+).

Run it again after `git pull` to upgrade. An existing config is kept as is.

Manage the service with:

    sudo systemctl status shadowsocks-server
    sudo systemctl restart shadowsocks-server
    sudo journalctl -u shadowsocks-server -f

To install by hand instead: `pip install .` (inside a virtualenv) and copy
`systemd/shadowsocks-server.service` to `/etc/systemd/system/`.

If you installed an older version with `python setup.py install`, the old
copy (`/usr/local/lib/python3*/dist-packages/shadowsocks-*.egg`) is no longer
used once `install.sh` has run and can be deleted.

### Ciphers

Use an **AEAD cipher**, on the server and on every client:

| method                    | notes                                       |
|---------------------------|---------------------------------------------|
| `chacha20-ietf-poly1305`  | recommended, fast everywhere, esp. phones   |
| `aes-256-gcm`             | default; fastest on CPUs with AES-NI        |
| `aes-128-gcm`             |                                             |
| `xchacha20-ietf-poly1305` | needs libsodium                             |

All current clients support these: [Android], [Windows], shadowsocks-rust,
shadowsocks-libev, Shadowrocket, Clash, etc.

The old stream ciphers (`aes-256-cfb`, `rc4-md5`, `chacha20`, `table`, ...)
still work for compatibility, but they have no integrity protection and are
easily identified by active probing, so servers using them get blocked
quickly. ssserver prints a warning when one is configured.

On top of AEAD, the server

* rejects replayed connections (repeated salts), and
* doesn't close a connection that fails authentication right away; it reads
  and discards the data until the client gives up or the timeout expires,
  so probes can't tell it apart from other servers by how it reacts.

**A note on the GFW:** this is a big improvement over stream ciphers, but
since late 2021 the GFW also blocks some "fully encrypted" traffic that looks
like random bytes, which includes every Shadowsocks variant, statistically.
If the server still gets blocked, the more robust options today are
Shadowsocks 2022 (`2022-blake3-*` ciphers, available in shadowsocks-rust,
which the Android app also uses) or TLS-based protocols, e.g. a
v2ray-plugin/TLS setup or Xray (VLESS + REALITY).

### Usage

    ssserver -p 443 -k password -m chacha20-ietf-poly1305

or with a config file (see `debian/config.json`):

    ssserver -c /etc/shadowsocks.json

Without systemd you can still use the built-in daemon mode:

    sudo ssserver -c /etc/shadowsocks.json -d start
    sudo ssserver -c /etc/shadowsocks.json -d status
    sudo ssserver -c /etc/shadowsocks.json -d stop
    sudo less /var/log/shadowsocks.log

Check all the options via `-h`. You can also use a [Configuration] file
instead.

Client
------

* [Windows] / [OS X]
* [Android] / [iOS]
* [OpenWRT]

Use GUI clients on your local PC/phones. Check the README of your client
for more information.

Documentation
-------------

You can find all the documentation in the [Wiki].

License
-------

Copyright 2015 clowwindy

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

Bugs and Issues
----------------

* [Troubleshooting]
* [Issue Tracker]
* [Mailing list]



[Android]:           https://github.com/shadowsocks/shadowsocks-android
[Build Status]:      https://img.shields.io/travis/shadowsocks/shadowsocks/master.svg?style=flat
[Configuration]:     https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File
[Coverage Status]:   https://jenkins.shadowvpn.org/result/shadowsocks
[Coverage]:          https://jenkins.shadowvpn.org/job/Shadowsocks/ws/PYENV/py34/label/linux/htmlcov/index.html
[Debian sid]:        https://packages.debian.org/unstable/python/shadowsocks
[iOS]:               https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help
[Issue Tracker]:     https://github.com/shadowsocks/shadowsocks/issues?state=open
[Install Server on Windows]: https://github.com/shadowsocks/shadowsocks/wiki/Install-Shadowsocks-Server-on-Windows
[Mailing list]:      https://groups.google.com/group/shadowsocks
[OpenWRT]:           https://github.com/shadowsocks/openwrt-shadowsocks
[OS X]:              https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help
[PyPI]:              https://pypi.python.org/pypi/shadowsocks
[PyPI version]:      https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
[Travis CI]:         https://travis-ci.org/shadowsocks/shadowsocks
[Troubleshooting]:   https://github.com/shadowsocks/shadowsocks/wiki/Troubleshooting
[Wiki]:              https://github.com/shadowsocks/shadowsocks/wiki
[Windows]:           https://github.com/shadowsocks/shadowsocks-csharp
