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
`/etc/shadowsocks.json` with a random `2022-blake3-aes-256-gcm` key (if you
don't have a config yet) and enables the `shadowsocks-server` systemd
service. No source files need
patching any more, and it works with Python 3.8 - 3.13 and OpenSSL 1.1 / 3.x
(Debian 11, 12, 13; Ubuntu 20.04+).

Run it again after `git pull` to upgrade. An existing config is kept as is.

Manage the service with:

    sudo systemctl status shadowsocks-server
    sudo systemctl restart shadowsocks-server
    sudo journalctl -u shadowsocks-server -f

To install by hand instead: `pip install .` (inside a virtualenv) and copy
`systemd/shadowsocks-server.service` to `/etc/systemd/system/`.

### Upgrading from an old `python setup.py install`

Just run `sudo ./install.sh`. It keeps your `/etc/shadowsocks.json` exactly
as it is (and saves a copy as `/etc/shadowsocks.json.bak-<date>`), then:

* stops the server started with `ssserver -d start`,
* removes the old copy (`/usr/local/lib/python3*/dist-packages/
  shadowsocks-*.egg`, its line in `easy-install.pth` and the old
  `/usr/local/bin/ssserver` / `sslocal` scripts),
* starts the same config under systemd.

If you started the server from `/etc/rc.local` or cron, the script tells
you; remove that line, systemd starts it at boot now.

### Uninstall

    sudo ./uninstall.sh            # keeps /etc/shadowsocks.json
    sudo ./uninstall.sh --purge    # also deletes the config

### Ciphers

Use a **Shadowsocks 2022** cipher, or at least an **AEAD** one, on the
server and on every client:

| method                          | notes                                   |
|---------------------------------|-----------------------------------------|
| `2022-blake3-aes-256-gcm`       | recommended                             |
| `2022-blake3-aes-128-gcm`       |                                         |
| `2022-blake3-chacha20-poly1305` | UDP needs libsodium                     |
| `chacha20-ietf-poly1305`        | AEAD, for clients without 2022 support  |
| `aes-256-gcm`                   | AEAD, default when no method is set     |
| `aes-128-gcm`                   | AEAD                                    |
| `xchacha20-ietf-poly1305`       | AEAD, needs libsodium                   |

The **2022** ciphers (SIP022) add timestamps and full replay protection,
hide the request size with random padding and use a real key instead of a
password. They are supported by the [Android] app, shadowsocks-rust,
sing-box, Clash Meta / mihomo, Shadowrocket and v2rayN, but not by older
clients such as shadowsocks-libev. Notes:

* The password must be a base64 key of the right size; generate one with
  `openssl rand -base64 32` (`-base64 16` for `2022-blake3-aes-128-gcm`)
  and paste the same string into the client's password field.
* The server and the clients must have the right time (within 30 seconds);
  `timedatectl` shows whether the server's clock is synchronized.
* Only a single key per port is supported (no multi-user identity
  headers); use `port_password` for several users.

Example `/etc/shadowsocks.json`:

    {
        "server": "0.0.0.0",
        "server_port": 8388,
        "password": "<output of openssl rand -base64 32>",
        "method": "2022-blake3-aes-256-gcm",
        "timeout": 300
    }

To switch an existing server: put a new key and method in
`/etc/shadowsocks.json`, run `sudo systemctl restart shadowsocks-server`
and update the method and password in every client.

The AEAD ciphers are supported by every client from the last few years:
[Android], [Windows], shadowsocks-rust, shadowsocks-libev, etc.

The old stream ciphers (`aes-256-cfb`, `rc4-md5`, `chacha20`, `table`, ...)
still work for compatibility, but they have no integrity protection and are
easily identified by active probing, so servers using them get blocked
quickly. ssserver prints a warning when one is configured.

On top of AEAD, the server

* rejects replayed connections (repeated salts), and
* doesn't close a connection that fails authentication right away; it reads
  and discards the data until the client gives up or the timeout expires,
  so probes can't tell it apart from other servers by how it reacts.

**A note on the GFW:** the 2022 ciphers fix the known weaknesses that get
Shadowsocks servers found by active probing and replays. But since late
2021 the GFW also blocks some traffic simply because it looks like random
bytes, which is true of every Shadowsocks variant. If the server still gets
blocked, the next step is a protocol that looks like normal TLS, such as
Xray (VLESS + REALITY) or Shadowsocks behind a TLS plugin.

### Usage

    ssserver -p 443 -k "$(openssl rand -base64 32)" -m 2022-blake3-aes-256-gcm

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
