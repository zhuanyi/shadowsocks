shadowsocks
===========

[![PyPI version]][PyPI]
[![Build Status]][Travis CI]
[![Coverage Status]][Coverage]

A fast, secure tunnel proxy.

Server
------

### Install (Debian / Ubuntu, systemd)

    git clone https://github.com/zhuanyi/shadowsocks.git
    cd shadowsocks
    sudo ./install.sh

The script installs shadowsocks into a virtualenv in `/opt/shadowsocks`,
links `ssserver`, `sslocal`, `ssconfig` and `sslink` into `/usr/local/bin`
and enables the `shadowsocks-server` systemd service. If you don't have a
config yet, it walks you through creating one (see below). No source files need
patching any more, and it works with Python 3.8 - 3.13 and OpenSSL 1.1 / 3.x
(Debian 11, 12, 13; Ubuntu 20.04+).

Run it again after `git pull` to upgrade. An existing config is kept as is.

Manage the service with:

    sudo systemctl status shadowsocks-server
    sudo systemctl restart shadowsocks-server
    sudo journalctl -u shadowsocks-server -f

To install by hand instead: `pip install .` (inside a virtualenv) and copy
`systemd/shadowsocks-server.service` to `/etc/systemd/system/`.

### Configuring (ports, passwords, cipher)

    sudo ssconfig

works like `rclone config`. Without a config it asks for:

1. the cipher (Enter = `2022-blake3-aes-256-gcm`),
2. the server port(s), e.g. `8388, 443`,
3. a password for each port: **press Enter to generate a random key** (the
   same as `openssl rand -base64 32`), or type your own (for the 2022
   ciphers it must be such a base64 key),
4. the listen address and timeout.

With an existing config it shows a menu to add or delete ports, change a
port's password, switch the cipher (generating new keys when the old
passwords don't fit it) or start over. On saving it keeps the previous
version as `/etc/shadowsocks.json.bak-<date>`, offers to restart the service
and to show a QR code.

All passwords, generated or not, are stored in plain text in
`/etc/shadowsocks.json` (readable by root and the service only), so
`sudo cat /etc/shadowsocks.json` shows them later. `install.sh` runs
`ssconfig` when there is no config; set `SS_NONINTERACTIVE=1` to skip the
questions and generate a default config instead.

### Sharing a connection (ss:// links and QR codes)

    sudo sslink              # ss:// links for all ports
    sudo sslink -qr          # QR code; asks which port if there are several
    sudo sslink -qr 8389     # QR code for port 8389 (or its number in the list)
    sudo sslink -qr all      # QR codes for all ports

like `pivpn -qr`. It reads `/etc/shadowsocks.json` (`-c` for another
config). Scan the QR code with the Android app (+ > Scan QR code), or copy
the link and import it from the clipboard in the Android app or v2rayN.

* `-H vps.example.com` uses that address or domain in the links. By default
  sslink guesses the server's address and warns if it looks private (e.g.
  behind NAT).
* `-n "My VPS"` sets the name shown in the client.
* For a PNG instead: `qrencode -o vps.png 'ss://...'`.

Anyone who has a link can use your server, so share it privately.

### TCP BBR

`install.sh` also switches the kernel's TCP congestion control to **BBR**
(in `/etc/sysctl.d/90-shadowsocks-bbr.conf`), which usually gives much
better speeds than the default (cubic) on long-distance or lossy links. It
only changes how this server sends TCP data, i.e. your downloads. It is
skipped when the kernel or VPS type doesn't allow it (e.g. some containers),
`SS_BBR=0 sudo ./install.sh` leaves it alone, and `uninstall.sh` reverts it.
Check it with `sysctl net.ipv4.tcp_congestion_control`.

To turn it on by hand (Linux 4.9 or newer), e.g. on a server set up without
`install.sh`:

    sudo modprobe tcp_bbr
    sysctl net.ipv4.tcp_available_congestion_control   # must list bbr
    printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' |
        sudo tee /etc/sysctl.d/90-bbr.conf
    echo tcp_bbr | sudo tee /etc/modules-load.d/bbr.conf
    sudo sysctl --system
    sysctl net.ipv4.tcp_congestion_control             # should print bbr

The files make it permanent across reboots. If `sysctl --system` complains
about `default_qdisc`, the kernel lacks the `fq` scheduler; that's fine,
BBR works without it on Linux 4.13 and newer. To undo it:
`sudo rm /etc/sysctl.d/90-bbr.conf /etc/modules-load.d/bbr.conf` and
`sudo sysctl -w net.ipv4.tcp_congestion_control=cubic`.

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

**If connections still get blocked:** the 2022 ciphers fix the known
weaknesses that let Shadowsocks servers be identified by active probing and
replays. Some networks, however, also block traffic simply because it looks
like random bytes, which is true of every Shadowsocks variant. In that case
a protocol that looks like normal HTTPS works better, such as Xray
VLESS + REALITY (see [vless-oneclick]), which can run on the same server
next to Shadowsocks.

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

Recommended clients (all support the 2022 ciphers and `ss://` links):

* Android: the official [Android] app (Google Play: "Shadowsocks" by
  Max Lv), or [v2rayNG] (APK from its GitHub releases:
  `v2rayNG_<version>_arm64-v8a.apk` for current phones)
* Windows: [v2rayN] (GitHub releases:
  `v2rayN-windows-64.zip` for x64, `v2rayN-windows-arm64.zip` for ARM; a
  portable zip: extract it and run v2rayN). The old official
  shadowsocks-windows client does not support the 2022 ciphers.

Clients listed by the original project (the [Windows] and [OS X] ones
predate the 2022 ciphers): [Windows] / [OS X] / [iOS] / [OpenWRT].

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
[v2rayNG]:           https://github.com/2dust/v2rayNG/releases
[v2rayN]:            https://github.com/2dust/v2rayN/releases
[vless-oneclick]:    https://github.com/zhuanyi/vless-oneclick
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
