#!/bin/sh
# Install / upgrade the shadowsocks server on Debian or Ubuntu as a systemd
# service.
#
#   git clone https://github.com/zhuanyi/shadowsocks.git
#   cd shadowsocks
#   sudo ./install.sh
#
# What it does:
#   * installs python3 + venv from apt
#   * installs this source tree into a virtualenv in /opt/shadowsocks
#     (no more `python setup.py install`, no files to patch by hand, and no
#     clash with Debian's "externally managed" system Python)
#   * stops a server started the old way (ssserver -d start) and removes
#     old copies installed with `python setup.py install` or `pip install`
#     into the system Python; the config file is kept (and backed up)
#   * links /usr/local/bin/ssserver and /usr/local/bin/sslocal to it
#   * creates a `shadowsocks` system user to run the service as
#   * creates /etc/shadowsocks.json with a random key if it is missing
#   * installs and starts the shadowsocks-server systemd service
#
# Run it again after `git pull` to upgrade. To remove: sudo ./uninstall.sh
#
# Without a config, it asks for the cipher, ports and passwords (Enter
# generates a random key); `sudo ssconfig` changes them later.
#
# Environment variables:
#   SS_CONFIG   config file to use (default /etc/shadowsocks.json)
#   SS_NONINTERACTIVE=1  don't ask, generate a config from SS_PORT and
#               SS_METHOD instead (also done when not run in a terminal)
#   SS_PORT     server port for a generated config (default 8388)
#   SS_METHOD   cipher for a generated config
#               (default 2022-blake3-aes-256-gcm)

set -eu

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/shadowsocks
VENV=$PREFIX/venv
CONFIG=${SS_CONFIG:-/etc/shadowsocks.json}
PORT=${SS_PORT:-8388}
METHOD=${SS_METHOD:-2022-blake3-aes-256-gcm}
SERVICE=shadowsocks-server
USER_NAME=shadowsocks

if [ "$(id -u)" -ne 0 ]; then
    echo "please run as root: sudo $0" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "this script supports Debian / Ubuntu only (apt-get not found)" >&2
    exit 1
fi

echo "==> installing system packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv
# optional: libsodium is only needed for UDP with
# 2022-blake3-chacha20-poly1305, xchacha20-ietf-poly1305 and the legacy
# salsa20 / chacha20 stream ciphers
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libsodium23 \
    >/dev/null 2>&1 || true
# optional: QR codes in `sslink`
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qrencode \
    >/dev/null 2>&1 || true

echo "==> installing shadowsocks into $VENV"
mkdir -p "$PREFIX"
if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR"
# optional: a faster BLAKE3 for the 2022 ciphers (a pure-Python fallback
# is built in)
"$VENV/bin/pip" install --quiet blake3 >/dev/null 2>&1 || true

# stop an instance started the old way (ssserver -d start) so that the
# service can bind the port
if [ -f "$CONFIG" ] && ! systemctl is-active --quiet "$SERVICE"; then
    if "$VENV/bin/ssserver" -c "$CONFIG" -d status >/dev/null 2>&1; then
        echo "==> stopping old ssserver daemon"
        "$VENV/bin/ssserver" -c "$CONFIG" -d stop || true
    fi
fi

if [ -f "$CONFIG" ]; then
    BACKUP="$CONFIG.bak-$(date +%Y%m%d%H%M%S)"
    cp -p "$CONFIG" "$BACKUP"
    echo "==> backed up $CONFIG to $BACKUP"
fi

# remove old copies installed into the system Python with
# `python setup.py install` (an .egg) or `pip install`; they are no longer
# used and would only cause confusion
for site in /usr/local/lib/python3*/dist-packages \
            /usr/local/lib/python3*/site-packages; do
    [ -d "$site" ] || continue
    for old in "$site"/shadowsocks-*.egg "$site"/shadowsocks-*.egg-info \
               "$site"/shadowsocks-*.dist-info; do
        [ -e "$old" ] || continue
        echo "==> removing old install $old"
        rm -rf "$old"
        if [ "${old%.dist-info}" != "$old" ] || \
                [ "${old%.egg-info}" != "$old" ]; then
            # pip / plain setup.py install put the package next to it
            rm -rf "$site/shadowsocks"
        fi
    done
    if [ -f "$site/easy-install.pth" ]; then
        sed -i '/shadowsocks-.*\.egg/d' "$site/easy-install.pth"
    fi
done

if dpkg -s shadowsocks >/dev/null 2>&1; then
    echo "NOTE: the Debian 'shadowsocks' package is also installed. Remove it"
    echo "      with 'apt-get remove shadowsocks' (not purge, which would"
    echo "      delete its config in /etc/shadowsocks/)."
fi
for f in /etc/rc.local /etc/crontab /etc/cron.d/* \
         /var/spool/cron/crontabs/*; do
    if [ -f "$f" ] && grep -q 'ss\(server\|local\).*-d *\(start\|restart\)' \
            "$f"; then
        echo "NOTE: $f starts ssserver/sslocal on its own; remove that line,"
        echo "      systemd starts the server at boot now."
    fi
done

for prog in ssserver sslocal sslink ssconfig; do
    ln -sf "$VENV/bin/$prog" "/usr/local/bin/$prog"
done

if ! id "$USER_NAME" >/dev/null 2>&1; then
    echo "==> creating system user $USER_NAME"
    useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$USER_NAME"
fi

NEW_CONFIG=0
if [ ! -f "$CONFIG" ] && [ -t 0 ] && [ -z "${SS_NONINTERACTIVE:-}" ]; then
    # ask for the cipher, ports and passwords, like `rclone config`
    echo "==> creating $CONFIG"
    if "$VENV/bin/ssconfig" -c "$CONFIG" --installer; then
        NEW_CONFIG=1
    else
        echo "no config saved; generating a default one instead"
    fi
fi

if [ ! -f "$CONFIG" ]; then
    echo "==> generating $CONFIG"
    case "$METHOD" in
        2022-blake3-aes-128-gcm) KEY_LEN=16 ;;
        *) KEY_LEN=32 ;;
    esac
    case "$METHOD" in
        2022-*) PASSWORD=$(python3 -c "import base64, os
print(base64.b64encode(os.urandom($KEY_LEN)).decode())") ;;
        *) PASSWORD=$(python3 -c 'import secrets
print(secrets.token_urlsafe(24))') ;;
    esac
    cat > "$CONFIG" <<CONF
{
    "server": "0.0.0.0",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "method": "$METHOD",
    "timeout": 300,
    "fast_open": false
}
CONF
    NEW_CONFIG=1
elif [ "$NEW_CONFIG" = 0 ]; then
    if ! python3 - "$CONFIG" <<'PY'
import json, sys
m = (json.load(open(sys.argv[1])).get('method') or 'aes-256-gcm').lower()
sys.exit(0 if m.startswith('2022-blake3-') or m in (
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305') else 1)
PY
    then
        echo
        echo "WARNING: $CONFIG uses a legacy stream cipher, which is easily"
        echo "         detected and blocked. See README.md (Ciphers) for how"
        echo "         to switch to 2022-blake3-aes-256-gcm, here AND in all"
        echo "         your clients, then: systemctl restart $SERVICE"
        echo
    fi
    if grep -q '"user"' "$CONFIG"; then
        echo "NOTE: the service already runs as user '$USER_NAME'; remove the"
        echo "      \"user\" option from $CONFIG if the service fails to start."
    fi
fi
chown root:"$USER_NAME" "$CONFIG"
chmod 640 "$CONFIG"

echo "==> installing systemd service $SERVICE"
for unit in shadowsocks-server shadowsocks-local; do
    sed "s|/etc/shadowsocks.json|$CONFIG|" \
        "$SRC_DIR/systemd/$unit.service" > "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
sleep 1
systemctl --no-pager status "$SERVICE" || true

echo
echo "done. useful commands:"
echo "  systemctl status $SERVICE"
echo "  systemctl restart $SERVICE"
echo "  journalctl -u $SERVICE -f"
echo "  sudo ssconfig                 # change ports, passwords, cipher"
echo "  sudo sslink -qr               # QR code to scan with a client"
if [ "$NEW_CONFIG" = 1 ]; then
    echo
    echo "the passwords are saved in $CONFIG"
    "$VENV/bin/sslink" -c "$CONFIG" -qr || true
    PORTS=$(python3 - "$CONFIG" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
if c.get('port_password'):
    ports = sorted(c['port_password'], key=int)
else:
    p = c.get('server_port', 8388)
    ports = p if isinstance(p, list) else [p]
print(' '.join(str(p) for p in ports))
PY
)
    if grep -q '"2022-' "$CONFIG"; then
        echo "the 2022 ciphers reject clients whose clock is off by"
        echo "more than 30 seconds; keep time in sync on both sides."
    fi
    echo "remember to open port(s) $PORTS (TCP and UDP) in your firewall."
fi
