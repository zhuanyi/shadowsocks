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
#   * links /usr/local/bin/ssserver and /usr/local/bin/sslocal to it
#   * creates a `shadowsocks` system user to run the service as
#   * creates /etc/shadowsocks.json with a random password if it is missing
#   * installs and starts the shadowsocks-server systemd service
#
# Environment variables:
#   SS_CONFIG   config file to use (default /etc/shadowsocks.json)
#   SS_PORT     server port for a newly generated config (default 8388)
#   SS_METHOD   cipher for a newly generated config
#               (default chacha20-ietf-poly1305)

set -eu

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/shadowsocks
VENV=$PREFIX/venv
CONFIG=${SS_CONFIG:-/etc/shadowsocks.json}
PORT=${SS_PORT:-8388}
METHOD=${SS_METHOD:-chacha20-ietf-poly1305}
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
# optional: libsodium is only needed for xchacha20-ietf-poly1305 and the
# legacy salsa20 / chacha20 stream ciphers
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libsodium23 \
    >/dev/null 2>&1 || true

echo "==> installing shadowsocks into $VENV"
mkdir -p "$PREFIX"
if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR"

# stop an instance started the old way (ssserver -d start) so that the
# service can bind the port
if [ -f "$CONFIG" ] && [ -f /var/run/shadowsocks.pid ] && \
        ! systemctl is-active --quiet "$SERVICE"; then
    echo "==> stopping old ssserver daemon"
    "$VENV/bin/ssserver" -c "$CONFIG" -d stop || true
fi

for prog in ssserver sslocal; do
    ln -sf "$VENV/bin/$prog" "/usr/local/bin/$prog"
done

if ! id "$USER_NAME" >/dev/null 2>&1; then
    echo "==> creating system user $USER_NAME"
    useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$USER_NAME"
fi

if [ ! -f "$CONFIG" ]; then
    echo "==> generating $CONFIG"
    PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
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
else
    NEW_CONFIG=0
    if ! python3 - "$CONFIG" <<'PY'
import json, sys
m = (json.load(open(sys.argv[1])).get('method') or 'aes-256-gcm').lower()
sys.exit(0 if m in ('aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
                    'chacha20-ietf-poly1305',
                    'xchacha20-ietf-poly1305') else 1)
PY
    then
        echo
        echo "WARNING: $CONFIG uses a legacy stream cipher, which is easily"
        echo "         detected and blocked. Change \"method\" to"
        echo "         \"chacha20-ietf-poly1305\" (or \"aes-256-gcm\") here AND in"
        echo "         all your clients, then: systemctl restart $SERVICE"
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
if [ "$NEW_CONFIG" = 1 ]; then
    echo
    echo "client settings (also in $CONFIG):"
    echo "  port:     $PORT"
    echo "  password: $PASSWORD"
    echo "  method:   $METHOD"
    echo "remember to open port $PORT (TCP and UDP) in your firewall."
fi
