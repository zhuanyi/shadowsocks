#!/bin/sh
# Remove shadowsocks installed by install.sh.
#
#   sudo ./uninstall.sh           keeps /etc/shadowsocks.json
#   sudo ./uninstall.sh --purge   also deletes the config and the
#                                 shadowsocks system user
#
# Environment variables:
#   SS_CONFIG   config file (default /etc/shadowsocks.json)

set -eu

PREFIX=/opt/shadowsocks
CONFIG=${SS_CONFIG:-/etc/shadowsocks.json}
USER_NAME=shadowsocks
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "please run as root: sudo $0" >&2
    exit 1
fi

for unit in shadowsocks-server shadowsocks-local; do
    if [ -f "/etc/systemd/system/$unit.service" ]; then
        echo "==> removing $unit service"
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$unit.service"
    fi
done
systemctl daemon-reload 2>/dev/null || true

for prog in ssserver sslocal sslink ssconfig; do
    link="/usr/local/bin/$prog"
    if [ -L "$link" ] && readlink "$link" | grep -q "^$PREFIX/"; then
        rm -f "$link"
    fi
done

if [ -d "$PREFIX" ]; then
    echo "==> removing $PREFIX"
    rm -rf "$PREFIX"
fi

if [ "$PURGE" = 1 ]; then
    echo "==> removing $CONFIG and user $USER_NAME"
    rm -f "$CONFIG"
    if id "$USER_NAME" >/dev/null 2>&1; then
        userdel "$USER_NAME" || true
    fi
else
    echo "kept $CONFIG (use --purge to delete it)"
fi
echo "done."
