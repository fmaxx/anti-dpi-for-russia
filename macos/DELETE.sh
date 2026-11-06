#!/bin/sh
set -eu
IGARECK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IGARECK_APP="$IGARECK_DIR/app/remove_installation.py"
if [ ! -f "$IGARECK_APP" ]; then IGARECK_APP="$IGARECK_DIR/remove_installation.py"; fi
if [ "$(id -u)" -eq 0 ]; then
    exec /usr/bin/python3 "$IGARECK_APP" "$@"
fi
exec /usr/bin/sudo /usr/bin/python3 "$IGARECK_APP" "$@"
