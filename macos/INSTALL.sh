#!/bin/sh
set -eu
IGARECK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IGARECK_APP="$IGARECK_DIR/app/install.py"
if [ ! -f "$IGARECK_APP" ]; then IGARECK_APP="$IGARECK_DIR/install.py"; fi
if [ "$(id -u)" -eq 0 ]; then
    exec /usr/bin/python3 "$IGARECK_APP" install "$@"
fi
exec /usr/bin/sudo /usr/bin/python3 "$IGARECK_APP" install "$@"
