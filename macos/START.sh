#!/bin/sh
set -eu
IGARECK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IGARECK_APP="$IGARECK_DIR/app/igareck.py"
if [ ! -f "$IGARECK_APP" ]; then IGARECK_APP="$IGARECK_DIR/igareck.py"; fi
case "${1:-}" in
    list|show|check-engine|--help|-h)
        exec /usr/bin/python3 "$IGARECK_APP" "$@"
        ;;
esac
if [ "$(id -u)" -eq 0 ]; then
    exec /usr/bin/python3 "$IGARECK_APP" "$@"
fi
exec /usr/bin/sudo /usr/bin/python3 "$IGARECK_APP" "$@"
