#!/bin/sh
set -eu

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 -m venv "$TOOL_DIR/.venv"
"$TOOL_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$TOOL_DIR/requirements.txt"

echo
echo "Installed. Run the tool with:"
echo "  $TOOL_DIR/fritzbox-ucg /path/to/backup.export"
