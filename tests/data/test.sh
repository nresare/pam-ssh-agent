#!/usr/bin/env sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$1" != "user" ]; then
  exit 1
fi

# A little script that can be used to test the authorized_keys_command
cat $SCRIPT_DIR/id_ed25519.pub
