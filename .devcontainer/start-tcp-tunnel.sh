#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v ssh >/dev/null 2>&1; then
  echo "ERROR: OpenSSH client is not installed in this Codespace." >&2
  exit 1
fi

echo "Starting a raw TCP tunnel to OwpenGram on 127.0.0.1:2398."
echo "Keep this terminal running. Pinggy should print a public tcp:// address."
echo "The free tunnel expires after 60 minutes; its public port changes on reconnect."
exec ssh -p 443 \
  -o StrictHostKeyChecking=accept-new \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes \
  -R0:127.0.0.1:2398 tcp@free.pinggy.io
