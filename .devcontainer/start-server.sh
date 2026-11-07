#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin logs
if [[ ! -x bin/owpengram-ctl ]]; then
  go build -o bin/owpengram-ctl ./cmd/owpengram-ctl
fi
if pgrep -f '[b]in/owpengram-ctl' >/dev/null; then
  echo "OwpenGram supervisor is already running."
  exit 0
fi
nohup ./bin/owpengram-ctl > logs/codespace-ctl.log 2>&1 < /dev/null &
echo "OwpenGram startup requested; see logs/codespace-ctl.log"
