#!/bin/bash
# Start the combined Zen proxy in the background (mirrors omp-zen-proxy/start.sh,
# so a client configured against it never finds the port closed).
# Usage: ./start.sh   env: PORT (8787) ZEN_KEY PROXY_TOKEN UPSTREAM_PROXY FALLBACK_MODEL
set -euo pipefail
cd "$(dirname "$0")"
P="${PORT:-8787}"
if curl -s -m 3 "http://127.0.0.1:${P}/health" >/dev/null 2>&1; then
  echo "proxy already running on :${P}"
  exit 0
fi
nohup python3 opproxy.py > opproxy.log 2>&1 &
sleep 2
curl -s -m 10 "http://127.0.0.1:${P}/v1/models" | head -c 160
echo
echo "proxy started on :${P} (localhost + 127.0.0.1) — log: opproxy.log"
