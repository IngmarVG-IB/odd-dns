#!/usr/bin/env bash
# Loopback demonstration of the diode tx/rx pipeline -- no real diode
# hardware and no BIND installation required (it runs with
# --skip-validation --skip-reload by default; drop those flags and point
# --zone-file / --checkzone-bin / --rndc-bin at a real BIND install to
# exercise the full path, see README.md).
#
# Usage:
#   test/run_demo.sh            # single-chunk zone, clean link
#   test/run_demo.sh --lossy    # multi-chunk zone through a 30%-loss relay
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

KEY_FILE="$WORK/diode.key"
python3 -c "import secrets; print(secrets.token_hex(32))" > "$KEY_FILE"

RX_PORT=15900
TX_DEST_PORT=15900
LOSSY=0
if [[ "${1:-}" == "--lossy" ]]; then
    LOSSY=1
    ZONE_FILE="$ROOT/test/sample_zone/db.example-large.com"
    TX_DEST_PORT=15901   # tx sends to the relay's listen port, not directly to rx
else
    ZONE_FILE="$ROOT/bind/inside/zones/db.example.com"
fi

OUT_FILE="$WORK/received-zone"
STATE_FILE="$WORK/rx-state.json"
RX_LOG="$WORK/rx.log"

if [[ "$LOSSY" == "1" ]]; then
    echo "== running a lossy relay (30% drop) between tx and rx =="
    python3 "$ROOT/test/lossy_relay.py" "$TX_DEST_PORT" "$RX_PORT" 0.3 25 > "$WORK/relay.log" 2>&1 &
fi

python3 "$ROOT/diode_rx/zone_diode_rx.py" \
    --zone example.com \
    --listen-host 127.0.0.1 --listen-port "$RX_PORT" \
    --key-file "$KEY_FILE" \
    --zone-file "$OUT_FILE" \
    --state-file "$STATE_FILE" \
    --skip-validation --skip-reload \
    --once --idle-timeout 22 -v > "$RX_LOG" 2>&1 &

sleep 1

python3 "$ROOT/diode_tx/zone_diode_tx.py" \
    --zone example.com \
    --dest-host 127.0.0.1 --dest-port "$TX_DEST_PORT" \
    --key-file "$KEY_FILE" \
    --source-mode rawfile --zone-file "$ZONE_FILE" \
    --repeats 4 --pacing-ms 2 \
    --once -v

wait

echo
echo "== rx log =="
cat "$RX_LOG"
if [[ "$LOSSY" == "1" ]]; then
    echo
    echo "== relay log =="
    cat "$WORK/relay.log"
fi

echo
if diff -q "$ZONE_FILE" "$OUT_FILE" > /dev/null; then
    echo "PASS: received zone is byte-identical to the source zone"
    exit 0
else
    echo "FAIL: received zone differs from the source zone"
    diff "$ZONE_FILE" "$OUT_FILE" || true
    exit 1
fi
