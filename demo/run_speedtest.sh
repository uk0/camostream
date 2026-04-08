#!/usr/bin/env bash
# CamoStream SpeedTest Demo
# Tests all wire modes with CRC32 data integrity verification
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/camostream"
DEMO="$ROOT/demo/speedtest.go"
AES_KEY="0123456789abcdef0123456789abcdef"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
    PIDS=()
    pkill -9 -f "camostream.*-role=" 2>/dev/null
    pkill -9 -f "speedtest.*-mode=" 2>/dev/null
    sleep 1
}
trap cleanup EXIT

track() { PIDS+=("$1"); }

build() {
    echo -e "${CYAN}Building camostream...${NC}"
    cd "$ROOT" && go build -o camostream . || exit 1
    echo -e "${GREEN}Build OK${NC}"
}

run_test() {
    local wire="$1"
    local label="$2"
    local extra_server="${3:-}"
    local extra_client="${4:-}"
    local pps="${5:-200}"
    local size="${6:-1000}"
    local dur="${7:-10}"

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Wire Mode: ${CYAN}${label}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    cleanup 2>/dev/null

    # Start CamoStream server
    "$BIN" -role=server -mode=udp -wire="$wire" -listen=:39001 -forward=127.0.0.1:18081 \
        -bitrate-mbps=50 -fps=60 -decoy-rps=5 -aes="$AES_KEY" \
        -rtcp-sr-rps=1 -stun-rps=0.2 -dtls=false \
        -metrics=:9100 -log=warn $extra_server &
    track $!
    sleep 0.5

    # Start CamoStream client
    "$BIN" -role=client -mode=udp -wire="$wire" -listen=:37001 -server=127.0.0.1:39001 \
        -bitrate-mbps=50 -fps=60 -decoy-rps=5 -aes="$AES_KEY" \
        -rtcp-sr-rps=1 -stun-rps=0.2 -dtls=false \
        -metrics=:9101 -log=warn $extra_client &
    track $!
    sleep 2

    # Start speedtest server (receiver behind tunnel)
    go run "$DEMO" -mode=server -recv=:18081 &
    track $!
    sleep 1

    # Run speedtest client (sender through tunnel)
    go run "$DEMO" -mode=client -send=127.0.0.1:37001 \
        -size="$size" -pps="$pps" -duration="$dur"

    sleep 2

    # Grab metrics
    echo ""
    echo -e "${CYAN}CamoStream Metrics:${NC}"
    curl -s http://127.0.0.1:9100/debug/vars 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for k in sorted(d.keys()):
        if isinstance(d[k],(int,float)) and d[k]>0:
            print(f'  {k}: {d[k]}')
except: pass
" 2>/dev/null

    # Kill the speedtest server (send SIGINT for final report)
    for p in "${PIDS[@]}"; do
        if ps -p "$p" -o comm= 2>/dev/null | grep -q "go\|speedtest"; then
            kill -INT "$p" 2>/dev/null
            sleep 1
        fi
    done

    cleanup 2>/dev/null
}

# ─── Main ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     CamoStream SpeedTest - All Wire Modes       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"

build

# Test 1: rtpish (legacy)
run_test "rtpish" "RTP-ish (Legacy)" "" "" 200 1000 10

# Test 2: webrtc
run_test "webrtc" "WebRTC (SRTP + Audio)" "" "" 200 1000 10

# Test 3: ipcam
run_test "ipcam" "IPCAM (H.264 Surveillance)" "" "" 200 1000 10

echo ""
echo -e "${GREEN}${BOLD}All speedtests complete.${NC}"
