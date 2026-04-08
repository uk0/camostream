#!/usr/bin/env bash
# CamoStream End-to-End Test Suite
# Tests TCP/UDP tunneling, encryption, decoy injection, PCAP, and metrics.
# No Docker required - runs entirely on localhost.

set +e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${PROJECT_ROOT}/camostream"
RESULTS_DIR="${PROJECT_ROOT}/tests/results"
AES_KEY="0123456789abcdef0123456789abcdef"

PASS_COUNT=0
FAIL_COUNT=0
PIDS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_hdr()   { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

track_pid() { PIDS+=("$1"); }

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    PIDS=()
    pkill -f "camostream.*-role=" 2>/dev/null
    pkill -f "python3.*socketserver" 2>/dev/null
    pkill -f "udp_echo" 2>/dev/null
    sleep 1
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 max=${2:-5} i=0
    while ! (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
        sleep 0.5; i=$((i + 1))
        [ "$i" -ge "$((max * 2))" ] && return 1
    done
}

fetch_metric() {
    local port=$1 key=$2
    curl -s --max-time 3 "http://127.0.0.1:${port}/debug/vars" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$key', 0))" 2>/dev/null || echo "0"
}

kill_tracked() {
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done
    PIDS=()
    pkill -9 -f "camostream.*-role=" 2>/dev/null
    pkill -9 -f "tcp_echo" 2>/dev/null
    pkill -9 -f "udp_echo" 2>/dev/null
    sleep 2
}

# ─── Initial Cleanup ────────────────────────────────────────────────────────
pkill -9 -f "camostream.*-role=" 2>/dev/null
pkill -9 -f "tcp_echo.py" 2>/dev/null
pkill -9 -f "udp_echo" 2>/dev/null
sleep 2

# ─── Prerequisites ──────────────────────────────────────────────────────────
log_hdr "Prerequisites"
mkdir -p "$RESULTS_DIR"
cd "$PROJECT_ROOT"

if [ ! -f "$BINARY" ]; then
    log_info "Building camostream..."
    go build -o camostream main.go
fi
[ ! -x "$BINARY" ] && { echo "Binary not found: $BINARY"; exit 1; }
log_info "Binary OK"

# Build UDP echo server
UDP_ECHO="${PROJECT_ROOT}/udp_echo"
if [ -f "sim/udp_server.go" ] && [ ! -f "$UDP_ECHO" ]; then
    (cd sim && go build -o "$UDP_ECHO" udp_server.go)
fi

# ─── Test 1: TCP Data Integrity ────────────────────────────────────────────
test_tcp_integrity() {
    log_hdr "Test 1: TCP Data Integrity"

    # TCP echo server (persistent, handles many connections)
    python3 "${PROJECT_ROOT}/tests/scripts/tcp_echo.py" 4141 &
    track_pid $!
    sleep 1

    "$BINARY" -role=server -mode=tcp -listen=:39001 -forward=127.0.0.1:4141 \
        -bitrate-mbps=20 -decoy-rps=5 \
        -pcap="${RESULTS_DIR}/tcp_srv.pcap" -metrics=:9100 -log=warn &
    track_pid $!

    "$BINARY" -role=client -mode=tcp -listen=:37001 -server=127.0.0.1:39001 \
        -bitrate-mbps=20 -decoy-rps=5 \
        -pcap="${RESULTS_DIR}/tcp_cli.pcap" -metrics=:9101 -log=warn &
    track_pid $!

    sleep 2
    wait_for_port 37001 5 || { log_fail "T1 - port 37001 not ready"; kill_tracked; return; }

    local resp
    resp=$(echo "CAMOSTREAM_TCP_TEST" | timeout 10 nc 127.0.0.1 37001 2>/dev/null || echo "")

    if [ "$(echo "$resp" | tr -d '[:space:]')" = "CAMOSTREAM_TCP_TEST" ]; then
        log_pass "T1 - TCP data integrity OK"
    else
        log_fail "T1 - TCP data mismatch: got='$resp'"
    fi

    sleep 1
    local bu=$(fetch_metric 9100 "bytes_up")
    if [ "$bu" -gt 0 ] 2>/dev/null; then
        log_pass "T1 - TCP metrics active (bytes_up=$bu)"
    else
        log_fail "T1 - TCP metrics inactive"
    fi

    kill_tracked
}

# ─── Test 2: TCP with AES-GCM ──────────────────────────────────────────────
test_tcp_aes() {
    log_hdr "Test 2: TCP AES-GCM Encryption"

    python3 "${PROJECT_ROOT}/tests/scripts/tcp_echo.py" 4142 &
    track_pid $!
    sleep 1

    "$BINARY" -role=server -mode=tcp -listen=:39002 -forward=127.0.0.1:4142 \
        -bitrate-mbps=20 -decoy-rps=5 -aes="$AES_KEY" \
        -metrics=:9102 -log=warn &
    track_pid $!

    "$BINARY" -role=client -mode=tcp -listen=:37002 -server=127.0.0.1:39002 \
        -bitrate-mbps=20 -decoy-rps=5 -aes="$AES_KEY" \
        -metrics=:9103 -log=warn &
    track_pid $!

    sleep 2
    wait_for_port 37002 5 || { log_fail "T2 - port not ready"; kill_tracked; return; }

    local resp
    resp=$(echo "AES_ENCRYPTED_DATA" | timeout 10 nc 127.0.0.1 37002 2>/dev/null || echo "")

    if [ "$(echo "$resp" | tr -d '[:space:]')" = "AES_ENCRYPTED_DATA" ]; then
        log_pass "T2 - AES-GCM encrypted tunnel OK"
    else
        log_fail "T2 - AES data mismatch: got='$resp'"
    fi
    kill_tracked
}

# ─── Test 3: UDP Comprehensive (integrity + decoys + PCAP) ─────────────────
test_udp_comprehensive() {
    log_hdr "Test 3: UDP Comprehensive (integrity + decoys + PCAP)"

    [ ! -x "$UDP_ECHO" ] && { log_fail "T3 - udp_echo not built"; return; }

    local pcap_file="${RESULTS_DIR}/udp_test.pcap"
    rm -f "$pcap_file"

    # Single udp_echo instance for all UDP tests
    "$UDP_ECHO" &
    track_pid $!
    sleep 1

    "$BINARY" -role=server -mode=udp -wire=rtpish -listen=:39003 -forward=127.0.0.1:18081 \
        -fps=60 -bitrate-mbps=20 -decoy-rps=10 \
        -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
        -pcap="$pcap_file" -pcap-max-mb=10 \
        -metrics=:9104 -log=warn -showdrop &
    track_pid $!

    "$BINARY" -role=client -mode=udp -wire=rtpish -listen=:37003 -server=127.0.0.1:39003 \
        -fps=60 -bitrate-mbps=20 -decoy-rps=10 \
        -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
        -pcap="${RESULTS_DIR}/udp_cli.pcap" -pcap-max-mb=10 \
        -metrics=:9105 -log=warn -showdrop &
    track_pid $!

    sleep 2

    # 3a) UDP data integrity - send traffic and check metrics
    for i in $(seq 1 30); do
        python3 -c "import socket,os; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(os.urandom(800),('127.0.0.1',37003)); s.close()" 2>/dev/null
        sleep 0.1
    done

    sleep 3

    local bu=$(fetch_metric 9104 "bytes_up")
    local fu=$(fetch_metric 9104 "frames_up")
    if [ "$bu" -gt 0 ] 2>/dev/null; then
        log_pass "T3a - UDP data through tunnel (bytes_up=$bu, frames_up=$fu)"
    else
        log_fail "T3a - No UDP data through tunnel"
    fi

    # 3b) Decoy injection verification
    local dd=$(fetch_metric 9104 "decoy_dropped")
    local sd=$(fetch_metric 9104 "shim_decoy_sent")
    local sr=$(fetch_metric 9104 "rtcp_sr_sent")
    local rr=$(fetch_metric 9104 "rtcp_rr_sent")
    local rk=$(fetch_metric 9104 "rtp_keepalive_sent")
    local st=$(fetch_metric 9104 "stun_sent")

    local csd=$(fetch_metric 9105 "shim_decoy_sent")
    local csr=$(fetch_metric 9105 "rtcp_sr_sent")
    local crr=$(fetch_metric 9105 "rtcp_rr_sent")
    local crk=$(fetch_metric 9105 "rtp_keepalive_sent")
    local cst=$(fetch_metric 9105 "stun_sent")

    log_info "Server: decoy_dropped=$dd shim=$sd rtcp_sr=$sr rtcp_rr=$rr rtp_keep=$rk stun=$st"
    log_info "Client: shim=$csd rtcp_sr=$csr rtcp_rr=$crr rtp_keep=$crk stun=$cst"

    local tsd=$((sd + csd)); local tsr=$((sr + csr)); local trr=$((rr + crr))
    local trk=$((rk + crk)); local tst=$((st + cst))

    [ "$tsd" -gt 0 ] 2>/dev/null && log_pass "T3b - Shim decoys ($tsd)" || log_fail "T3b - No shim decoys"
    [ "$tsr" -gt 0 ] 2>/dev/null && log_pass "T3b - RTCP SR ($tsr)" || log_fail "T3b - No RTCP SR"
    [ "$trr" -gt 0 ] 2>/dev/null && log_pass "T3b - RTCP RR ($trr)" || log_fail "T3b - No RTCP RR"
    [ "$trk" -gt 0 ] 2>/dev/null && log_pass "T3b - RTP keepalive ($trk)" || log_fail "T3b - No RTP keepalive"
    [ "$tst" -gt 0 ] 2>/dev/null && log_pass "T3b - STUN ($tst)" || log_fail "T3b - No STUN"

    # 3c) PCAP verification
    if [ -f "$pcap_file" ]; then
        local sz=$(stat -f%z "$pcap_file" 2>/dev/null || stat -c%s "$pcap_file" 2>/dev/null || echo "0")
        if [ "$sz" -gt 24 ]; then
            log_pass "T3c - PCAP generated ($sz bytes)"
        else
            log_fail "T3c - PCAP only has header ($sz bytes)"
        fi
    else
        log_fail "T3c - PCAP not created"
    fi

    kill_tracked
}

# ─── Test 6: Metrics Endpoint Validation ───────────────────────────────────
test_metrics() {
    log_hdr "Test 6: Metrics Endpoint"

    "$BINARY" -role=server -mode=tcp -listen=:39006 -forward=127.0.0.1:9999 \
        -bitrate-mbps=20 -metrics=:9110 -log=warn &
    track_pid $!

    sleep 1

    local json
    json=$(curl -s --max-time 3 "http://127.0.0.1:9110/debug/vars" 2>/dev/null || echo "")

    if [ -z "$json" ]; then
        log_fail "T6 - Could not fetch metrics"
        kill_tracked; return
    fi

    if echo "$json" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "T6 - Metrics returns valid JSON"
    else
        log_fail "T6 - Invalid JSON from metrics"
        kill_tracked; return
    fi

    local keys=("bytes_up" "bytes_down" "frames_up" "frames_down" "decoy_dropped" "sessions_active" "rtcp_sr_sent" "rtcp_rr_sent" "rtp_keepalive_sent" "stun_sent" "shim_decoy_sent")
    local ok=true
    for key in "${keys[@]}"; do
        if ! echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
            log_fail "T6 - Missing key: $key"
            ok=false
        fi
    done
    $ok && log_pass "T6 - All ${#keys[@]} metric keys present"

    kill_tracked
}

# ─── Run ────────────────────────────────────────────────────────────────────
log_hdr "CamoStream E2E Test Suite"
log_info "Project: $PROJECT_ROOT"
log_info "Results: $RESULTS_DIR"

test_tcp_integrity
test_tcp_aes
test_udp_comprehensive
test_metrics

# ─── Summary ────────────────────────────────────────────────────────────────
log_hdr "Summary"
echo -e "  ${GREEN}PASSED: ${PASS_COUNT}${NC}"
echo -e "  ${RED}FAILED: ${FAIL_COUNT}${NC}"
echo ""

[ "$FAIL_COUNT" -gt 0 ] && { echo -e "${RED}${BOLD}Some tests failed.${NC}"; exit 1; }
echo -e "${GREEN}${BOLD}All tests passed.${NC}"
exit 0
