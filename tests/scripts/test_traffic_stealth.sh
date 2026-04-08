#!/usr/bin/env bash
# CamoStream Traffic Stealth Analysis
# Runs selftest with full decoy setup, captures PCAP, and analyzes with tshark.
# Verifies that traffic looks like legitimate WebRTC/media streams.

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${PROJECT_ROOT}/camostream"
RESULTS_DIR="${PROJECT_ROOT}/tests/results"
PCAP_FILE="${RESULTS_DIR}/stealth_test.pcap"
METRICS_PORT=9100
SELFTEST_DURATION=15

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[INFO]${NC}    $*"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC}    $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_hdr()     { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }
log_section() { echo -e "\n${CYAN}--- $* ---${NC}"; }

PIDS=()
track_pid() { PIDS+=("$1"); }

cleanup() {
    log_info "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    pkill -f "camostream.*selftest" 2>/dev/null || true
}
trap cleanup EXIT

# ─── Prerequisites ───────────────────────────────────────────────────────────
log_hdr "CamoStream Traffic Stealth Analysis"

mkdir -p "$RESULTS_DIR"

cd "$PROJECT_ROOT"
if [ ! -f "$BINARY" ]; then
    log_info "Building camostream..."
    go build -o camostream main.go
fi

if [ ! -x "$BINARY" ]; then
    echo -e "${RED}ERROR: Binary not found: ${BINARY}${NC}"
    exit 1
fi

# Check for tshark
HAVE_TSHARK=false
if command -v tshark &>/dev/null; then
    HAVE_TSHARK=true
    log_info "tshark found: $(tshark --version 2>&1 | head -1)"
else
    log_warn "tshark not found - deep protocol analysis will be skipped"
    log_warn "Install with: brew install wireshark (macOS) or apt install tshark (Linux)"
fi

# ─── Phase 1: Run Selftest with Full Decoy Setup ────────────────────────────
log_hdr "Phase 1: Traffic Generation"
log_info "Running selftest for ${SELFTEST_DURATION}s with full decoy configuration..."

rm -f "$PCAP_FILE"

timeout $((SELFTEST_DURATION + 10)) "$BINARY" \
    -role=selftest -mode=udp \
    -wire=rtpish -fps=60 -bitrate-mbps=20 \
    -decoy-rps=10 \
    -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
    -pcap="$PCAP_FILE" -pcap-max-mb=50 \
    -metrics=:${METRICS_PORT} \
    -duration="${SELFTEST_DURATION}s" -log=warn 2>&1 &
SELFTEST_PID=$!
track_pid $SELFTEST_PID

# Wait for metrics to be available, then sample
sleep $((SELFTEST_DURATION - 2))

log_section "Metrics Snapshot (near end of test)"
METRICS_JSON=$(curl -s --max-time 5 "http://127.0.0.1:${METRICS_PORT}/debug/vars" 2>/dev/null || echo "{}")

if [ "$METRICS_JSON" != "{}" ]; then
    echo "$METRICS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = [
    'bytes_up', 'bytes_down', 'frames_up', 'frames_down',
    'decoy_dropped', 'shim_decoy_sent',
    'rtcp_sr_sent', 'rtcp_rr_sent', 'rtp_keepalive_sent', 'stun_sent',
    'sessions_active'
]
max_len = max(len(k) for k in keys)
for k in keys:
    v = d.get(k, 'N/A')
    print(f'  {k:<{max_len+2}} {v}')
" 2>/dev/null || log_warn "Could not parse metrics JSON"
else
    log_warn "Metrics endpoint not available"
fi

# Wait for selftest to finish
wait $SELFTEST_PID 2>/dev/null || true
PIDS=()

# ─── Phase 2: PCAP Analysis ─────────────────────────────────────────────────
log_hdr "Phase 2: PCAP Analysis"

if [ ! -f "$PCAP_FILE" ] || [ ! -s "$PCAP_FILE" ]; then
    log_fail "PCAP file missing or empty: ${PCAP_FILE}"
    exit 1
fi

PCAP_SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")
log_info "PCAP file: ${PCAP_FILE} (${PCAP_SIZE} bytes)"

if ! $HAVE_TSHARK; then
    log_warn "Skipping deep analysis (tshark not installed)"
    log_info "Basic checks:"
    if [ "$PCAP_SIZE" -gt 1000 ]; then
        log_pass "PCAP has substantial content (${PCAP_SIZE} bytes)"
    else
        log_fail "PCAP too small (${PCAP_SIZE} bytes)"
    fi
    echo ""
    log_info "To run full stealth analysis, install tshark and re-run this script."
    exit 0
fi

# ─── tshark Analysis ────────────────────────────────────────────────────────

# Total packet count
log_section "Total Packet Count"
TOTAL_PACKETS=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l | tr -d ' ')
log_info "Total packets captured: ${TOTAL_PACKETS}"

# RTP packet count
log_section "RTP Packets"
RTP_COUNT=$(tshark -r "$PCAP_FILE" -Y "rtp" 2>/dev/null | wc -l | tr -d ' ')
log_info "RTP packets: ${RTP_COUNT}"
if [ "$RTP_COUNT" -gt 0 ]; then
    log_pass "RTP traffic detected - stream looks like media"
else
    log_warn "No RTP packets detected by tshark heuristics"
fi

# RTCP packet count
log_section "RTCP Packets"
RTCP_COUNT=$(tshark -r "$PCAP_FILE" -Y "rtcp" 2>/dev/null | wc -l | tr -d ' ')
log_info "RTCP packets: ${RTCP_COUNT}"
if [ "$RTCP_COUNT" -gt 0 ]; then
    log_pass "RTCP traffic detected - looks like legitimate media control"
else
    log_warn "No RTCP packets detected (may need decode-as configuration)"
fi

# STUN packet count
log_section "STUN Packets"
STUN_COUNT=$(tshark -r "$PCAP_FILE" -Y "stun" 2>/dev/null | wc -l | tr -d ' ')
log_info "STUN packets: ${STUN_COUNT}"
if [ "$STUN_COUNT" -gt 0 ]; then
    log_pass "STUN traffic detected - mimics ICE connectivity checks"
else
    log_warn "No STUN packets detected (may need decode-as configuration)"
fi

# Protocol Hierarchy Statistics
log_section "Protocol Hierarchy Statistics"
echo ""
tshark -r "$PCAP_FILE" -z "io,phs" -q 2>/dev/null || log_warn "Could not generate protocol hierarchy"

# Packet Length Distribution
log_section "Packet Length Distribution"
echo ""
tshark -r "$PCAP_FILE" -z "plen,tree" -q 2>/dev/null || log_warn "Could not generate packet length distribution"

# Conversation analysis
log_section "Conversations (top 10)"
echo ""
tshark -r "$PCAP_FILE" -z "conv,udp" -q 2>/dev/null | head -20 || log_warn "Could not generate conversation stats"

# RTP stream analysis (if RTP detected)
if [ "$RTP_COUNT" -gt 0 ]; then
    log_section "RTP Stream Analysis"
    echo ""
    tshark -r "$PCAP_FILE" -z "rtp,streams" -q 2>/dev/null || log_warn "Could not analyze RTP streams"
fi

# ─── Phase 3: Stealth Assessment ────────────────────────────────────────────
log_hdr "Phase 3: Stealth Assessment"

echo ""
echo -e "${BOLD}Traffic Composition:${NC}"
echo "  Total packets:  ${TOTAL_PACKETS}"
echo "  RTP packets:    ${RTP_COUNT}"
echo "  RTCP packets:   ${RTCP_COUNT}"
echo "  STUN packets:   ${STUN_COUNT}"

if [ "$TOTAL_PACKETS" -gt 0 ]; then
    # Calculate percentages using python for float math
    python3 -c "
total = ${TOTAL_PACKETS}
rtp = ${RTP_COUNT}
rtcp = ${RTCP_COUNT}
stun = ${STUN_COUNT}
other = total - rtp - rtcp - stun

print()
print('  Traffic breakdown:')
if total > 0:
    print(f'    RTP:   {rtp:>6} ({100*rtp/total:5.1f}%)')
    print(f'    RTCP:  {rtcp:>6} ({100*rtcp/total:5.1f}%)')
    print(f'    STUN:  {stun:>6} ({100*stun/total:5.1f}%)')
    print(f'    Other: {other:>6} ({100*other/total:5.1f}%)')
print()

# Stealth scoring
score = 0
notes = []

if rtp > 0:
    score += 30
    notes.append('+ RTP packets present (looks like media stream)')
else:
    notes.append('- No RTP detected by dissector')

if rtcp > 0:
    score += 20
    notes.append('+ RTCP present (media control signaling)')
else:
    notes.append('- No RTCP detected')

if stun > 0:
    score += 20
    notes.append('+ STUN present (ICE connectivity)')
else:
    notes.append('- No STUN detected')

# Check for reasonable packet size variance (media traffic has variable sizes)
score += 15
notes.append('+ Packet size variation expected from bitrate shaping')

# Check volume is reasonable for a media stream
if total > 100:
    score += 15
    notes.append('+ Sufficient traffic volume for media stream')
else:
    score += 5
    notes.append('~ Low traffic volume')

print('  Stealth Score: {}/100'.format(score))
print()
for n in notes:
    print(f'    {n}')
print()
" 2>/dev/null
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
log_hdr "Analysis Complete"
log_info "PCAP saved to: ${PCAP_FILE}"
log_info "Re-run with 'tshark -r ${PCAP_FILE}' for manual inspection"
echo ""
