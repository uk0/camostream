#!/usr/bin/env bash
#
# CamoStream - Master Test Runner
# Runs all test suites and generates a summary report
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
REPORT_FILE="$RESULTS_DIR/test_report.txt"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

header() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

log() { echo -e "[$(date '+%H:%M:%S')] $1"; }

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

run_suite() {
    local name="$1"
    local script="$2"
    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    header "Test Suite: $name"

    local logfile="$RESULTS_DIR/${name// /_}_${TIMESTAMP}.log"

    if bash "$script" 2>&1 | tee "$logfile"; then
        echo -e "\n${GREEN}[SUITE PASS] $name${NC}\n"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        echo -e "\n${RED}[SUITE FAIL] $name${NC}\n"
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
}

# ----------------------------------------------------------------
# Phase 0: Build
# ----------------------------------------------------------------
header "Build CamoStream"
cd "$PROJECT_ROOT"

if ! command -v go &>/dev/null; then
    echo -e "${RED}Go not found. Install Go 1.24+ first.${NC}"
    exit 1
fi

log "Building camostream binary..."
go build -o camostream main.go
log "Build OK: $(file camostream)"

# Build UDP echo server for tests
log "Building UDP echo server..."
(cd sim && go build -o ../udp_echo udp_server.go)
log "Build OK: udp_echo"

# ----------------------------------------------------------------
# Phase 1: Local E2E Tests (no Docker)
# ----------------------------------------------------------------
if [ -f "$SCRIPT_DIR/scripts/test_e2e.sh" ]; then
    run_suite "E2E-Local" "$SCRIPT_DIR/scripts/test_e2e.sh"
else
    log "${YELLOW}Skipping E2E tests (script not found)${NC}"
fi

# ----------------------------------------------------------------
# Phase 2: Traffic Stealth Analysis
# ----------------------------------------------------------------
if [ -f "$SCRIPT_DIR/scripts/test_traffic_stealth.sh" ]; then
    run_suite "Traffic-Stealth" "$SCRIPT_DIR/scripts/test_traffic_stealth.sh"
else
    log "${YELLOW}Skipping stealth tests (script not found)${NC}"
fi

# ----------------------------------------------------------------
# Phase 3: Python PCAP Deep Analysis
# ----------------------------------------------------------------
if [ -f "$SCRIPT_DIR/scripts/analyze_pcap.py" ]; then
    # Run selftest to generate a fresh pcap for analysis
    ANALYSIS_PCAP="$RESULTS_DIR/analysis_${TIMESTAMP}.pcap"
    header "Generating PCAP for deep analysis (selftest 15s)"
    timeout 25 "$PROJECT_ROOT/camostream" \
        -role=selftest -mode=udp -wire=rtpish \
        -fps=60 -bitrate-mbps=20 \
        -decoy-rps=10 \
        -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
        -pcap="$ANALYSIS_PCAP" -pcap-max-mb=20 \
        -metrics=:9300 -duration=15s -log=warn \
    || true

    if [ -f "$ANALYSIS_PCAP" ] && [ -s "$ANALYSIS_PCAP" ]; then
        if command -v python3 &>/dev/null; then
            # Install deps if needed
            pip3 install scapy numpy 2>/dev/null || true

            TOTAL_SUITES=$((TOTAL_SUITES + 1))
            ANALYSIS_REPORT="$RESULTS_DIR/pcap_analysis_${TIMESTAMP}.json"
            header "PCAP Deep Analysis"
            if python3 "$SCRIPT_DIR/scripts/analyze_pcap.py" \
                "$ANALYSIS_PCAP" --mode udp \
                --output "$ANALYSIS_REPORT" 2>&1 | tee "$RESULTS_DIR/pcap_analysis_${TIMESTAMP}.log"; then
                echo -e "\n${GREEN}[SUITE PASS] PCAP-Analysis${NC}\n"
                PASSED_SUITES=$((PASSED_SUITES + 1))
            else
                echo -e "\n${RED}[SUITE FAIL] PCAP-Analysis${NC}\n"
                FAILED_SUITES=$((FAILED_SUITES + 1))
            fi
        else
            log "${YELLOW}Python3 not found, skipping PCAP analysis${NC}"
        fi
    else
        log "${YELLOW}No PCAP generated, skipping analysis${NC}"
    fi
else
    log "${YELLOW}Skipping PCAP analysis (script not found)${NC}"
fi

# ----------------------------------------------------------------
# Phase 4: Docker Compose Tests (if docker available)
# ----------------------------------------------------------------
if command -v docker &>/dev/null && command -v docker-compose &>/dev/null || docker compose version &>/dev/null 2>&1; then
    if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
        TOTAL_SUITES=$((TOTAL_SUITES + 1))
        header "Docker Compose Integration Tests"

        COMPOSE_CMD="docker compose"
        if ! docker compose version &>/dev/null 2>&1; then
            COMPOSE_CMD="docker-compose"
        fi

        cd "$SCRIPT_DIR"
        log "Starting Docker environment..."

        if $COMPOSE_CMD up --build --abort-on-container-exit --exit-code-from test-runner 2>&1 \
            | tee "$RESULTS_DIR/docker_${TIMESTAMP}.log"; then
            echo -e "\n${GREEN}[SUITE PASS] Docker-Integration${NC}\n"
            PASSED_SUITES=$((PASSED_SUITES + 1))
        else
            echo -e "\n${RED}[SUITE FAIL] Docker-Integration${NC}\n"
            FAILED_SUITES=$((FAILED_SUITES + 1))
        fi

        # Cleanup
        $COMPOSE_CMD down -v --remove-orphans 2>/dev/null || true
        cd "$PROJECT_ROOT"
    fi
else
    log "${YELLOW}Docker not available, skipping Docker tests${NC}"
fi

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
header "Test Summary"

echo -e "  Total suites:  $TOTAL_SUITES"
echo -e "  ${GREEN}Passed:        $PASSED_SUITES${NC}"
echo -e "  ${RED}Failed:        $FAILED_SUITES${NC}"
echo ""
echo "  Results dir:   $RESULTS_DIR"
echo "  Timestamp:     $TIMESTAMP"
echo ""

# Write report
{
    echo "CamoStream Test Report - $TIMESTAMP"
    echo "======================================"
    echo "Total: $TOTAL_SUITES | Pass: $PASSED_SUITES | Fail: $FAILED_SUITES"
    echo ""
    echo "Results in: $RESULTS_DIR"
} > "$REPORT_FILE"

if [ "$FAILED_SUITES" -gt 0 ]; then
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi

echo -e "${GREEN}All tests passed!${NC}"
exit 0
