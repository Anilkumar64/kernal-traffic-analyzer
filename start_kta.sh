#!/bin/bash

# ================================================================
# KTA — Kernel Traffic Analyzer — Full Start Script
# ================================================================

set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR=$PROJ/kernel_module
GUI_DIR=$PROJ/gui
BUILD_DIR=$GUI_DIR/build
MODULE_NAME=traffic_analyzer

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

log()  { echo -e "${BLUE}[KTA]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC}  $1"; }
warn() { echo -e "${AMBER}[!!]${NC}  $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }
sep()  { echo -e "${DIM}────────────────────────────────────────────${NC}"; }

sep
echo -e "${CYAN}  Kernel Traffic Analyzer  v6.0${NC}"
echo -e "${DIM}  Starting full build and launch...${NC}"
sep

# ── Must run as root ─────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    warn "Re-launching with sudo..."
    exec sudo bash "$0" "$@"
fi

# ── Step 1: Unload existing kernel module ────────────────────────
log "Unloading existing kernel module (if loaded)..."
if lsmod | grep -q "^$MODULE_NAME"; then
    rmmod $MODULE_NAME && ok "Module unloaded" || warn "rmmod failed — continuing"
else
    ok "Module was not loaded"
fi

# ── Step 2: Clean and rebuild kernel module ──────────────────────
sep
log "Cleaning kernel module build..."
cd $MODULE_DIR
make clean 2>/dev/null || true
ok "Kernel module cleaned"

log "Building kernel module..."
make -j$(nproc) 2>&1 | tail -5
if [ ! -f "$MODULE_DIR/$MODULE_NAME.ko" ]; then
    err "Kernel module build failed — $MODULE_NAME.ko not found"
fi
ok "Kernel module built successfully"

# ── Step 3: Load kernel module ───────────────────────────────────
sep
log "Loading kernel module..."
insmod $MODULE_DIR/$MODULE_NAME.ko
sleep 1

if lsmod | grep -q "^$MODULE_NAME"; then
    ok "Module loaded: $(lsmod | grep ^$MODULE_NAME)"
else
    err "Module failed to load — check: dmesg | tail -20"
fi

# Verify /proc files
log "Verifying /proc interface..."
PROC_FILES=(
    "/proc/traffic_analyzer"
    "/proc/traffic_analyzer_procs"
    "/proc/traffic_analyzer_dns"
    "/proc/traffic_analyzer_anomalies"
    "/proc/traffic_analyzer_dns_map"
    "/proc/traffic_analyzer_routes"
    "/proc/traffic_analyzer_routes_pending"
)
for f in "${PROC_FILES[@]}"; do
    if [ -f "$f" ]; then
        ok "  $f"
    else
        warn "  MISSING: $f"
    fi
done

# ── Step 4: Clean GUI build ──────────────────────────────────────
sep
log "Cleaning GUI build..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
ok "GUI build directory cleaned"

# ── Step 5: Build GUI ────────────────────────────────────────────
log "Running cmake..."
cd $BUILD_DIR
cmake $GUI_DIR -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -5
ok "cmake done"

log "Building GUI (this may take a minute)..."
make -j$(nproc) 2>&1 | grep -E "^\[|error:|warning:" | grep -v "deprecated" | tail -20

if [ ! -f "$BUILD_DIR/kernel_traffic_analyzer" ]; then
    err "GUI build failed — binary not found"
fi
ok "GUI built successfully"

# ── Step 6: Start route daemon in background ─────────────────────
sep
log "Starting route daemon..."
if pgrep -f "ta_route_daemon.py" > /dev/null; then
    warn "Route daemon already running — restarting..."
    pkill -f "ta_route_daemon.py" || true
    sleep 1
fi
cd $PROJ
python3 ta_route_daemon.py --verbose > /tmp/kta_daemon.log 2>&1 &
DAEMON_PID=$!
sleep 1
if kill -0 $DAEMON_PID 2>/dev/null; then
    ok "Route daemon started (PID $DAEMON_PID) — log: /tmp/kta_daemon.log"
else
    warn "Route daemon failed to start — routes won't be enriched"
    warn "Check: cat /tmp/kta_daemon.log"
fi

# ── Step 7: Quick data check ─────────────────────────────────────
sep
log "Checking live data..."
CONN_COUNT=$(cat /proc/traffic_analyzer 2>/dev/null | grep -v "^PID" | wc -l)
PROC_COUNT=$(cat /proc/traffic_analyzer_procs 2>/dev/null | grep -v "^PID" | wc -l)
DNS_COUNT=$(cat /proc/traffic_analyzer_dns_map 2>/dev/null | grep -v "^IP" | wc -l)
echo -e "  Connections : ${CYAN}$CONN_COUNT${NC}"
echo -e "  Processes   : ${CYAN}$PROC_COUNT${NC}"
echo -e "  DNS entries : ${CYAN}$DNS_COUNT${NC}"

# ── Step 8: Launch GUI ───────────────────────────────────────────
sep
ok "All systems ready — launching KTA GUI..."
sep
cd $BUILD_DIR
./kernel_traffic_analyzer

# ── Cleanup on exit ──────────────────────────────────────────────
sep
log "GUI closed — cleaning up..."
if kill -0 $DAEMON_PID 2>/dev/null; then
    kill $DAEMON_PID
    ok "Route daemon stopped"
fi

log "Unloading kernel module..."
rmmod $MODULE_NAME 2>/dev/null && ok "Module unloaded" || warn "Module already unloaded"
sep
echo -e "${CYAN}  KTA stopped cleanly.${NC}"
sep
