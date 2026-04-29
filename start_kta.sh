#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Kernel Traffic Analyzer"
MODULE_NAME="traffic_analyzer"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$ROOT_DIR/kernel_module"
GUI_DIR="$ROOT_DIR/gui"
GUI_BUILD_DIR="$GUI_DIR/build"
GUI_BIN="$GUI_BUILD_DIR/kernel_traffic_analyzer"
ROUTE_DAEMON="$ROOT_DIR/ta_route_daemon.py"

ROUTE_DAEMON_PID=""
MODULE_LOADED_BY_SCRIPT=0

log() {
    printf '\033[1;34m[KTA]\033[0m %s\n' "$*"
}

warn() {
    printf '\033[1;33m[KTA]\033[0m %s\n' "$*" >&2
}

fail() {
    printf '\033[1;31m[KTA]\033[0m %s\n' "$*" >&2
    exit 1
}

run() {
    log "$*"
    "$@"
}

cleanup() {
    local status=$?

    if [[ -n "${ROUTE_DAEMON_PID:-}" ]] && kill -0 "$ROUTE_DAEMON_PID" 2>/dev/null; then
        log "Stopping route daemon..."
        kill "$ROUTE_DAEMON_PID" 2>/dev/null || true
        wait "$ROUTE_DAEMON_PID" 2>/dev/null || true
    fi

    if [[ "$MODULE_LOADED_BY_SCRIPT" == "1" ]] && lsmod | awk '{print $1}' | grep -qx "$MODULE_NAME"; then
        log "Unloading kernel module..."
        rmmod "$MODULE_NAME" 2>/dev/null || warn "Could not unload $MODULE_NAME. It may still be in use."
    fi

    exit "$status"
}
trap cleanup EXIT INT TERM

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing '$1'. Install it and run this script again."
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log "Root is required to load the kernel module and run the route daemon. Re-launching with sudo..."
        exec sudo -E bash "$0" "$@"
    fi
}

prepare_display_env() {
    local real_user="${SUDO_USER:-$USER}"
    local real_uid

    real_uid="$(id -u "$real_user" 2>/dev/null || printf '1000')"

    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$real_uid}"
    export DISPLAY="${DISPLAY:-:0}"

    if [[ -z "${XAUTHORITY:-}" && -f "/home/$real_user/.Xauthority" ]]; then
        export XAUTHORITY="/home/$real_user/.Xauthority"
    fi
}

check_dependencies() {
    need_cmd make
    need_cmd cmake
    need_cmd python3
    need_cmd awk
    need_cmd grep
    need_cmd lsmod
    need_cmd insmod
    need_cmd rmmod

    [[ -d "/lib/modules/$(uname -r)/build" ]] || fail "Kernel headers are missing for $(uname -r). Install linux-headers-$(uname -r)."
}

build_kernel_module() {
    [[ -f "$KERNEL_DIR/Makefile" ]] || fail "Missing kernel module Makefile at $KERNEL_DIR/Makefile"

    log "Building kernel module..."
    run make -C "$KERNEL_DIR" clean
    run make -C "$KERNEL_DIR" "-j$(nproc)"

    [[ -f "$KERNEL_DIR/$MODULE_NAME.ko" ]] || fail "Kernel build finished, but $MODULE_NAME.ko was not created."
}

load_kernel_module() {
    if lsmod | awk '{print $1}' | grep -qx "$MODULE_NAME"; then
        log "Unloading existing $MODULE_NAME module..."
        rmmod "$MODULE_NAME" || fail "Could not unload existing $MODULE_NAME module."
    fi

    log "Loading kernel module..."
    insmod "$KERNEL_DIR/$MODULE_NAME.ko"
    MODULE_LOADED_BY_SCRIPT=1

    [[ -r /proc/traffic_analyzer ]] || fail "/proc/traffic_analyzer was not created after loading the module."
}

start_route_daemon() {
    if [[ ! -f "$ROUTE_DAEMON" ]]; then
        warn "Route daemon not found at $ROUTE_DAEMON. Continuing without route enrichment."
        return
    fi

    if ! command -v traceroute >/dev/null 2>&1; then
        warn "traceroute is not installed. Continuing without route enrichment. Install it with: sudo apt install traceroute"
        return
    fi

    log "Starting route daemon..."
    python3 "$ROUTE_DAEMON" --verbose &
    ROUTE_DAEMON_PID=$!
    sleep 1

    if ! kill -0 "$ROUTE_DAEMON_PID" 2>/dev/null; then
        ROUTE_DAEMON_PID=""
        warn "Route daemon exited early. The GUI will still run, but route maps may be empty."
    fi
}

build_gui() {
    [[ -f "$GUI_DIR/CMakeLists.txt" ]] || fail "Missing GUI CMakeLists.txt at $GUI_DIR/CMakeLists.txt"

    log "Configuring GUI..."
    run cmake -S "$GUI_DIR" -B "$GUI_BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

    log "Building GUI..."
    run cmake --build "$GUI_BUILD_DIR" -- "-j$(nproc)"

    [[ -x "$GUI_BIN" ]] || fail "GUI build finished, but executable was not found at $GUI_BIN."
}

launch_gui() {
    prepare_display_env

    log "Launching $APP_NAME..."
    "$GUI_BIN"
}

main() {
    cd "$ROOT_DIR"
    require_root "$@"
    check_dependencies
    build_kernel_module
    load_kernel_module
    start_route_daemon
    build_gui
    launch_gui
}

main "$@"
