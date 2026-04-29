#!/usr/bin/env bash
set -Eeuo pipefail

# Build kernel module, load it, start the route daemon, build the Qt GUI,
# launch the app, then stop the daemon and unload the module on exit.

MODULE=traffic_analyzer
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$ROOT_DIR/kernel_module"
BUILD_DIR="$ROOT_DIR/build"
GUI_BIN="$BUILD_DIR/gui/kernel_traffic_analyzer"
DAEMON="$ROOT_DIR/ta_route_daemon.py"
DAEMON_PID=""
LOADED=0

die() { printf 'KTA: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

cleanup() {
    status=$?
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [[ "$LOADED" == 1 ]] && lsmod | awk '{print $1}' | grep -qx "$MODULE"; then
        rmmod "$MODULE" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

[[ ${EUID:-$(id -u)} -eq 0 ]] || exec sudo -E bash "$0" "$@"
for cmd in make cmake python3 awk grep lsmod insmod rmmod; do need "$cmd"; done
[[ -d "/lib/modules/$(uname -r)/build" ]] || die "missing kernel headers for $(uname -r)"

real_user="${SUDO_USER:-$USER}"
real_uid="$(id -u "$real_user" 2>/dev/null || printf '1000')"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$real_uid}"
export DISPLAY="${DISPLAY:-:0}"
[[ -n "${XAUTHORITY:-}" || ! -f "/home/$real_user/.Xauthority" ]] || export XAUTHORITY="/home/$real_user/.Xauthority"

cd "$ROOT_DIR"
make -C "$KERNEL_DIR" clean || true
make -C "$KERNEL_DIR" -j"$(nproc)"
[[ -f "$KERNEL_DIR/$MODULE.ko" ]] || die "kernel module was not built"

if lsmod | awk '{print $1}' | grep -qx "$MODULE"; then rmmod "$MODULE"; fi
insmod "$KERNEL_DIR/$MODULE.ko"
LOADED=1
[[ -r /proc/traffic_analyzer ]] || die "/proc/traffic_analyzer was not created"

if [[ -f "$DAEMON" ]] && command -v traceroute >/dev/null 2>&1; then
    python3 "$DAEMON" &
    DAEMON_PID=$!
fi

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -- -j"$(nproc)"
exec "$GUI_BIN"
