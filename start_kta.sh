#!/usr/bin/env bash
set -Eeuo pipefail

# Kernel Traffic Analyzer launcher.
#
# What this script does:
#   1. Builds the kernel module, backend, and Qt GUI.
#   2. Loads traffic_analyzer.ko.
#   3. Starts the traceroute route daemon.
#   4. Optionally starts the AF_PACKET backend with --with-backend.
#   5. Launches the Qt GUI as the original desktop user.
#   6. Cleans up background processes and unloads the module on exit.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$ROOT_DIR/kernel_module"
BUILD_DIR="${KTA_BUILD_DIR:-$ROOT_DIR/build}"
MODULE_NAME="traffic_analyzer"
MODULE_KO="$KERNEL_DIR/$MODULE_NAME.ko"
ROUTE_DAEMON="${KTA_ROUTE_DAEMON:-$ROOT_DIR/daemon/ta_route_daemon.py}"
LOG_DIR="${KTA_LOG_DIR:-/tmp/kta}"
BUILD_LOG="$LOG_DIR/build.log"
BACKEND_OUTPUT="${KTA_BACKEND_OUTPUT:-/tmp/kta_flows.json}"

DO_BUILD=1
CLEAN_KERNEL=1
START_ROUTE_DAEMON=1
START_BACKEND="${KTA_START_BACKEND:-0}"
BACKEND_IFACE="${KTA_BACKEND_IFACE:-}"
KEEP_MODULE=0
VERBOSE="${KTA_VERBOSE:-0}"
GUI_ARGS=()

ROUTE_DAEMON_PID=""
BACKEND_PID=""
LOADED_BY_SCRIPT=0

usage() {
    cat <<'EOF'
Usage: ./start_kta.sh [options] [-- GUI_ARGS...]

Options:
  --no-build          Do not build; use existing binaries and module.
  --no-clean          Do not run kernel_module clean before building.
  --no-daemon         Do not start the route daemon.
  --with-backend      Start the AF_PACKET backend as well as the kernel module.
  --iface IFACE       Interface for --with-backend. Defaults to default route.
  --backend-output P  JSON output path for backend. Default: /tmp/kta_flows.json.
  --keep-module       Leave traffic_analyzer loaded when the GUI exits.
  --verbose           Print full build output instead of writing it to the log.
  -h, --help          Show this help.

Environment overrides:
  KTA_BUILD_DIR, KTA_LOG_DIR, KTA_ROUTE_DAEMON, KTA_START_BACKEND,
  KTA_BACKEND_IFACE, KTA_BACKEND_OUTPUT, KTA_VERBOSE
EOF
}

log() {
    printf '[KTA] %s\n' "$*"
}

warn() {
    printf '[KTA][WARN] %s\n' "$*" >&2
}

die() {
    printf '[KTA][ERROR] %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

version_ge() {
    local have="$1"
    local want="$2"
    printf '%s\n%s\n' "$want" "$have" | sort -V -C
}

check_qt_version() {
    local qt_version

    if ! command -v qmake6 >/dev/null 2>&1; then
        return
    fi

    qt_version="$(qmake6 -query QT_VERSION 2>/dev/null || true)"
    if [[ -n "$qt_version" ]] && ! version_ge "$qt_version" "6.2"; then
        die "Qt 6.2 or newer is required by gui/CMakeLists.txt; qmake6 reports Qt $qt_version"
    fi
}

module_loaded() {
    lsmod | awk '{print $1}' | grep -qx "$MODULE_NAME"
}

run_logged() {
    local label="$1"
    shift

    log "$label"
    if [[ "$VERBOSE" == "1" ]]; then
        "$@"
        return
    fi

    {
        printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$label"
        printf '$'
        printf ' %q' "$@"
        printf '\n'
    } >>"$BUILD_LOG"

    if ! "$@" >>"$BUILD_LOG" 2>&1; then
        tail -n 80 "$BUILD_LOG" >&2 || true
        die "$label failed; full log: $BUILD_LOG"
    fi
}

cleanup() {
    local status=$?

    if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        log "Stopping backend pid $BACKEND_PID"
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi

    if [[ -n "$ROUTE_DAEMON_PID" ]] && kill -0 "$ROUTE_DAEMON_PID" 2>/dev/null; then
        log "Stopping route daemon pid $ROUTE_DAEMON_PID"
        kill "$ROUTE_DAEMON_PID" 2>/dev/null || true
        wait "$ROUTE_DAEMON_PID" 2>/dev/null || true
    fi

    if [[ "$KEEP_MODULE" -eq 0 && "$LOADED_BY_SCRIPT" -eq 1 ]] && module_loaded; then
        log "Unloading $MODULE_NAME"
        rmmod "$MODULE_NAME" 2>/dev/null || warn "failed to unload $MODULE_NAME"
    fi

    exit "$status"
}
trap cleanup EXIT INT TERM

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-build)
                DO_BUILD=0
                shift
                ;;
            --no-clean)
                CLEAN_KERNEL=0
                shift
                ;;
            --no-daemon)
                START_ROUTE_DAEMON=0
                shift
                ;;
            --with-backend)
                START_BACKEND=1
                shift
                ;;
            --iface)
                [[ $# -ge 2 ]] || die "--iface requires a value"
                BACKEND_IFACE="$2"
                shift 2
                ;;
            --backend-output)
                [[ $# -ge 2 ]] || die "--backend-output requires a value"
                BACKEND_OUTPUT="$2"
                shift 2
                ;;
            --keep-module)
                KEEP_MODULE=1
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                GUI_ARGS=("$@")
                break
                ;;
            *)
                GUI_ARGS+=("$1")
                shift
                ;;
        esac
    done
}

require_root() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        return
    fi

    need sudo
    log "Root is required to load the kernel module. Re-running with sudo."
    exec sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XAUTHORITY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,QT_QPA_PLATFORM,KTA_BUILD_DIR,KTA_LOG_DIR,KTA_ROUTE_DAEMON,KTA_START_BACKEND,KTA_BACKEND_IFACE,KTA_BACKEND_OUTPUT \
        bash "$0" "$@"
}

preflight() {
    need awk
    need cmake
    need grep
    need insmod
    need lsmod
    need make
    need nproc
    need python3
    need rmmod
    need sort

    [[ -d "$KERNEL_DIR" ]] || die "missing kernel module directory: $KERNEL_DIR"
    [[ -f "$KERNEL_DIR/Makefile" ]] || die "missing kernel module Makefile"
    [[ -f "$ROOT_DIR/CMakeLists.txt" ]] || die "missing top-level CMakeLists.txt"
    [[ -d "/lib/modules/$(uname -r)/build" ]] || die "missing kernel headers for $(uname -r)"
    check_qt_version

    if [[ "$START_ROUTE_DAEMON" -eq 1 ]]; then
        [[ -f "$ROUTE_DAEMON" ]] || die "missing route daemon: $ROUTE_DAEMON"
        if ! command -v traceroute >/dev/null 2>&1; then
            warn "traceroute is missing; route daemon will not be started"
            START_ROUTE_DAEMON=0
        fi
    fi

    if [[ "$START_BACKEND" -eq 1 ]]; then
        need ip
    fi

    mkdir -p "$LOG_DIR"
}

build_project() {
    if [[ "$DO_BUILD" -eq 0 ]]; then
        log "Skipping build"
        return
    fi

    : >"$BUILD_LOG"
    if [[ "$CLEAN_KERNEL" -eq 1 ]]; then
        run_logged "Cleaning kernel module" make -C "$KERNEL_DIR" clean
    fi
    run_logged "Building kernel module" make -C "$KERNEL_DIR" -j"$(nproc)"
    [[ -f "$MODULE_KO" ]] || die "kernel module did not produce $MODULE_KO"

    run_logged "Configuring CMake project" cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

    run_logged "Building backend and GUI" cmake --build "$BUILD_DIR" --parallel "$(nproc)"
    log "Build log: $BUILD_LOG"
}

find_executable() {
    local path
    for path in "$@"; do
        if [[ -x "$path" ]]; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

load_module() {
    [[ -f "$MODULE_KO" ]] || die "kernel module not found: $MODULE_KO"

    if module_loaded; then
        log "$MODULE_NAME is already loaded; reloading it"
        rmmod "$MODULE_NAME" || die "failed to unload existing $MODULE_NAME"
    fi

    log "Loading $MODULE_KO"
    insmod "$MODULE_KO" || die "failed to load $MODULE_KO"
    LOADED_BY_SCRIPT=1

    [[ -r /proc/traffic_analyzer ]] || die "/proc/traffic_analyzer was not created"
    [[ -r /proc/traffic_analyzer_procs ]] || die "/proc/traffic_analyzer_procs was not created"
    [[ -r /proc/traffic_analyzer_dns ]] || die "/proc/traffic_analyzer_dns was not created"
    [[ -r /proc/traffic_analyzer_anomaly ]] || die "/proc/traffic_analyzer_anomaly was not created"
    [[ -r /proc/traffic_analyzer_routes ]] || die "/proc/traffic_analyzer_routes was not created"
    [[ -r /proc/traffic_analyzer_routes_pending ]] || die "/proc/traffic_analyzer_routes_pending was not created"
    [[ -r /proc/traffic_analyzer_stats ]] || die "/proc/traffic_analyzer_stats was not created"
}

start_route_daemon() {
    if [[ "$START_ROUTE_DAEMON" -eq 0 ]]; then
        log "Route daemon disabled"
        return
    fi

    log "Starting route daemon"
    python3 "$ROUTE_DAEMON" >"$LOG_DIR/route_daemon.log" 2>&1 &
    ROUTE_DAEMON_PID=$!
    sleep 0.2
    if ! kill -0 "$ROUTE_DAEMON_PID" 2>/dev/null; then
        die "route daemon exited immediately; see $LOG_DIR/route_daemon.log"
    fi
}

default_iface() {
    ip route show default 2>/dev/null | awk 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
}

start_backend() {
    local backend_bin

    if [[ "$START_BACKEND" -eq 0 ]]; then
        return
    fi

    backend_bin="$(find_executable \
        "$BUILD_DIR/backend/kta_backend" \
        "$BUILD_DIR/backend/kta_packet_backend" \
        "$ROOT_DIR/build/backend/kta_backend" \
        "$ROOT_DIR/build/backend/kta_packet_backend")" || die "backend binary not found after build"

    if [[ -z "$BACKEND_IFACE" ]]; then
        BACKEND_IFACE="$(default_iface)"
    fi
    [[ -n "$BACKEND_IFACE" ]] || die "could not detect default network interface; pass --iface IFACE"

    log "Starting backend on $BACKEND_IFACE, exporting to $BACKEND_OUTPUT"
    "$backend_bin" --iface "$BACKEND_IFACE" --output "$BACKEND_OUTPUT" >"$LOG_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    sleep 0.3
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        die "backend exited immediately; see $LOG_DIR/backend.log"
    fi
}

real_user() {
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
        printf '%s\n' "$SUDO_USER"
    else
        id -un
    fi
}

run_gui_as_desktop_user() {
    local gui_bin user uid home_dir runtime_dir qt_qpa_platform

    gui_bin="$(find_executable \
        "$BUILD_DIR/gui/kta_gui" \
        "$BUILD_DIR/gui/kernel_traffic_analyzer" \
        "$ROOT_DIR/gui/build/kta_gui" \
        "$ROOT_DIR/gui/build/kernel_traffic_analyzer")" || die "GUI binary not found after build"

    if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
        die "no DISPLAY or WAYLAND_DISPLAY is set; cannot launch Qt GUI"
    fi

    user="$(real_user)"
    uid="$(id -u "$user" 2>/dev/null || printf '0')"
    home_dir="$(getent passwd "$user" 2>/dev/null | awk -F: 'NR == 1 {print $6}')"
    runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$uid}"

    if [[ -z "${XAUTHORITY:-}" && -n "$home_dir" && -f "$home_dir/.Xauthority" ]]; then
        export XAUTHORITY="$home_dir/.Xauthority"
    fi
    qt_qpa_platform="${QT_QPA_PLATFORM:-}"
    if [[ -z "$qt_qpa_platform" && -n "${DISPLAY:-}" ]]; then
        qt_qpa_platform="xcb"
    fi

    log "Launching GUI: $gui_bin"
    if [[ "$user" == "root" ]]; then
        QT_QPA_PLATFORM="$qt_qpa_platform" "$gui_bin" "${GUI_ARGS[@]}"
    else
        sudo -u "$user" env \
            HOME="$home_dir" \
            USER="$user" \
            LOGNAME="$user" \
            DISPLAY="${DISPLAY:-}" \
            WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
            QT_QPA_PLATFORM="$qt_qpa_platform" \
            XAUTHORITY="${XAUTHORITY:-}" \
            XDG_RUNTIME_DIR="$runtime_dir" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            "$gui_bin" "${GUI_ARGS[@]}"
    fi
}

main() {
    parse_args "$@"
    require_root "$@"
    preflight

    cd "$ROOT_DIR"
    build_project
    load_module
    start_route_daemon
    start_backend
    run_gui_as_desktop_user
}

main "$@"
