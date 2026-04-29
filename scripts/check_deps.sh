#!/usr/bin/env bash
set -euo pipefail

missing=0

ok() {
    printf '[OK] %s\n' "$1"
}

missing_required() {
    printf '[MISSING] %s\n' "$1"
    missing=1
}

missing_optional() {
    printf '[OPTIONAL - missing] %s\n' "$1"
}

version_ge() {
    local have="$1"
    local want="$2"
    printf '%s\n%s\n' "$want" "$have" | sort -V -C
}

if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
    ok "kernel headers for $(uname -r)"
else
    missing_required "kernel headers for $(uname -r)"
fi

for tool in gcc make; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        missing_required "$tool"
    fi
done

if command -v cmake >/dev/null 2>&1; then
    cmake_version="$(cmake --version | awk 'NR==1 {print $3}')"
    if version_ge "$cmake_version" "3.20"; then
        ok "cmake >= 3.20"
    else
        missing_required "cmake >= 3.20"
    fi
else
    missing_required "cmake >= 3.20"
fi

if command -v clang >/dev/null 2>&1; then
    ok "clang for eBPF"
else
    missing_required "clang for eBPF"
fi

if dpkg-query -W -f='${Status}' qt6-base-dev >/dev/null 2>&1 || \
   dpkg-query -W -f='${Status}' libqt6-dev >/dev/null 2>&1; then
    ok "Qt6 development packages"
else
    missing_required "Qt6 development packages"
fi

if dpkg-query -W -f='${Status}' libsqlite3-dev >/dev/null 2>&1; then
    ok "libsqlite3-dev"
else
    missing_required "libsqlite3-dev"
fi

if command -v python3 >/dev/null 2>&1; then
    python_version="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
    if version_ge "$python_version" "3.9"; then
        ok "python3 >= 3.9"
    else
        missing_required "python3 >= 3.9"
    fi
else
    missing_required "python3 >= 3.9"
fi

if command -v pip3 >/dev/null 2>&1; then
    ok "pip3"
else
    missing_required "pip3"
fi

if command -v traceroute >/dev/null 2>&1; then
    ok "traceroute"
else
    missing_required "traceroute"
fi

if python3 -c 'import geoip2' >/dev/null 2>&1; then
    ok "geoip2 python module"
else
    missing_optional "geoip2 python module"
fi

exit "$missing"
