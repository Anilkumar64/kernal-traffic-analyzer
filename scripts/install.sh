#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID}" -ne 0 ]]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

# Verify toolchain and runtime dependencies before modifying the system.
bash scripts/check_deps.sh

# Build all project components from their canonical source directories.
make -C kernel_module
cmake -B build/backend -S backend -DCMAKE_BUILD_TYPE=Release
cmake --build build/backend --parallel
cmake -B build/gui -S gui -DCMAKE_BUILD_TYPE=Release
cmake --build build/gui --parallel

# Load the kernel module for the current boot session.
insmod kernel_module/traffic_analyzer.ko

cp build/backend/kta_backend /usr/local/bin/
if [[ -x build/gui/kta_gui ]]; then
    cp build/gui/kta_gui /usr/local/bin/
elif [[ -x gui/build/kta_gui ]]; then
    cp gui/build/kta_gui /usr/local/bin/
else
    echo "kta_gui binary not found after GUI build" >&2
    exit 1
fi

mkdir -p /usr/local/lib/kta
cp daemon/ta_route_daemon.py /usr/local/lib/kta/
chmod 0755 /usr/local/lib/kta/ta_route_daemon.py

pip3 install -r daemon/requirements.txt

cp daemon/kta-route.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now kta-route.service

echo "KTA installed. Run: sudo kta_gui"
