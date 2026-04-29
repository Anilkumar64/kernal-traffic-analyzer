#!/usr/bin/env bash
set -euo pipefail

systemctl stop kta-route.service || true
systemctl disable kta-route.service || true
rm -f /etc/systemd/system/kta-route.service
systemctl daemon-reload

rmmod traffic_analyzer || true

rm -f /usr/local/bin/kta_backend /usr/local/bin/kta_gui
rm -rf /usr/local/lib/kta

echo "KTA uninstalled."
