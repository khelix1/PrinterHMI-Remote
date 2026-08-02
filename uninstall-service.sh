#!/usr/bin/env bash
set -euo pipefail

service_name="printerhmi-remote.service"
unit_path="/etc/systemd/system/$service_name"

command -v sudo >/dev/null 2>&1 || {
    echo "ERROR: sudo is required" >&2
    exit 1
}

sudo systemctl disable --now "$service_name" 2>/dev/null || true
sudo rm -f "$unit_path"
sudo systemctl daemon-reload
sudo systemctl reset-failed "$service_name" 2>/dev/null || true

echo "PASS: PrinterHMI Remote system service removed"
echo "Normalized state was retained under ~/.local/state/printerhmi-remote"
