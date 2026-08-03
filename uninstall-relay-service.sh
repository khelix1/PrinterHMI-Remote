#!/usr/bin/env bash
set -euo pipefail

service_name="printerhmi-remote-relay.service"
unit_path="/etc/systemd/system/$service_name"

sudo systemctl disable --now "$service_name" >/dev/null 2>&1 || true
sudo rm -f "$unit_path"
sudo systemctl daemon-reload

echo "PASS: PrinterHMI relay worker service removed"
echo "Relay configuration, identity and state were retained."
