#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
service_name="printerhmi-remote.service"
service_user="${PRINTERHMI_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"

for command_name in getent id sed sudo systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $command_name" >&2
        exit 1
    }
done

[[ -x "$repo_dir/.venv/bin/printerhmi-agent" ]] || {
    echo "ERROR: run ./install.sh first" >&2
    exit 1
}

passwd_entry="$(getent passwd "$service_user")"
[[ -n "$passwd_entry" ]] || {
    echo "ERROR: service user does not exist: $service_user" >&2
    exit 1
}

home_dir="$(printf '%s\n' "$passwd_entry" | cut -d: -f6)"
service_group="$(id -gn "$service_user")"
state_dir="$home_dir/.local/state/printerhmi-remote"
unit_template="$repo_dir/packaging/systemd/printerhmi-remote.service.in"
unit_path="/etc/systemd/system/$service_name"
unit_temp="$(mktemp)"
trap 'rm -f "$unit_temp"' EXIT

# Retire the development user unit if it was installed during field testing.
# Failure is harmless when no user manager is available in the current shell.
systemctl --user disable --now "$service_name" >/dev/null 2>&1 || true

sed \
    -e "s|@REPO_DIR@|$repo_dir|g" \
    -e "s|@AGENT@|$repo_dir/.venv/bin/printerhmi-agent|g" \
    -e "s|@SERVICE_USER@|$service_user|g" \
    -e "s|@SERVICE_GROUP@|$service_group|g" \
    -e "s|@HOME_DIR@|$home_dir|g" \
    -e "s|@STATE_DIR@|$state_dir|g" \
    "$unit_template" > "$unit_temp"

sudo install -d -m 0750 -o "$service_user" -g "$service_group" "$state_dir"
sudo install -m 0644 "$unit_temp" "$unit_path"
sudo systemctl daemon-reload
sudo systemctl enable --now "$service_name"

echo "PASS: PrinterHMI Remote system service enabled"
echo "Service user: $service_user"
echo "State: $state_dir/status.json"
echo "Status: sudo systemctl status $service_name"
