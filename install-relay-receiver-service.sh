#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
service_name="printerhmi-relay-receiver.service"
service_user="${PRINTERHMI_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
config=""
listener_confirmed=false

usage()
{
    echo "Usage: ./install-relay-receiver-service.sh --config PATH --enable-listener"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            config="$2"
            shift 2
            ;;
        --enable-listener)
            listener_confirmed=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$config" ]] || { echo "ERROR: --config is required" >&2; exit 2; }
[[ "$listener_confirmed" == true ]] || {
    echo "ERROR: --enable-listener is required for the receiver service" >&2
    exit 2
}
config="$(readlink -f "$config")"
[[ -f "$config" ]] || { echo "ERROR: config not found: $config" >&2; exit 1; }
agent="$repo_dir/.venv/bin/printerhmi-agent"
[[ -x "$agent" ]] || { echo "ERROR: run ./install.sh first" >&2; exit 1; }

passwd_entry="$(getent passwd "$service_user")"
[[ -n "$passwd_entry" ]] || {
    echo "ERROR: service user does not exist: $service_user" >&2
    exit 1
}
home_dir="$(printf '%s\n' "$passwd_entry" | cut -d: -f6)"
service_group="$(id -gn "$service_user")"

sudo -u "$service_user" env HOME="$home_dir" \
    "$agent" relay-receiver --config "$config" --validate-config

mapfile -t config_values < <(
    sudo -u "$service_user" env HOME="$home_dir" \
      "$repo_dir/.venv/bin/python" - "$config" <<'PY'
import sys
from pathlib import Path
from printerhmi_agent.relay_receiver import RelayReceiverConfig

config = RelayReceiverConfig.load(Path(sys.argv[1]))
print(config.state_file.parent)
print(config.cert_file)
print(config.key_file)
print(config.api_socket)
PY
)

state_dir="${config_values[0]}"
cert_file="${config_values[1]}"
key_file="${config_values[2]}"
api_socket="${config_values[3]}"
template="$repo_dir/packaging/systemd/printerhmi-relay-receiver.service.in"
unit_path="/etc/systemd/system/$service_name"
unit_temp="$(mktemp)"
trap 'rm -f "$unit_temp"' EXIT

sed \
    -e "s|@REPO_DIR@|$repo_dir|g" \
    -e "s|@AGENT@|$agent|g" \
    -e "s|@SERVICE_USER@|$service_user|g" \
    -e "s|@SERVICE_GROUP@|$service_group|g" \
    -e "s|@HOME_DIR@|$home_dir|g" \
    -e "s|@CONFIG@|$config|g" \
    -e "s|@CERT_FILE@|$cert_file|g" \
    -e "s|@KEY_FILE@|$key_file|g" \
    -e "s|@STATE_DIR@|$state_dir|g" \
    "$template" > "$unit_temp"

sudo install -d -m 0750 -o "$service_user" -g "$service_group" "$state_dir"
sudo install -m 0644 "$unit_temp" "$unit_path"
sudo systemctl daemon-reload
sudo systemctl enable "$service_name"
sudo systemctl restart "$service_name"

ready=false
for _attempt in {1..40}; do
    if sudo systemctl is-active --quiet "$service_name" &&
       sudo -u "$service_user" env HOME="$home_dir" \
         "$agent" relay-receiver --config "$config" \
           --api health >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.25
done

[[ "$ready" == true ]] || {
    echo "ERROR: relay receiver did not become ready" >&2
    sudo systemctl status "$service_name" --no-pager -l >&2 || true
    exit 1
}

echo "PASS: loopback PrinterHMI relay receiver enabled"
echo "Config: $config"
echo "Local API: $api_socket"
echo "Status: sudo systemctl status $service_name"
