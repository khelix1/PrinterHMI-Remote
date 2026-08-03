#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
service_name="printerhmi-remote-relay.service"
service_user="${PRINTERHMI_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
config=""
network_confirmed=false

usage()
{
    echo "Usage: ./install-relay-service.sh --config PATH --enable-network"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            config="$2"
            shift 2
            ;;
        --enable-network)
            network_confirmed=true
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
[[ "$network_confirmed" == true ]] || {
    echo "ERROR: --enable-network is required for the outbound relay service" >&2
    exit 2
}
config="$(readlink -f "$config")"
[[ -f "$config" ]] || { echo "ERROR: config not found: $config" >&2; exit 1; }
[[ -x "$repo_dir/.venv/bin/printerhmi-relay-worker" ]] || {
    echo "ERROR: run ./install.sh first" >&2
    exit 1
}

passwd_entry="$(getent passwd "$service_user")"
home_dir="$(printf '%s\n' "$passwd_entry" | cut -d: -f6)"
service_group="$(id -gn "$service_user")"
state_dir="$home_dir/.local/state/printerhmi-remote"
api_socket="$state_dir/agent.sock"
worker_state="$state_dir/relay-worker.json"
template="$repo_dir/packaging/systemd/printerhmi-remote-relay.service.in"
unit_path="/etc/systemd/system/$service_name"
unit_temp="$(mktemp)"
trap 'rm -f "$unit_temp"' EXIT

sudo -u "$service_user" env HOME="$home_dir" \
    "$repo_dir/.venv/bin/printerhmi-relay-worker" \
    --config "$config" --validate-config

ca_file="$(sudo -u "$service_user" env HOME="$home_dir" \
    "$repo_dir/.venv/bin/python" -c \
    'import sys; from pathlib import Path; from printerhmi_agent.relay_transport import RelayConfig; print(RelayConfig.load(Path(sys.argv[1])).ca_file)' \
    "$config")"

sed \
    -e "s|@REPO_DIR@|$repo_dir|g" \
    -e "s|@WORKER@|$repo_dir/.venv/bin/printerhmi-relay-worker|g" \
    -e "s|@SERVICE_USER@|$service_user|g" \
    -e "s|@SERVICE_GROUP@|$service_group|g" \
    -e "s|@HOME_DIR@|$home_dir|g" \
    -e "s|@STATE_DIR@|$state_dir|g" \
    -e "s|@API_SOCKET@|$api_socket|g" \
    -e "s|@WORKER_STATE@|$worker_state|g" \
    -e "s|@CONFIG@|$config|g" \
    -e "s|@CA_FILE@|$ca_file|g" \
    "$template" > "$unit_temp"

sudo install -d -m 0750 -o "$service_user" -g "$service_group" "$state_dir"
sudo install -m 0644 "$unit_temp" "$unit_path"
sudo systemctl daemon-reload
sudo systemctl enable "$service_name"
sudo systemctl restart "$service_name"

for _attempt in {1..40}; do
    sudo systemctl is-active --quiet "$service_name" && break
    sleep 0.25
done
sudo systemctl is-active --quiet "$service_name" || {
    echo "ERROR: relay worker service did not start" >&2
    sudo systemctl status "$service_name" --no-pager -l >&2 || true
    exit 1
}

echo "PASS: opt-in PrinterHMI relay worker enabled"
echo "Config: $config"
echo "Status: sudo systemctl status $service_name"
