#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
moonraker_config="${PRINTERHMI_MOONRAKER_CONFIG:-}"
moonraker_service="${PRINTERHMI_MOONRAKER_SERVICE:-moonraker.service}"
include_name="printerhmi-remote-update.conf"
include_line="[include $include_name]"
service_name="printerhmi-remote"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --moonraker-config)
            moonraker_config="$2"
            shift 2
            ;;
        --moonraker-service)
            moonraker_service="$2"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

service_user="${PRINTERHMI_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
home_dir="$(getent passwd "$service_user" | cut -d: -f6)"
if [[ -z "$moonraker_config" ]]; then
    mapfile -t candidates < <(
        find "$home_dir" -maxdepth 5 -type f \
            -path '*/config/moonraker.conf' -print 2>/dev/null | sort
    )
    [[ ${#candidates[@]} -eq 1 ]] || {
        echo "ERROR: specify --moonraker-config PATH" >&2
        exit 1
    }
    moonraker_config="${candidates[0]}"
fi

config_dir="$(cd "$(dirname "$moonraker_config")" && pwd)"
data_dir="$(cd "$config_dir/.." && pwd)"
fragment="$config_dir/$include_name"
allowed_services="$data_dir/moonraker.asvc"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

if [[ -f "$moonraker_config" ]]; then
    grep -Fvx "$include_line" "$moonraker_config" > "$temporary" || true
    install -m 0644 "$temporary" "$moonraker_config"
fi
rm -f "$fragment"

if [[ -f "$allowed_services" ]]; then
    grep -Fvx "$service_name" "$allowed_services" > "$temporary" || true
    install -m 0644 "$temporary" "$allowed_services"
fi

sudo systemctl restart "$moonraker_service"
echo "PASS: PrinterHMI Remote removed from Moonraker Update Manager"
echo "Agent service and retained diagnostics state were not removed."
