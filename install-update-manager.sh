#!/usr/bin/env bash
set -euo pipefail

usage()
{
    cat <<'USAGE'
Usage: ./install-update-manager.sh [--moonraker-config PATH] [--moonraker-service NAME]

Registers this pristine Git checkout with Moonraker Update Manager.
When multiple Moonraker configurations exist, --moonraker-config is required.
USAGE
}

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
moonraker_config="${PRINTERHMI_MOONRAKER_CONFIG:-}"
moonraker_service="${PRINTERHMI_MOONRAKER_SERVICE:-moonraker.service}"
service_name="printerhmi-remote"
include_name="printerhmi-remote-update.conf"
include_line="[include $include_name]"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --moonraker-config)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            moonraker_config="$2"
            shift 2
            ;;
        --moonraker-service)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            moonraker_service="$2"
            shift 2
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

for command_name in cut find getent git grep install mktemp sed sleep sort sudo systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $command_name" >&2
        exit 1
    }
done

[[ -d "$repo_dir/.git" ]] || {
    echo "ERROR: Update Manager requires a Git checkout: $repo_dir" >&2
    exit 1
}

[[ "$(git -C "$repo_dir" branch --show-current)" == "main" ]] || {
    echo "ERROR: switch PrinterHMI Remote to its main branch first" >&2
    exit 1
}

[[ -z "$(git -C "$repo_dir" status --porcelain)" ]] || {
    echo "ERROR: Update Manager requires a pristine PrinterHMI Remote checkout" >&2
    git -C "$repo_dir" status --short >&2
    exit 1
}

origin="$(git -C "$repo_dir" remote get-url origin 2>/dev/null || true)"
case "$origin" in
    https://github.com/khelix1/PrinterHMI-Remote.git|git@github.com:khelix1/PrinterHMI-Remote.git)
        ;;
    *)
        echo "ERROR: unexpected origin; refusing Update Manager registration" >&2
        echo "origin: $origin" >&2
        exit 1
        ;;
esac

service_user="${PRINTERHMI_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
home_dir="$(getent passwd "$service_user" | cut -d: -f6)"
[[ -n "$home_dir" ]] || {
    echo "ERROR: unable to resolve home directory for $service_user" >&2
    exit 1
}

if [[ -z "$moonraker_config" ]]; then
    mapfile -t candidates < <(
        find "$home_dir" -maxdepth 5 -type f \
            -path '*/config/moonraker.conf' -print 2>/dev/null | sort
    )
    if [[ ${#candidates[@]} -eq 0 ]]; then
        echo "ERROR: no Moonraker configuration found" >&2
        echo "Use --moonraker-config PATH for a custom installation." >&2
        exit 1
    fi
    if [[ ${#candidates[@]} -ne 1 ]]; then
        echo "ERROR: multiple Moonraker configurations found" >&2
        printf '  %s\n' "${candidates[@]}" >&2
        echo "Choose the primary instance with --moonraker-config PATH." >&2
        exit 1
    fi
    moonraker_config="${candidates[0]}"
fi

[[ -f "$moonraker_config" ]] || {
    echo "ERROR: Moonraker configuration not found: $moonraker_config" >&2
    exit 1
}

config_dir="$(cd "$(dirname "$moonraker_config")" && pwd)"
data_dir="$(cd "$config_dir/.." && pwd)"
fragment="$config_dir/$include_name"
allowed_services="$data_dir/moonraker.asvc"
template="$repo_dir/packaging/moonraker/printerhmi-remote-update.conf.in"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

sed \
    -e "s|@REPO_DIR@|$repo_dir|g" \
    -e "s|@VIRTUALENV@|$repo_dir/.venv|g" \
    "$template" > "$temporary"

install -m 0644 "$temporary" "$fragment"

backup="$moonraker_config.printerhmi-remote.bak"
if ! grep -Fxq "$include_line" "$moonraker_config"; then
    [[ -e "$backup" ]] || install -m 0644 "$moonraker_config" "$backup"
    printf '\n%s\n' "$include_line" >> "$moonraker_config"
fi

if [[ ! -e "$allowed_services" ]]; then
    : > "$allowed_services"
fi
if ! grep -Fxq "$service_name" "$allowed_services"; then
    printf '%s\n' "$service_name" >> "$allowed_services"
fi

sudo systemctl restart "$moonraker_service"
for _attempt in {1..40}; do
    if sudo systemctl is-active --quiet "$moonraker_service"; then
        break
    fi
    sleep 0.25
done
sudo systemctl is-active --quiet "$moonraker_service" || {
    echo "ERROR: Moonraker did not restart after registration" >&2
    sudo systemctl status "$moonraker_service" --no-pager -l >&2 || true
    exit 1
}

echo "PASS: PrinterHMI Remote registered with Moonraker Update Manager"
echo "Configuration: $fragment"
echo "Allowed service: $service_name"
echo "Channel: dev"
echo "Moonraker service: $moonraker_service"
