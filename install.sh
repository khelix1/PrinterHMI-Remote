#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="$repo_dir/.venv"

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: Python 3 is required" >&2
    exit 1
}

python3 -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install --upgrade pip
"$venv_dir/bin/python" -m pip install --editable "$repo_dir"

echo "PASS: PrinterHMI Remote agent development environment installed"
echo "Run: $venv_dir/bin/printerhmi-agent discover --json"
