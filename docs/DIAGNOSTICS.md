# Diagnostics

Run one command from the installed repository:

```bash
.venv/bin/printerhmi-agent diagnose
```

The command reports service state, local API readiness, discovered and connected
printer counts, and the number of sanitized recent errors. It also writes a
mode-`0600` ZIP support bundle in the current directory.

Use `--json --no-bundle` for machine-readable output without creating a file,
or `--output PATH` to choose the bundle destination.

## Privacy boundary

Bundles contain only `diagnostics.json` and a disclosure note. They exclude raw
telemetry, hostnames, stable instance identifiers, Unix-socket paths, IP addresses,
URLs, print filenames and credential-like values. Inspect a bundle before sharing
it whenever local policy requires human review.
