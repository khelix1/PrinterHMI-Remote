# Contributing

PrinterHMI Remote is local-first and security-sensitive.

Before submitting a change:

```bash
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v
git diff --check
```

Changes that add a listener, cloud connection, credential, remote command, installer
privilege, telemetry collection or automatic update must include corresponding threat
analysis and tests. Printer-control behavior is outside the initial project scope.
