# End-to-end relay integration gate

The integration gate exercises the production-shaped read-only data path while
remaining completely disposable and loopback-only:

1. generate private receiver TLS and enrollment identities;
2. enroll two disposable agents through signed challenge and receipt files;
3. start the same-user local agent API and authenticated TLS receiver;
4. send changing snapshots through the real outbound worker;
5. verify latest-state replacement, per-device isolation and privacy filtering;
6. stop the receiver, observe a bounded worker failure, restart and reconnect;
7. verify stale-state reporting and absence of receiver control methods.

Run the complete gate with the update-stable launcher:

```bash
.venv/bin/printerhmi-agent relay-integration --json
```

The default workspace is a temporary directory and is removed afterward. To
retain artifacts for inspection, provide a new or empty disposable directory:

```bash
.venv/bin/printerhmi-agent relay-integration \
  --workspace /tmp/printerhmi-relay-field-test \
  --json
```

The command refuses the production PrinterHMI Remote state directory and any
non-empty workspace. It never invokes systemd, opens a public listener, reads a
Moonraker socket or changes the permanent production enrollment identity.

`--skip-stale-wait` exists only for the automated test suite. Field validation
must use the default real stale-state delay.
