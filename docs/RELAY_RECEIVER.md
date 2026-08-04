# Loopback relay receiver foundation

The receiver proves the authenticated agent-to-relay boundary without creating
a public service. It is built and installed with the rest of the repository by
`./install.sh`, but it is not started by any printer-host installer.

## Boundaries

- The TLS listener is restricted to a loopback IP.
- The configuration must explicitly enable the receiver.
- Every accepted device ID must map to its enrolled Ed25519 public key.
- Unknown IDs and mismatched keys are rejected before telemetry is accepted.
- Incoming telemetry must already satisfy the agent privacy filter.
- Only the latest snapshot per enrolled device is retained; there is no history.
- The read API is a same-user, mode-0600 Unix socket.
- There are no accounts, browser sessions, printer controls or public endpoints.

## Role-specific installation

Copy `config/relay-receiver.example.json` outside the repository, provide a
private TLS certificate and key, add real enrolled devices and set `enabled` to
`true`. The listener remains loopback-only at this milestone.

```bash
./install.sh
./install-relay-receiver-service.sh \
  --config /absolute/path/relay-receiver.json \
  --enable-listener
```

Inspect its private API on the receiver host:

```bash
.venv/bin/printerhmi-relay-receiver \
  --config /absolute/path/relay-receiver.json \
  --api health
```

Remove only the receiver service with
`./uninstall-relay-receiver-service.sh`. Configuration, certificates,
enrollments and latest state are retained.

Allowing a LAN or internet bind remains a later reviewed milestone requiring
tenant authorization, public TLS deployment, rate limiting and adversarial
field testing.
