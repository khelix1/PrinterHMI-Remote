# Roadmap

## Phase 0 — foundation

- Local Unix-socket discovery
- Stable instance identity
- Read-only JSON-RPC inspection
- Protocol schema and automated tests

## Phase 1 — local agent

- Long-running service and health model
- Zeroconf and multi-instance reconciliation
- Same-user authenticated local catalog and telemetry API
- Installer, systemd service and privacy-preserving diagnostics
- Moonraker Update Manager integration through a pristine Git checkout

## Phase 2 — secure enrollment

- Formal threat model
- Device key generation and protected storage
- Expiring one-time pairing codes
- Revocation, key rotation and audit events

## Phase 3 — remote monitoring

- Outbound TLS relay transport
- Multi-tenant isolation
- Read-only browser/PWA dashboard
- Printer state, temperatures, progress, ETA and notifications

## Phase 4 — ecosystem integration

- PrinterHMI P4 settings and agent catalog integration
- Self-hosted relay packaging
- KIAUH extension proposal

Remote control is not scheduled until monitoring has completed security review and
sustained field testing.
