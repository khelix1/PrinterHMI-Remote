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

- [x] Formal threat model
- [x] Ed25519 device key generation and protected local storage
- [x] Expiring, attempt-limited one-time pairing codes
- [x] Peer revocation, destructive key rotation and secret-free audit events
- [x] Domain-separated relay challenges, peer key proof and signed receipts
- [x] Persisted challenge replay prevention and versioned transcript schemas
- [ ] End-to-end enrollment over a reviewed network relay

## Phase 3 — remote monitoring

- [x] Disabled-by-default TLS connector and loopback relay simulator
- [x] Certificate/hostname validation and signed session authentication
- [x] TLS-protected device selection before addressed session challenges
- [x] Privacy-filtered envelopes, bounded queue and bounded retry policy
- [x] Separate opt-in relay service with explicit operator enablement
- [x] Loopback relay receiver with enrolled-key authentication and latest state
- [x] Private TLS/config generation and signed-receipt allowlist tooling
- [x] Disposable production-shaped loopback integration gate
- [ ] Field-test the worker against a production relay
- [ ] Multi-tenant isolation
- [ ] Read-only browser/PWA dashboard
- [ ] Printer state, temperatures, progress, ETA and notifications

## Phase 4 — ecosystem integration

- PrinterHMI P4 settings and agent catalog integration
- Self-hosted relay packaging
- KIAUH extension proposal

Remote control is not scheduled until monitoring has completed security review and
sustained field testing.
