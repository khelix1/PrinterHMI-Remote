# Changelog

## [Unreleased]

### Added

- Added atomic, lock-protected relay configuration tooling that generates
  private local TLS material and a disabled loopback receiver configuration.
- Added signed-receipt-only device enrollment, pending-challenge binding,
  explicit enable/disable and confirmed allowlist removal commands.
- Added a disabled-by-default, loopback-only relay receiver with enrolled-key
  authentication, latest-snapshot storage and a private read-only Unix API.
- Kept every component in one package build while requiring separate explicit
  service activation for monitor, outbound-worker and receiver roles.
- Added a TLS-protected agent hello so a multi-device relay can select the
  enrolled public key before issuing a device-addressed session challenge.

- Added a separately installed outbound TLS relay worker that consumes only
  the private local API.
- Kept the Moonraker monitor permanently AF_UNIX-only and required explicit
  configuration plus `--enable-network` before installing remote transport.

- Established the standalone PrinterHMI Remote repository.
- Added read-only discovery of local Moonraker Unix sockets.
- Added stable per-instance identities and normalized catalog output.
- Added a minimal JSON-RPC Unix-socket client, protocol schema and tests.
- Documented architecture, security boundaries and the staged product roadmap.
- Enriched discovered instances with the hostname reported by `printer.info`.
- Added reusable deployment exclusions for generated development artifacts.
- Added dynamic, read-only Moonraker object subscriptions over the local Unix socket.
- Added normalized telemetry snapshots, reconnecting multi-instance service operation,
  atomic state-file publication and a hardened systemd user-service template.
- Coalesced high-frequency telemetry writes and retained humidity and temperature-fan
  fields from dynamically discovered sensor objects.
- Replaced the development user unit with a boot-persistent, least-privilege system
  service that runs as the Klipper account and requires only Unix-socket access.
- Added a versioned, same-user, read-only local Unix-socket API for agent health,
  catalog discovery, complete snapshots and individual instance state.
- Made service upgrades restart deterministically and verify the new API with an
  end-to-end request instead of trusting a possibly stale socket pathname.
- Added one-command operator diagnostics and mode-0600 support bundles with strict
  exclusion of raw telemetry, identities, network endpoints and print filenames.
- Added idempotent Moonraker Update Manager registration for pristine `main` checkouts,
  canonical-origin validation and least-privilege service restart authorization.
- Made Update Manager installation wait for Moonraker to validate the exact clean
  `main` revision over its local Unix socket before reporting success.
- Added the offline secure-enrollment foundation with Ed25519 device identity,
  expiring attempt-limited pairing, peer revocation, key rotation and audit events.
- Added a formal Phase 2 threat model and versioned pairing-offer schema while
  retaining the no-network service sandbox.
- Added domain-separated relay challenge signatures, peer proof-of-key ownership,
  signed enrollment receipts and persisted replay protection.
- Added versioned relay transcript schemas and offline CLI seams without enabling
  any TCP listener or outbound relay transport.
- Added a disabled-by-default TLS connector and loopback relay simulator with
  certificate and hostname verification plus signed Ed25519 session challenges.
- Added privacy-filtered telemetry envelopes, strict frame limits, bounded
  latest-state queuing and bounded reconnect delays while retaining the
  production service's private network namespace and AF_UNIX-only policy.
