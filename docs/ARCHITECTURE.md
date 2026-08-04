# Architecture

## Outbound relay process boundary

`printerhmi-remote.service` discovers Moonraker Unix sockets, normalizes
telemetry and serves the private same-user local API. It permanently retains
`PrivateNetwork=true` and `RestrictAddressFamilies=AF_UNIX`.

The optional `printerhmi-remote-relay.service` consumes only the local API and
owns outbound TLS. It reuses the authenticated, privacy-filtering relay
connector and writes only a small private health record. It never opens a
listener and never receives a Moonraker socket path.

The optional `printerhmi-relay-receiver.service` is a distinct runtime role
from the printer-side services but is built from the same repository and Python
package. At this foundation stage it binds TLS only on loopback, authenticates
an explicit device allowlist, retains one latest snapshot per device and serves
only a private same-user Unix API.

## Boundaries

PrinterHMI Remote has three future runtime boundaries:

1. **Agent** — runs beside Moonraker and owns printer discovery and telemetry.
2. **Relay** — accepts outbound authenticated agent connections and isolates tenants.
3. **Client** — browser, phone, or PrinterHMI P4 consuming normalized state.

The local agent, signed relay enrollment and isolated TLS transport harness now
exist. The production network relay and client remain future components.

## Local data flow

```text
Moonraker Unix socket -> Agent catalog -> normalized model -> local Unix API
```

The local API is a versioned request/response boundary for future relay and P4
consumers. It is available only through a mode-0600 Unix socket, verifies the
peer user with Linux credentials and exposes health, catalog and snapshot reads.

The Unix socket is preferred because it is local, supports Moonraker JSON-RPC,
and does not require copying an API key. Network discovery and manual endpoints
will be reconciled into the same catalog later.

## Ownership

- `discovery.py` owns candidate socket enumeration.
- `identity.py` owns stable local instance identity.
- `enrollment.py` owns device keys, one-time pairing, signed relay challenges, peer key proof, replay tracking, signed receipts, revocation and audit events.
- `relay_transport.py` owns TLS client validation, signed session authentication,
  TLS-protected device selection, privacy filtering, bounded queuing and retry
  policy.
- `relay_simulator.py` owns the loopback-only protocol test server.
- `relay_receiver.py` owns enrolled-device TLS ingestion and the private relay
  read API.
- `relay_registry.py` owns latest-snapshot-only relay state and atomic private
  persistence.
- `moonraker.py` owns JSON-RPC framing and transport.
- `catalog.py` owns normalized instance inspection.
- `model.py` owns consumer-facing data structures.
- `api.py` owns the same-user, read-only local consumer boundary.
- `diagnostics.py` owns redaction, health summaries and private support bundles.
- `packaging/moonraker/` owns the official Git-repository update contract.
- `protocol/` owns versioned cross-process schemas.
- `docs/RELAY_ENROLLMENT_PROTOCOL.md` owns canonical signing and transcript semantics.
- `docs/TLS_TRANSPORT_FOUNDATION.md` owns isolated transport behavior and gates.

The production `run` service does not instantiate the relay connector. Network
access cannot be enabled accidentally by placing a configuration file because
the systemd unit still creates a private network namespace and allows only
`AF_UNIX`.

The P4 firmware is not an internet gateway. It will be an optional local client of
the agent and will continue talking directly to Moonraker for operational control.
