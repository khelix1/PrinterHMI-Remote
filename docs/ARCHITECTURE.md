# Architecture

## Boundaries

PrinterHMI Remote has three future runtime boundaries:

1. **Agent** — runs beside Moonraker and owns printer discovery and telemetry.
2. **Relay** — accepts outbound authenticated agent connections and isolates tenants.
3. **Client** — browser, phone, or PrinterHMI P4 consuming normalized state.

Only the agent exists in the foundation milestone.

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
- `moonraker.py` owns JSON-RPC framing and transport.
- `catalog.py` owns normalized instance inspection.
- `model.py` owns consumer-facing data structures.
- `api.py` owns the same-user, read-only local consumer boundary.
- `diagnostics.py` owns redaction, health summaries and private support bundles.
- `protocol/` owns versioned cross-process schemas.

The P4 firmware is not an internet gateway. It will be an optional local client of
the agent and will continue talking directly to Moonraker for operational control.
