# TLS transport foundation

This milestone implements the first real network protocol boundary without
enabling it in the production agent service. It exists for isolated desktop and
ARM testing before PrinterHMI Remote is allowed to make internet connections.

## Components

- `relay_transport.py` validates explicit relay configuration, creates a
  certificate-verifying TLS client, authenticates the device with its existing
  Ed25519 identity and sends one privacy-filtered telemetry snapshot.
- `relay_simulator.py` is a loopback-oriented TLS test relay. It issues a fresh
  short-lived challenge, verifies the agent signature and acknowledges one
  normalized telemetry envelope.
- `relay-session-v1.schema.json` defines every frame in the test session.
- `relay.example.json` is disabled by default and contains no public service
  endpoint.

The connector is not called by `printerhmi-agent run`. The installed systemd
unit remains `PrivateNetwork=true` and `RestrictAddressFamilies=AF_UNIX`.

## Authentication sequence

1. TLS verifies the configured CA and `server_name` before application data is
   accepted. TLS 1.2 is the minimum protocol version.
2. Inside the verified TLS channel, the agent sends its pseudonymous device ID.
   This lets a multi-device relay select the enrolled public key without
   exposing the identifier before TLS authentication.
3. The relay sends a fresh 256-bit nonce in a challenge addressed to that
   enrolled device ID and expiring within 120 seconds.
4. The agent verifies the configured relay ID, audience and timestamps, then
   signs the canonical challenge transcript using:
   `PrinterHMI Remote relay session authentication v1\0`.
5. The relay verifies the Ed25519 signature against the enrolled public key and
   confirms the exact session.
6. The agent sends one sequence-numbered, read-only snapshot and requires an
   acknowledgement for that session and sequence.

Every new TLS connection receives a new challenge. An authentication response
captured from another connection cannot match the newly issued session and
nonce.

## Privacy and resource limits

The foundation removes local Unix-socket paths, print filenames, Moonraker
messages and detailed local errors before serialization. Frames are limited to
256 KiB. The queue retains at most 1–64 snapshots and discards the oldest state
when full, favoring current telemetry over an unbounded backlog. Connection
timeouts and exponential retry delays are bounded.

## Isolated use

`printerhmi-relay-sim` requires an explicit certificate, key and expected
device ID. `printerhmi-agent relay-test` requires an explicit configuration and
snapshot file:

```bash
printerhmi-relay-sim \
  --cert server.pem --key server-key.pem \
  --device-id phm_example --host 127.0.0.1 --port 8443

printerhmi-agent relay-test \
  --config relay-test.json --snapshot status.json
```

These are development seams, not instructions for public exposure. Do not bind
the simulator to a public interface or enable a production relay configuration.

## Remaining release gates

Production integration still requires explicit operator enablement, durable
relay trust configuration, credential and tenant authorization, revocation
propagation, long-lived session sequencing, rate limiting, bounded reconnect
operation, privacy review and adversarial internet field testing.
