# Relay enrollment protocol v1

This milestone defines and tests the cryptographic enrollment transcript without
opening a network connection. The production service remains local-only,
`PrivateNetwork=true`, and restricted to Unix sockets.

## Exchange

1. The operator asks the local agent for an expiring, attempt-limited pairing
   offer and transfers its code to the intended client.
2. The relay creates a fresh `relay.challenge` addressed to the agent's stable
   device ID. A challenge contains a 256-bit nonce, relay ID, issue time and
   expiry no more than 300 seconds later.
3. The agent signs the complete challenge. The client signs a domain-separated
   enrollment proof binding its public key to the pairing ID, peer ID, device
   ID, challenge ID, relay ID and nonce.
4. The agent validates the challenge, one-time code and peer proof atomically,
   records the peer and used challenge, then signs an enrollment receipt.

A successful challenge ID cannot complete enrollment twice. An invalid peer
proof does not consume the one-time pairing offer.

## Canonical signatures

Signed JSON uses UTF-8, lexicographically sorted keys, compact separators and
ASCII escaping. The signature field itself is omitted before canonicalization.
Each message is prefixed with one exact domain separator, including its final
NUL byte:

- `PrinterHMI Remote relay challenge response v1\0`
- `PrinterHMI Remote peer enrollment proof v1\0`
- `PrinterHMI Remote enrollment receipt v1\0`

Ed25519 public keys, signatures and nonces use unpadded URL-safe Base64.

## Offline CLI seam

The relay transport can later pass JSON through these stable commands:

```bash
printerhmi-agent enrollment challenge-sign --request challenge.json
printerhmi-agent enrollment relay-complete --request enrollment-request.json
```

Use `--request -` for standard input. These commands do not connect to a relay.
They provide a field-testable seam while TLS endpoint identity, authorization
and session behavior remain behind the Phase 3 release gate.

## Privacy and trust

Pairing codes and private keys never appear in signed responses, receipts or
audit records. At this offline milestone, possession of the short pairing code
authorizes the intended peer. A future relay endpoint is not trusted merely
because it chose a `relay_id`; TLS and configured relay trust must bind that
identifier before internet transport is enabled.

Schemas are published in `protocol/relay-challenge-v1.schema.json` and
`protocol/relay-enrollment-v1.schema.json`.
