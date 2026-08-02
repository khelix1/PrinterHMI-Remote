# Secure enrollment threat model

## Scope

This threat model covers the local Phase 2 enrollment foundation. The agent
still opens no network listener and makes no relay connection. Remote transport
remains disabled until its own review gate is complete.

## Assets

- The Ed25519 device private key and stable device identity
- One-time pairing codes and pending enrollment sessions
- Authorized peer public keys and revocation state
- Printer identity, normalized telemetry and future relay credentials
- Audit evidence needed to explain enrollment changes

## Trust boundaries

1. The Klipper host account owns the agent state directory.
2. An operator transfers a short pairing code to one intended client through an
   out-of-band path.
3. A paired client proves possession of its own Ed25519 private key.
4. Future relay traffic crosses the public internet only through outbound TLS.

Root and physical access to the Klipper host can recover agent secrets and are
outside the software-only protection boundary. A compromised Klipper account is
also trusted at this milestone because it owns Moonraker and the agent process.

## Threats and implemented mitigations

| Threat | Mitigation |
| --- | --- |
| Pairing-code guessing | Ten Crockford-style characters, five-attempt lockout, PBKDF2-HMAC-SHA256 verifier and generic rejection errors |
| Pairing-code replay | Successful codes are deleted atomically and cannot be reused |
| Stale pairing offer | Ten-minute default expiry; accepted range is 60–1800 seconds |
| Private-key disclosure | Mode-0700 directory, mode-0600 files, atomic writes and no private key in CLI or audit output |
| State races | Advisory process lock around identity, pairing, peer and audit mutations |
| Unauthorized peer persistence | Explicit peer inventory and revocation; device rotation clears every pairing and peer |
| Key substitution | Device ID derives from the Ed25519 public key; stored key, public key and ID are verified together |
| Audit leakage | Audit records contain event outcomes, public IDs and fingerprints but never codes or private keys |
| Network exposure | Service remains `PrivateNetwork=true` and `AF_UNIX`-only during Phase 2 |

## Deliberately unsupported

- No internet relay or browser dashboard
- No remote printer-control methods
- No inbound TCP listener or direct Moonraker exposure
- No unattended device-key recovery after loss or rotation
- No claim of protection after root, host-account or physical compromise

## Phase 3 release gates

Before enabling remote transport, the project must add authenticated challenge
exchange, TLS certificate validation, replay-resistant relay sessions,
multi-tenant authorization, credential revocation propagation, rate limiting,
bounded queues, privacy review and sustained adversarial field testing.
