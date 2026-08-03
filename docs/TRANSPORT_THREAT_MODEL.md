# Outbound transport threat model

## Scope

This model covers the isolated TLS connector and loopback relay simulator. The
production service does not invoke the connector and still has no network
namespace or Internet address family access.

## Threats and current mitigations

| Threat | Mitigation |
| --- | --- |
| Relay server impersonation | Certificate-chain and hostname verification against an explicit CA file before protocol exchange |
| Relay identifier substitution | Signed session challenge relay ID must exactly match local configuration |
| Agent impersonation | Agent signs a fresh, audience-bound challenge with its protected Ed25519 device key |
| Authentication replay | Each TLS connection receives a unique session UUID and 256-bit nonce with a maximum 120-second lifetime |
| Protocol confusion | Session authentication uses its own NUL-terminated domain separator and strict message shapes |
| Local-data disclosure | Serialization removes Unix-socket paths, detailed errors, print filenames and Moonraker messages |
| Memory exhaustion | Frames are capped at 256 KiB and the latest-state queue is bounded to at most 64 entries |
| Retry storm | Connection timeout is bounded and retry delay grows exponentially to a 30-second ceiling |
| Accidental production exposure | Example configuration is disabled; production service retains `PrivateNetwork=true` and `AF_UNIX` only |

## Not yet claimed

- No production relay endpoint or globally trusted domain
- No multi-tenant account authorization or browser session
- No durable relay credential revocation propagation
- No continuous connection or resume protocol
- No notification delivery or offline retention contract
- No protection after host-account, root or physical compromise

The simulator must remain loopback-only. Passing this milestone does not
authorize removing the production systemd network sandbox.
