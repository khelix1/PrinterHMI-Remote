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
| Device-selection confusion | Agent sends only its pseudonymous device ID after TLS server authentication; the relay must reject unknown IDs and select the enrolled public key before issuing a challenge |
| Agent impersonation | Agent signs a fresh, audience-bound challenge with its protected Ed25519 device key |
| Authentication replay | Each TLS connection receives a unique session UUID and 256-bit nonce with a maximum 120-second lifetime |
| Protocol confusion | Session authentication uses its own NUL-terminated domain separator and strict message shapes |
| Local-data disclosure | Serialization removes Unix-socket paths, detailed errors, print filenames and Moonraker messages |
| Memory exhaustion | Frames are capped at 256 KiB and the latest-state queue is bounded to at most 64 entries |
| Retry storm | Connection timeout is bounded and retry delay grows exponentially to a 30-second ceiling |
| Accidental production exposure | Example configuration is disabled; production service retains `PrivateNetwork=true` and `AF_UNIX` only |
| Unknown device ingestion | Receiver selects only configured device IDs and requires the session public key to exactly match the enrolled key |
| Receiver data accumulation | Registry atomically replaces one latest snapshot per device and keeps no history |
| Premature public exposure | Receiver foundation rejects non-loopback listener addresses and exposes its read API only through a same-user mode-0600 Unix socket |
| Manual key substitution | Configurator accepts only a device-signed receipt bound to the local relay peer key and a pending challenge; bare public keys are rejected |
| Configuration race or partial write | Mutations use an exclusive local lock, validate candidates and atomically replace mode-0600 configuration files |
| Accidental key overwrite | Initialization refuses non-empty directories and enablement requires a verified device plus explicit confirmation |

## Not yet claimed

- No production relay endpoint or globally trusted domain
- No multi-tenant account authorization or browser session
- No durable relay credential revocation propagation
- No continuous connection or resume protocol
- No notification delivery or offline retention contract
- No protection after host-account, root or physical compromise

The simulator must remain loopback-only. Passing this milestone does not
authorize removing the production systemd network sandbox.
