# Security policy

## Supported versions

PrinterHMI Remote is pre-alpha. No version is currently supported for production
internet exposure.

## Current security boundary

The foundation agent:

- opens no TCP listener;
- stores its Ed25519 device identity and enrollment state under mode-0600 files;
- limits one-time pairing offers by expiry and failed-attempt count;
- authenticates offline relay transcripts with domain-separated Ed25519 signatures;
- persists consumed challenge IDs so successful enrollment cannot be replayed;
- includes a disabled-by-default TLS test connector with CA and hostname
  verification, signed session authentication and privacy-filtered payloads;
- makes no cloud connection;
- sends no printer data off the host;
- reads Moonraker through explicitly discovered local Unix sockets;
- exposes no printer-control commands;
- serves local state only through a mode-0600 Unix socket with same-user peer checks;
- accepts managed updates only from the configured canonical GitHub origin and only
  when Moonraker validates a pristine checkout on `main`.

Do not expose Moonraker ports or development agent interfaces to the public internet.
Do not bind `printerhmi-relay-sim` to a public interface. The simulator and
connector are test harnesses and are not a hosted relay service.

## Future release gates

The local enrollment threat model is documented in `docs/THREAT_MODEL.md`.
Internet relay work additionally requires review covering authentication,
enrollment, tenant isolation, secret storage, key rotation, revocation, replay
prevention, rate limiting, audit logging, update integrity and incident response.

## Reporting vulnerabilities

Report vulnerabilities privately through GitHub's private vulnerability reporting
feature. Do not include credentials or private printer data in public issues.
