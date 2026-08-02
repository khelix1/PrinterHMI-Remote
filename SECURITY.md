# Security policy

## Supported versions

PrinterHMI Remote is pre-alpha. No version is currently supported for production
internet exposure.

## Current security boundary

The foundation agent:

- opens no TCP listener;
- makes no cloud connection;
- sends no printer data off the host;
- reads Moonraker through explicitly discovered local Unix sockets;
- exposes no printer-control commands.

Do not expose Moonraker ports or development agent interfaces to the public internet.

## Future release gates

Internet relay work requires a reviewed threat model covering authentication,
enrollment, tenant isolation, secret storage, key rotation, revocation, replay
prevention, rate limiting, audit logging, update integrity and incident response.

## Reporting vulnerabilities

Report vulnerabilities privately through GitHub's private vulnerability reporting
feature. Do not include credentials or private printer data in public issues.
