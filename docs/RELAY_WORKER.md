# Opt-in relay worker

The relay worker is the only PrinterHMI Remote process permitted to use IP
networking. It is not installed by `install.sh` or `install-service.sh` and the
example relay configuration remains disabled.

## Boundary

- The existing monitor reads Moonraker Unix sockets and retains
  `PrivateNetwork=true`.
- The worker reads normalized snapshots from the private same-user local API.
- The worker applies the transport privacy filter before sending.
- The worker authenticates TLS, the configured relay identity and the signed
  Ed25519 session challenge.
- No service opens an internet-facing listener.

## Installation

Create a private configuration from `config/relay.example.json`, set
`enabled` to `true`, and provide the absolute path to the trusted relay CA.
Then make the network authority explicit:

```bash
./install.sh
./install-relay-service.sh \
  --config /absolute/path/printerhmi-relay.json \
  --enable-network
```

Remove only the worker with:

```bash
./uninstall-relay-service.sh
```

The uninstaller retains configuration, identity and health state. This
milestone does not provide a public hosted relay, a domain, or operator-facing
remote access; it establishes the process boundary required for those later
components.
