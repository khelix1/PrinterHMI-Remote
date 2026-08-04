# Relay configuration and enrollment

`printerhmi-agent relay-config` creates the loopback receiver's complete private
configuration without requiring operators to edit JSON or copy public keys by
hand. Its stable launcher is installed by the repository's normal `./install.sh`
command and remains valid across Moonraker source updates.

The tool never installs or starts a service. New configurations are disabled,
restricted to loopback and contain no enrolled devices.

## Initialize the receiver host

Choose a new empty directory owned by the receiver service account:

```bash
.venv/bin/printerhmi-agent relay-config init \
  --directory "$HOME/.config/printerhmi-relay" \
  --relay-id my-relay
```

Initialization creates:

- a private relay enrollment key;
- private 3072-bit RSA CA and TLS server keys;
- a local CA and a 397-day localhost server certificate;
- a mode-0600 disabled receiver configuration;
- an empty device allowlist.

Private files and the directory use modes `0600` and `0700`. Existing non-empty
directories are never overwritten. The private CA key is retained only for a
future certificate-renewal workflow and must never be copied to an agent host.

## Enroll one printer host

On the printer host, create a short-lived pairing offer and save its JSON:

```bash
.venv/bin/printerhmi-agent enrollment pair-create --json \
  > pairing-offer.json
```

Transfer that file directly to the intended receiver host. Treat it as a
temporary secret because it contains the one-time code. On the receiver host,
create the signed enrollment request:

```bash
.venv/bin/printerhmi-agent relay-config request \
  --directory "$HOME/.config/printerhmi-relay" \
  --offer pairing-offer.json \
  --output enrollment-request.json
```

Transfer the request back to the same printer host and complete it with the
protected device identity:

```bash
.venv/bin/printerhmi-agent enrollment relay-complete \
  --request enrollment-request.json \
  > enrollment-receipt.json
```

Transfer only the receipt to the receiver and import it:

```bash
.venv/bin/printerhmi-agent relay-config add-receipt \
  --directory "$HOME/.config/printerhmi-relay" \
  --receipt enrollment-receipt.json
```

The configurator verifies the device signature, relay ID, local relay peer key
and pending challenge before changing the allowlist. Arbitrary identity files
and bare public keys are not accepted. Delete the temporary offer and request
after successful enrollment.

Repeat the pairing exchange for each printer host. Inspect the public status at
any time without disclosing private keys:

```bash
.venv/bin/printerhmi-agent relay-config status \
  --directory "$HOME/.config/printerhmi-relay"
```

## Explicit enablement

Enabling requires at least one verified receipt and an explicit confirmation:

```bash
.venv/bin/printerhmi-agent relay-config enable \
  --directory "$HOME/.config/printerhmi-relay" \
  --confirm
```

This changes only the configuration. It still does not install or start the
receiver service. The role-specific installer remains a separate action:

```bash
./install-relay-receiver-service.sh \
  --config "$HOME/.config/printerhmi-relay/relay-receiver.json" \
  --enable-listener
```

At this milestone the generated listener is always `127.0.0.1`; it is not a
LAN or Internet relay. Disable before removing the final enrolled device.
