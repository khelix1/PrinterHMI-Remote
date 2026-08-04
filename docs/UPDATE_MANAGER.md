# Moonraker Update Manager

PrinterHMI Remote uses Moonraker's official `git_repo` extension contract.
Register a clean installation on `main` with:

```bash
./install-update-manager.sh
```

The installer writes an included configuration fragment, authorizes only the
`printerhmi-remote` systemd service in `moonraker.asvc`, and restarts Moonraker.
It is idempotent and retains one backup of `moonraker.conf` before adding the
include. Installation returns successfully only after Moonraker reports a valid,
clean `main` checkout at the exact installed commit and canonical origin. The
readiness probe uses the selected instance's local Unix socket, not a fixed TCP
port.

If multiple Moonraker instances exist, select the primary instance explicitly:

```bash
./install-update-manager.sh \
  --moonraker-config "$HOME/printer_data/config/moonraker.conf" \
  --moonraker-service moonraker.service
```

## Update policy

The pre-alpha repository uses Moonraker's `dev` channel. Moonraker requires a
pristine Git checkout on a named branch and a matching configured origin. Stable
or beta channels additionally require semantic `vX.Y.Z` tags. The integration
should move to `stable` only after PrinterHMI Remote publishes its first reviewed
release tag.

Moonraker updates the repository and tracked Python requirements, then restarts
only `printerhmi-remote`. It does not regenerate new editable-install console
script wrappers on every Git update. Update-critical services and operator
workflows therefore dispatch through the original `printerhmi-agent` launcher,
which loads current source directly. Newly added convenience wrappers appear
after a full `./install.sh`, but are never required for a managed update.
Moonraker does not restart Klipper or expose Moonraker publicly.

Remove only the Update Manager registration with:

```bash
./uninstall-update-manager.sh
```
