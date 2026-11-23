<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/pando85/passless/master/assets/logo.svg" alt="logo" width="200">
  <br>
  passless
  <br>
  <br>
</h1>

![Build status](https://img.shields.io/github/actions/workflow/status/pando85/passless/rust.yml?branch=master)
![passless license](https://img.shields.io/github/license/pando85/passless)

Passless is a software FIDO2 authenticator that emulates hardware security keys. Built with
[soft-fido2](https://github.com/pando85/soft-fido2), it runs as a virtual UHID device on Linux.

It also includes client capabilities for interacting with any FIDO2 authenticator. Experimental
agent mode can broker policy-controlled WebAuthn for explicitly configured local automation without
exposing credential private keys to the agent.

> [!IMPORTANT]
>
> **Client compatibility:** Sandboxed environments (Flatpak, Snap) and some Electron applications
> may not be able to communicate with the authenticator out of the box. The
> [Credentials for Linux](https://github.com/linux-credentials/credentialsd) project is developing
> a system credential service and browser integrations that may provide a portal-style path for
> confined applications. Current integrations are experimental and do not automatically enable
> arbitrary Electron, Flatpak, or Snap applications. See
> [docs/CLIENT_COMPATIBILITY.md](docs/CLIENT_COMPATIBILITY.md) for details on compatibility
> boundaries, troubleshooting, and credentialsd integration.

## ⚠️ Security Warning <!-- omit in toc -->

**Passless is a software FIDO2 authenticator and does not provide the same hardware-backed isolation
as dedicated security keys.** While Passless applies multiple hardening measures (GPG encryption,
memory protection, core dump prevention), credentials stored in software remain more exposed to
system-level compromise than non-exportable keys protected by secure hardware.

For many users, this trade-off is acceptable in exchange for better availability, usability, and
Linux-native integration. However, hardware FIDO2 authenticators offer stronger guarantees against
credential exfiltration and OS-level compromise, and remain the recommended option for high-value
accounts or stricter threat models.

Users should choose the solution that best fits their own security and practicality requirements.

- [Features](#features)
- [Agent authentication (experimental)](#agent-authentication-experimental)
- [Android](#android)
- [Configuration](#configuration)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)
  - [First-run setup](#first-run-setup)
- [Permissions and Hardening](#permissions-and-hardening)
- [Acknowledgements](#acknowledgements)

## Features

- FIDO2/WebAuthn authentication without hardware tokens
- Passkey support (resident credentials)
- User verification via desktop notifications or PIN
- PIN support with configurable enforcement policies
- Storage backends:
  - [pass](https://www.passwordstore.org/) (encrypted, git-synced)
  - [passage](https://github.com/FiloSottile/passage) (age-encrypted, git-synced)
  - TPM 2.0 (Experimental), including a [portable TPM backend](docs/TPM_PORTABLE.md)
    with TPM-resident non-exportable keys syncable across devices via a recovery seed
  - Local filesystem (testing only)
- Security hardening (memory locking, core dump prevention)
- Credential management via CTAP commands
- Encrypted credential [backup and restore](docs/CREDENTIAL_BACKUP.md) (software credentials)
- Change a credential's [credProtect level](docs/CRED_PROTECT.md), for example for SSH keys after `always_uv = false`

## Agent authentication (experimental)

> [!WARNING]
>
> Agent mode is implemented but **not yet validated for production use**. Interfaces,
> configuration fields, and behavior may change without notice.

Passless can broker WebAuthn authentication for explicitly configured local agents while keeping
credential private keys inside the Passless daemon and configured backend/key provider. The agent
receives a bounded authentication capability, not raw signing-key material.

Two identity modes are available:

- **`isolated`** — recommended for unattended automation. The agent has its own credential
  namespace and RP identity and cannot enumerate or sign with the human credential namespace.
- **`same-user`** — privileged delegation of the existing human WebAuthn identity. The daemon uses
  the human credential backend, so an autonomous profile can authenticate as the human within its
  configured RP and action policy.

For every intercepted ceremony, the daemon re-evaluates the browser-derived origin and RP,
credential scope, current policy generation, session bounds, operation budget, replay state, and
audit requirements before credential use.

This boundary controls **authentication authority**, not the actions available after login. Once a
WebAuthn ceremony succeeds, an agent controlling the managed browser can exercise whatever
application authority that authenticated RP session provides. Passless is therefore not an
application-level authorization proxy.

For unattended automation, prefer RP-native scoped mechanisms such as OAuth, application
installations, service accounts, or workload identity when they are available. Agent mode is most
useful when a workflow genuinely needs to authenticate through WebAuthn.

To let an agent sign in through Playwright MCP, follow the [agent quick start](docs/agents/quick-start.md).
See the [agent-mode overview](docs/agents/README.md) for configuration and threat-model guidance,
and read the [agent security model](docs/agents/security.md) before enabling autonomous
authentication.

## Android

[Password Store (Passkey Edition)](https://github.com/pando85/Android-Password-Store) is the
Android companion application for managing passkeys on mobile devices. It extends the well-known
[`pass`](https://www.passwordstore.org/) password manager with full FIDO2/WebAuthn credential
support.

### Credential Provider

Password Store registers as an Android Credential Manager provider, allowing supported applications
and browsers to request WebAuthn passkey operations directly from the device. This enables
passwordless authentication on Android using the same credentials managed by Passless on desktop.

### Interoperability

Passkeys created by Passless can be imported and used on Android, and passkeys created on Android
can be used by Passless on desktop. Both tools share the same encrypted CBOR credential format and
operate on the same `pass`-compatible directory structure, so credentials synchronize seamlessly
through the existing git-backed `pass` store.

### Installation

Password Store (Passkey Edition) is available from:

- [GitHub Releases](https://github.com/pando85/Android-Password-Store/releases)
- [F-Droid](https://f-droid.org/packages/app.passwordstore.pando85/)

## PIN Support

Passless supports optional PIN-based user verification. When a PIN is set, the authenticator
requires PIN verification for WebAuthn operations based on the configured enforcement policy.

### PIN Enforcement Policies

| Policy | `always_uv=false` | `always_uv=true` |
|--------|-------------------|------------------|
| `never` | Notification | Notification |
| `optional` | Notification | **PIN required** |
| `required` | **PIN required** | **PIN required** |

**Default:** `enforcement=optional`, `always_uv=true`

### Behavior Matrix

| PIN Set | `enforcement` | `always_uv` | User Verification Method |
|---------|---------------|-------------|--------------------------|
| No | any | any | Desktop notification |
| Yes | `never` | `false` | Desktop notification |
| Yes | `never` | `true` | Desktop notification |
| Yes | `optional` | `false` | Desktop notification |
| Yes | `optional` | `true` | PIN required |
| Yes | `required` | `false` | PIN required |
| Yes | `required` | `true` | PIN required |

For OpenSSH `-sk` keys and `always_uv`, see
[Client Compatibility](docs/CLIENT_COMPATIBILITY.md#openssh-security-keys--sk).

### Setting a PIN

```bash
# Set a new PIN
passless client pin set 1234

# Change existing PIN
passless client pin change 1234 5678
```

### Configuration

```toml
[pin]
# PIN enforcement policy: "never", "optional", "required"
enforcement = "optional"

# Minimum PIN length (4-63 characters)
min_length = 4

# Maximum PIN retry attempts before lockout
max_retries = 8

# Maximum user verification retry attempts before UV is blocked
# Use `passless client pin uv-reset` to restore after authentication
max_uv_retries = 8
```

Note: For enhanced security with hardware-backed protection, consider using the TPM backend
which seals credentials to the TPM hardware. The experimental
[portable TPM backend](docs/TPM_PORTABLE.md) goes further: signing keys are generated inside
the TPM and never exposed to host memory, and credential blobs can be synchronized across
multiple TPMs provisioned from the same recovery seed.

## Credential protection level

New credentials default to credProtect level 2 (UV optional with the credential ID list).
Credentials created by earlier versions, such as `ed25519-sk` SSH keys, can be stored with
level 3, which needs a PIN or UV for every use. To change the level of your own
credentials, authorized by your PIN or the verification prompt:

```bash
passless client set-cred-protect --rp ssh: --level 1   # lists the keys, asks, then lowers them
passless client set-cred-protect --id <CREDENTIAL_ID> --level 3
```

See [SSH keys and always_uv](docs/CRED_PROTECT.md#ssh-keys-and-always_uv) before lowering a
level: level 1 means user presence only for that key, which with
`security.user_verification_authentication = false` is silent signing for any process with hidraw
access, and lowering has no effect while `always_uv = true`.

## Configuration

Passless can be configured using a TOML configuration file. By default, the configuration file is
located at `~/.config/passless/config.toml`.

To generate a default configuration file:

```bash
mkdir -p ~/.config/passless
passless config print > ~/.config/passless/config.toml
```

You can then edit this file to customize the storage backend, security settings, and other options.
Command-line arguments will override settings from the configuration file.

### Password-store Git synchronization

By default, the `pass` backend pulls changes, creates local Git commits, and pushes those commits
when a remote is configured. To retain automatic pulls and local commits but **disable automatic
pushes**, configure:

```toml
[pass]
git_sync = true
git_auto_push = false
```

The default is `git_auto_push = true` when the setting is omitted, preserving existing behavior.
You can also use `--pass-git-auto-push=false` or `PASSLESS_PASS_GIT_AUTO_PUSH=false`.
With automatic pushes disabled, use `git -C ~/.password-store push` when you want to publish
local commits. Setting `git_sync = false` instead disables automatic pull and commit as well.

**Agent profiles use separate Git settings.** An isolated agent with a `pass` backend
uses `[agents.profiles.<id>.storage.pass]` with its own `git_sync` and
`git_auto_push` settings (both default to `true`); it does not inherit the global
`[pass]` values. For example:

```toml
[pass]
git_auto_push = false  # Human backend only

[agents.profiles.release-bot.storage.pass]
store_path = "/home/user/.password-store-agents"
path = "fido2"
pin_path = "pin"
git_auto_push = true  # This isolated agent still pushes
```

A `same-user` agent shares the human backend and follows `[pass]`. See
[agent storage configuration](docs/agents/configuration.md#same-user-and-isolated-storage) for details.
Because a Git push publishes all reachable commits, use **separate Git repositories**
for human and isolated-agent stores when you need strict push isolation.

### passage (age) backend

`backend_type = "passage"` keeps passkeys in a [passage](https://github.com/FiloSottile/passage)
store instead, encrypted by calling the `age` binary like passage does, so age plugins
(`age-plugin-se`, `age-plugin-yubikey`, ...) work unchanged.

A passkey sits in its site's folder next to the site's other entries:
`<path>/<rp-id>/passkey.age`, and `passkey-<first 8 hex chars of the credential ID>.age` for
further accounts of the same site. Only `passkey.age` and `passkey-*.age` are read; other entries
(`user.age`, `pass.age`, `otp.age`) are never decrypted or touched.

```toml
backend_type = "passage"

[passage]
# Defaults follow passage: $PASSAGE_DIR, $PASSAGE_IDENTITIES_FILE and $PASSAGE_AGE, else these.
store_path = "/home/user/.passage/store"
identities_file = "/home/user/.passage/identities"
age_binary = "age"
# Passkey root: www/github.com/passkey.age. Default "fido2"; "" puts site folders at the root.
path = "www"
```

Recipients follow passage: `$PASSAGE_RECIPIENTS_FILE`, else `$PASSAGE_RECIPIENTS`, else the
nearest `.age-recipients` up to the store root, else the identities file itself. `git_sync` and
`git_auto_push` work as for `[pass]`. Isolated agent profiles do not support passage storage yet.

With an age plugin that asks for its hardware on every decrypt (`age-plugin-tpm`,
`age-plugin-yubikey`), a sign-in costs one approval: the site's passkey. The decrypted passkey is
kept in memory only from the browser's silent pre-flight to its real request of the same sign-in,
and at most `cache_ttl` seconds (default 15, `PASSLESS_PASSAGE_CACHE_TTL`); after that it costs
another approval, never a failed sign-in. Passless keeps the host waiting with CTAPHID keepalives
meanwhile. Its PIN retry counters (not secret) are a plain
`<path>/pin_retries.local.json`, kept out of Git; the encrypted `pin_state.age` is written only
when PIN settings change and decrypted again only when the file changes. Each `age` run gets the
entry it reads or writes in `PASSLESS_AGE_TARGET` (e.g. `www/github.com/passkey`), so an `age`
wrapper's PIN prompt can name it; the data itself still goes through stdin.

### macOS and other systems without UHID (browser extension)

Where no virtual USB key can be created (macOS), passless serves Chromium-family browsers
(Chrome, Chromium, Brave, Edge, Vivaldi) directly: the extension in
`cmd/passless/assets/browser-extension/` takes over the browser's WebAuthn requests
(`chrome.webAuthenticationProxy`) and hands them to `passless`, which the browser starts as its
native messaging host `rs.passless.browser`. Same configuration, storage and prompts as the UHID
key; on macOS prompts are dialogs. Setup: [docs/MACOS.md](docs/MACOS.md).

### Headless automatic interaction

By default, Passless uses the desktop notification service when a WebAuthn operation needs local
user-presence or notification-based user-verification confirmation. A trusted headless deployment
can explicitly replace those confirmation prompts with automatic approval:

```bash
PASSLESS_INTERACTION_MODE=automatic passless
```

For a systemd service, set the same variable in the service environment, for example:

```ini
Environment=PASSLESS_INTERACTION_MODE=automatic
```

> [!WARNING]
>
> `automatic` deliberately removes the human confirmation boundary for WebAuthn prompts that would
> otherwise use desktop notifications. It can therefore satisfy user presence and notification-based
> user verification without a human gesture. Use it only when the host and all processes able to
> reach the authenticator are inside the intended trust boundary.

The default is `desktop`. An unknown `PASSLESS_INTERACTION_MODE` value is rejected rather than
falling back to automatic approval. Likewise, an unavailable or broken D-Bus notification service
never enables automatic approval implicitly.

This setting only changes WebAuthn UP/UV confirmation. General yes/no prompts used for storage
initialization or key selection remain interactive, and PIN policies that require PIN verification
are still evaluated before the notification fallback path is reached.

## Installation

### Cargo

Install from source with full system integration. See [DEVELOPMENT.md](DEVELOPMENT.md#prerequisites)
for required dependencies.

```bash
# Clone the repository
git clone https://github.com/pando85/passless.git
cd passless

# Install everything (binary, systemd service, udev rules, sysusers config)
make install

# Follow the post-install instructions to:
# 1. Add yourself to the fido group
# 2. Load the uhid kernel module
# 3. Log out and back in
# 4. Enable the systemd service
```

### Arch Linux

```bash
yay -S passless
```

or the binary from AUR:

```bash
yay -S passless-bin
```

### First-run setup

Both AUR packages (`passless` and `passless-bin`), as well as `make install`,
install the `fido` group definition, the `/dev/uhid` udev rule, the persistent
`uhid` module-loading configuration, and the `passless.service` **systemd user
unit**. You still need to grant your account access to the device and start the
service yourself.

```bash
# Grant your login user read/write access to /dev/uhid via the fido group.
sudo usermod -aG fido "$USER"

# Load the uhid module now (the packaged configuration loads it on future boots).
sudo modprobe uhid
```

**Log out and log back in** so the new group membership takes effect. Then
verify device access:

```bash
id -nG | grep -qw fido && echo "fido group OK"
test -r /dev/uhid && test -w /dev/uhid && echo "UHID access OK"
```

Before starting Passless, make sure your chosen storage backend is ready.
The default `pass` backend requires an initialized password store and an
available GPG key; see [Configuration](#configuration) and
[backend permissions](docs/PERMISSIONS.md#optional-backend-specific-access).

```bash
# Enable the authenticator for your user session and start it now.
systemctl --user enable --now passless.service

# Check startup errors if it does not stay running.
systemctl --user status passless.service
journalctl --user -u passless.service -n 50
```

Use `systemctl --user` without `sudo`: Passless runs as your regular user,
not as a system-wide root service. The user unit is optional if you prefer to
start `passless` manually. If device access checks fail, see the
[udev and group troubleshooting steps](docs/PERMISSIONS.md#permission-denied-on-devuhid).

## Permissions and Hardening

Passless runs as an unprivileged user and requires only regular-user read/write access to
`/dev/uhid`. Root is neither required nor recommended.

For detailed setup instructions, backend-specific permissions, hardened systemd service examples,
and troubleshooting, see [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

## Single-Instance Enforcement

Only one Passless daemon may own a given backend state directory at a time. Starting a second
daemon against the same backend fails immediately with a clear error. Multiple daemons are
supported only when each uses a different backend state path.

Client commands (`passless client ...`, `passless config print`) do not acquire the daemon lock
and work normally while the authenticator is running.

## Acknowledgements

A big thank you to the [PassKeeZ](https://github.com/Zig-Sec/PassKeeZ) project for being such a
great source of inspiration. Their work on a FIDO2 / Passkey-compatible Linux authenticator gave
this project both motivation and direction.
