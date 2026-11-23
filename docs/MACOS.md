# passless on macOS (browser extension + native messaging host)

macOS has no UHID, and a virtual HID device or a Credential Provider Extension needs an Apple
developer account. So passless reaches the browser the way password-manager extensions do:

```text
page ── navigator.credentials ──▶ Chromium ── webAuthenticationProxy ──▶ extension (worker.js)
                                                                            │ native messaging
                                                                            ▼
                                       passless (started by the browser, stdin/stdout)
                                       WebAuthn JSON → CTAP2 → AuthenticatorService → passage
```

The browser starts `passless` with the extension's origin as its only argument; passless then
serves that browser until it closes the port. Each request is translated into the CTAP2
MakeCredential/GetAssertion a browser sends to a USB key and answered by the same authenticator
as on Linux: same storage backends, user-verification settings, PIN-less sign-in and one decrypt
per sign-in. Registration and sign-in prompts are macOS dialogs (`osascript`); every decrypt also
shows a notification that names the entry (`Decrypting www/github.com/passkey`), because the
Secure Enclave's Touch ID sheet cannot say what it unlocks.

Supported browsers: Chromium family (Chrome, Chromium, Brave, Edge, Vivaldi), version 116 or
newer. Firefox has no `webAuthenticationProxy`.

## Setup

1. Configuration. A browser starts its native messaging host with the login environment of the
   GUI session, not your shell's: no `PASSLESS_*` variables and a `PATH` without Nix profiles.
   Point the host manifest at a wrapper that sets both (below), and keep the settings in a file:

   ```toml
   backend_type = "passage"

   [passage]
   store_path = "/Users/me/.passage/store"
   identities_file = "/Users/me/.passage/identities"   # AGE-PLUGIN-SE-1... identity
   path = "www"
   age_binary = "/run/current-system/sw/bin/age"

   [security]
   # The Secure Enclave decrypt (Touch ID) verifies the user at sign-in: no extra dialog.
   user_verification_authentication = false
   ```

2. Host manifest `rs.passless.browser.json` in the browser's `NativeMessagingHosts` directory:
   - Chrome: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
   - Chromium: `~/Library/Application Support/Chromium/NativeMessagingHosts/`
   - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/`
   - Edge: `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/`

   ```json
   {
     "name": "rs.passless.browser",
     "description": "passless",
     "path": "/absolute/path/to/passless-browser-host",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://adlnfbjbndianbljppelgaecanjmpppo/"]
   }
   ```

3. Extension: `chrome://extensions`, Developer mode, "Load unpacked",
   `cmd/passless/assets/browser-extension/`. Its ID is fixed by the manifest `key`
   (`adlnfbjbndianbljppelgaecanjmpppo`), matching `allowed_origins`.

### nix-darwin

```nix
{ pkgs, ... }:
let
  passless = pkgs.callPackage ./passless.nix { }; # this repository
  host = pkgs.writeShellScript "passless-browser-host" ''
    export PATH=${pkgs.lib.makeBinPath [ pkgs.age pkgs.age-plugin-se ]}:/usr/bin:/bin
    export PASSLESS_CONFIG="$HOME/.config/passless/config.toml"
    exec ${passless}/bin/passless "$@"
  '';
  manifest = builtins.toJSON {
    name = "rs.passless.browser";
    description = "passless";
    path = "${host}";
    type = "stdio";
    allowed_origins = [ "chrome-extension://adlnfbjbndianbljppelgaecanjmpppo/" ];
  };
in
{
  home-manager.users.me.home.file = {
    "Library/Application Support/Google/Chrome/NativeMessagingHosts/rs.passless.browser.json".text = manifest;
    "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/rs.passless.browser.json".text = manifest;
    ".config/passless/config.toml".source = ./passless.toml;
  };
}
```

## Behaviour and limits

- Sign-in: one decrypt of the site's passkey (one Touch ID with `age-plugin-se`), no other
  prompt with `user_verification_authentication = false`. A site with several passkeys and no
  `allowCredentials` decrypts each of them and asks which account to use.
- Registration: a dialog (nothing is decrypted, so there is nothing else to ask). A site where
  passkeys already exist decrypts them once per browser session to check `excludeCredentials`.
- While the extension is enabled, every WebAuthn request of the browser profile goes to passless:
  security keys and iCloud Keychain passkeys are not offered. Disable the extension to use them.
- Passkey autofill (conditional mediation) is not available through the proxy; sites fall back to
  their "Sign in with a passkey" button.
- Requests from cross-origin iframes are refused.
- Several browsers each start their own host; they take turns on the store (instance lock per
  request).

## Tests

- `cargo test -p passless-rs browser_host notification` (protocol, translation, fake `age`).
- `tests/browser-e2e/run.sh`: headless Chromium, the extension, the host and a passage store with
  a plain age identity, against a local WebAuthn page.
