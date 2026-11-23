# passless on macOS (Firefox extension + native messaging host)

macOS has no UHID, and a virtual HID device or a Credential Provider Extension needs an Apple
developer account. So passless reaches the browser the way password-manager extensions
(KeePassXC-Browser, Bitwarden) do:

```text
page ── navigator.credentials.create/get ──▶ page.js (extension, page world, replaces them)
                                                 │ window.postMessage (same frame only)
                                                 ▼
                                             bridge.js (content script)
                                                 │ runtime.sendMessage: Firefox adds the frame URL
                                                 ▼
                                             background.js ── native messaging ──▶ passless
                                     passless: WebAuthn JSON → CTAP2 → AuthenticatorService → passage
```

Firefox starts `passless` with the host manifest path and the extension ID as arguments; passless
then serves Firefox over stdin/stdout until Firefox closes the port. Each request is translated
into the CTAP2 MakeCredential/GetAssertion a browser sends to a USB key and answered by the same
authenticator as on Linux: same storage backends, user-verification settings and one decrypt per
sign-in. The origin comes from Firefox (the URL of the frame that sent the request), never from
the page; passless builds `clientDataJSON` and checks the RP ID against it. Registration and
account-choice prompts are macOS dialogs (`osascript`); every decrypt also shows a notification
naming the entry (`Decrypting www/github.com/passkey`), because the Secure Enclave's Touch ID
sheet cannot say what it unlocks.

The host is browser-neutral (wire protocol in `cmd/passless/src/browser_host/mod.rs`); a Chromium
extension (via `chrome.webAuthenticationProxy`) could use it unchanged.

## Setup

1. Configuration. Firefox starts its native messaging host with the environment of the GUI
   session, not your shell's: no `PASSLESS_*` variables and a `PATH` without Nix profiles. Point
   the host manifest at a wrapper that sets both (below), and keep the settings in a file:

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

2. Host manifest `~/Library/Application Support/Mozilla/NativeMessagingHosts/rs.passless.browser.json`
   (Linux: `~/.mozilla/native-messaging-hosts/`):

   ```json
   {
     "name": "rs.passless.browser",
     "description": "passless",
     "path": "/absolute/path/to/passless-browser-host",
     "type": "stdio",
     "allowed_extensions": ["browser@passless.rs"]
   }
   ```

3. Extension (`cmd/passless/assets/firefox-extension/`, ID `browser@passless.rs`). Release
   Firefox installs only add-ons signed by Mozilla:
   - to try it: `about:debugging` → This Firefox → Load Temporary Add-on → `manifest.json`
     (gone after a restart);
   - to keep it: sign it as an unlisted add-on with a (free) Mozilla account,
     `web-ext sign --channel=unlisted --source-dir cmd/passless/assets/firefox-extension`
     (API key from addons.mozilla.org), and install the returned `.xpi`;
   - or use Firefox Developer Edition, Nightly or ESR with `xpinstall.signatures.required = false`.

### nix-darwin / home-manager

```nix
{ pkgs, ... }:
let
  passless = pkgs.callPackage ./passless.nix { }; # this repository
  host = pkgs.writeShellScript "passless-browser-host" ''
    export PATH=${pkgs.lib.makeBinPath [ pkgs.age pkgs.age-plugin-se ]}:/usr/bin:/bin
    export PASSLESS_CONFIG="$HOME/.config/passless/config.toml"
    exec ${passless}/bin/passless "$@"
  '';
in
{
  home-manager.users.me.home.file = {
    "Library/Application Support/Mozilla/NativeMessagingHosts/rs.passless.browser.json".text =
      builtins.toJSON {
        name = "rs.passless.browser";
        description = "passless";
        path = "${host}";
        type = "stdio";
        allowed_extensions = [ "browser@passless.rs" ];
      };
    ".config/passless/config.toml".source = ./passless.toml;
  };
  # The signed .xpi can be installed through Firefox policies, e.g. home-manager's
  # programs.firefox.policies.ExtensionSettings."browser@passless.rs" = {
  #   installation_mode = "force_installed"; install_url = "file://${./passless.xpi}"; };
}
```

## Behaviour and limits

- Sign-in: one decrypt of the site's passkey (one Touch ID with `age-plugin-se`), no other
  prompt with `user_verification_authentication = false`. A site with several passkeys and no
  `allowCredentials` decrypts each of them and asks which account to use.
- Registration: a dialog (nothing is decrypted, so there is nothing else to ask). A site where
  passkeys already exist decrypts them to check `excludeCredentials`.
- While the extension is enabled every `navigator.credentials` public-key request goes to
  passless; security keys are offered only when the host is not installed (then the page falls
  back to Firefox's own WebAuthn). On Linux, where the UHID key already works, the extension is
  not needed.
- Passkey autofill (conditional mediation) stays with Firefox; the extension reports it as
  unavailable, so sites show their "Sign in with a passkey" button.
- Requests from cross-origin iframes are refused; pages on `http://` work only for `localhost`.
- The page gets `PublicKeyCredential` objects built by the extension (as with Bitwarden): they
  pass `instanceof` and `toJSON()`, but are not native objects.
- Several Firefox windows share one host; several browsers each start their own and take turns
  on the store (instance lock per request).

## Tests

- `cargo test -p passless-rs browser_host notification` (protocol, translation, fake `age`).
- `tests/browser-e2e/run.sh`: headless Firefox through geckodriver with the extension as a
  temporary add-on, the host and a passage store with a plain age identity, against a local
  WebAuthn page.
