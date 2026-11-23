//! The host as a browser drives it: frames in, frames out, served by the real authenticator
//! on a passage store whose `age` is a stand-in that counts decrypts.

use super::*;

use crate::human_prompts::HumanPrompts;
use crate::notification::NotificationResult;
use crate::storage::pass::age::{AgeCrypto, decrypt_count, install_counting_fake_age};
use crate::storage::pass::{PassStorageAdapter, StoreCrypto};

use passless_core::config::{PinConfig, SecurityConfig};

use std::io::{PipeReader, PipeWriter};
use std::path::PathBuf;
use std::thread::JoinHandle;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

const ORIGIN: &str = "https://login.example.com";
const RP_ID: &str = "example.com";

struct Store {
    dir: tempfile::TempDir,
}

impl Store {
    fn new() -> Self {
        let store = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::write(store.identities(), "fake").unwrap();
        std::fs::create_dir_all(store.root()).unwrap();
        install_counting_fake_age(&store.age(), &store.log());
        store
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("store")
    }
    fn identities(&self) -> PathBuf {
        self.dir.path().join("identities")
    }
    fn age(&self) -> PathBuf {
        self.dir.path().join("age")
    }
    fn log(&self) -> PathBuf {
        self.dir.path().join("decrypts")
    }

    fn decrypts(&self) -> usize {
        decrypt_count(&self.log())
    }

    fn backend(&self) -> BackendConfig {
        BackendConfig::Passage {
            store_path: self.root().display().to_string(),
            path: "www".into(),
            identities_file: self.identities().display().to_string(),
            age_binary: self.age().display().to_string(),
            cache_ttl: 15,
        }
    }

    fn passkeys(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.root().join("www").join(RP_ID))
            .map(|dir| dir.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        files.sort();
        files
    }
}

/// The browser side of one native messaging connection.
struct Browser {
    to_host: PipeWriter,
    from_host: PipeReader,
    host: JoinHandle<usize>,
    next_id: u64,
}

/// Approves every prompt and counts them.
struct CountingPrompts(Arc<Mutex<usize>>);

impl CountingPrompts {
    fn approve(&mut self) -> std::result::Result<NotificationResult, String> {
        *lock(&self.0) += 1;
        Ok(NotificationResult::Accepted)
    }
}

impl HumanPrompts for CountingPrompts {
    fn user_presence(
        &mut self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: u32,
    ) -> std::result::Result<NotificationResult, String> {
        self.approve()
    }

    fn user_verification(
        &mut self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: u32,
    ) -> std::result::Result<NotificationResult, String> {
        self.approve()
    }

    fn confirm_credential_protection_lowering(
        &mut self,
        _: &str,
        _: &str,
        _: u32,
    ) -> std::result::Result<NotificationResult, String> {
        self.approve()
    }

    fn interaction_is_automatic(&self) -> std::result::Result<bool, String> {
        Ok(false)
    }
}

impl Browser {
    /// Start a host on `store`. A sign-in asks for no UV prompt (the decrypt is the check, as
    /// with `user_verification_authentication = false` on the Mac); several accounts are
    /// resolved by picking the account named `choice` (none: the user declines).
    fn start(store: &Store, choice: Option<&'static str>) -> Self {
        let (input, to_host) = io::pipe().unwrap();
        let (from_host, output) = io::pipe().unwrap();
        let backend = store.backend();
        let (root, identities, age) = (store.root(), store.identities(), store.age());
        let host = thread::spawn(move || {
            let prompts = Arc::new(Mutex::new(0));
            let storage = PassStorageAdapter::new_with_options(
                root,
                "www".into(),
                StoreCrypto::Age(AgeCrypto::new(age, identities)),
                false,
            )
            .unwrap();
            let service = AuthenticatorService::<_, (), _>::with_shared_storage(
                Arc::new(Mutex::new(storage)),
                None,
                SecurityConfig {
                    user_verification_authentication: false,
                    ..Default::default()
                },
                PinConfig::default(),
            )
            .unwrap();
            service.set_prompts(CountingPrompts(prompts.clone()));
            serve_frames(
                input,
                output,
                ctap_service(backend, service),
                move |rp_id: &str, accounts: &[String]| {
                    assert_eq!(rp_id, RP_ID);
                    assert!(accounts.len() > 1);
                    Ok(choice.and_then(|name| accounts.iter().position(|account| account == name)))
                },
            );
            *lock(&prompts)
        });
        Self {
            to_host,
            from_host,
            host,
            next_id: 1,
        }
    }

    fn send(&mut self, frame: Value) {
        write_frame(&mut self.to_host, &frame).unwrap();
    }

    fn receive(&mut self) -> Value {
        read_frame(&mut self.from_host).unwrap().expect("a result")
    }

    /// Send a WebAuthn request and return its result frame.
    fn request(&mut self, op: &str, origin: &str, details: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({
            "type": "request", "id": id, "op": op, "origin": origin,
            "cross_origin": false, "body": details.to_string(),
        }));
        let result = self.receive();
        assert_eq!(result["id"], id);
        result
    }

    /// The `responseJson` of a successful request.
    fn ok(&mut self, op: &str, details: Value) -> Value {
        let result = self.request(op, ORIGIN, details);
        assert_eq!(result["ok"], true, "{result}");
        serde_json::from_str(result["body"].as_str().unwrap()).unwrap()
    }

    /// Close the port; returns the number of prompts the host raised.
    fn close(self) -> usize {
        drop(self.to_host);
        self.host.join().unwrap()
    }
}

fn b64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

fn registration(user: &str) -> Value {
    json!({
        "rp": {"id": RP_ID, "name": "Example"},
        "user": {"id": URL_SAFE_NO_PAD.encode(user), "name": user, "displayName": user},
        "challenge": "cmVnaXN0ZXI",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"residentKey": "required", "userVerification": "preferred"},
        "attestation": "none",
        "extensions": {"credProps": true},
    })
}

fn sign_in(allow: &[&Value]) -> Value {
    json!({
        "rpId": RP_ID,
        "challenge": "c2lnbi1pbg",
        "allowCredentials": allow.iter().map(|id| json!({"type": "public-key", "id": id})).collect::<Vec<_>>(),
        "userVerification": "preferred",
    })
}

/// The assertion verifies with the registered key, over the clientDataJSON the host built.
fn verify(credential: &Value, assertion: &Value) {
    let key =
        VerifyingKey::from_public_key_der(&b64(&credential["response"]["publicKey"])).unwrap();
    let client_data = b64(&assertion["response"]["clientDataJSON"]);
    let client: Value = serde_json::from_slice(&client_data).unwrap();
    assert_eq!(client["type"], "webauthn.get");
    assert_eq!(client["origin"], ORIGIN);
    assert_eq!(client["challenge"], "c2lnbi1pbg");
    let mut signed = b64(&assertion["response"]["authenticatorData"]);
    assert_eq!(&signed[..32], Sha256::digest(RP_ID).as_slice());
    assert_eq!(signed[32] & 0x01, 0x01, "user present");
    // The decrypt verified the user, so RPs that require user verification accept it.
    assert_eq!(signed[32] & 0x04, 0x04, "user verified");
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature = Signature::from_der(&b64(&assertion["response"]["signature"])).unwrap();
    key.verify(&signed, &signature).unwrap();
}

#[test]
fn registers_into_the_site_folder_and_signs_in_with_one_decrypt_each() {
    let store = Store::new();
    let mut browser = Browser::start(&store, None);

    let credential = browser.ok("create", registration("alice"));
    assert_eq!(credential["id"], credential["rawId"]);
    assert_eq!(
        credential["clientExtensionResults"]["credProps"]["rk"],
        true
    );
    let client: Value =
        serde_json::from_slice(&b64(&credential["response"]["clientDataJSON"])).unwrap();
    assert_eq!(client["type"], "webauthn.create");
    assert_eq!(client["origin"], ORIGIN);
    let attestation: ciborium::Value =
        ciborium::from_reader(b64(&credential["response"]["attestationObject"]).as_slice())
            .unwrap();
    assert_eq!(
        attestation.as_map().unwrap()[0],
        (
            ciborium::Value::Text("fmt".into()),
            ciborium::Value::Text("none".into())
        )
    );
    assert_eq!(
        store.passkeys(),
        [store.root().join("www/example.com/passkey.age")]
    );
    assert_eq!(store.decrypts(), 0, "a registration decrypts nothing");

    for sign_ins in 1..=2 {
        let assertion = browser.ok("get", sign_in(&[&credential["id"]]));
        assert_eq!(assertion["id"], credential["id"]);
        assert_eq!(
            b64(&assertion["response"]["userHandle"]),
            b"alice",
            "the user handle"
        );
        verify(&credential, &assertion);
        assert_eq!(
            store.decrypts(),
            sign_ins,
            "one decrypt per sign-in, none kept"
        );
    }

    // Without an allowList (a discoverable sign-in) the one passkey is used, also one decrypt.
    let assertion = browser.ok("get", sign_in(&[]));
    verify(&credential, &assertion);
    assert_eq!(store.decrypts(), 3);

    assert_eq!(browser.close(), 1, "only the registration asked the user");
}

#[test]
fn several_accounts_let_the_user_choose() {
    let store = Store::new();
    let mut browser = Browser::start(&store, Some("bob"));
    let alice = browser.ok("create", registration("alice"));
    let bob = browser.ok("create", registration("bob"));
    assert_eq!(store.passkeys().len(), 2);

    let before = store.decrypts();
    let assertion = browser.ok("get", sign_in(&[]));
    assert_eq!(b64(&assertion["response"]["userHandle"]), b"bob");
    verify(&bob, &assertion);
    // Picking between accounts needs each passkey of the site once.
    assert_eq!(store.decrypts() - before, 2);

    // With an allowList the browser has already chosen: one decrypt.
    let before = store.decrypts();
    verify(&alice, &browser.ok("get", sign_in(&[&alice["id"]])));
    assert_eq!(store.decrypts() - before, 1);
    browser.close();
}

#[test]
fn a_declined_choice_and_a_foreign_rp_are_refused() {
    let store = Store::new();
    let mut browser = Browser::start(&store, None);
    browser.ok("create", registration("alice"));
    browser.ok("create", registration("bob"));
    let result = browser.request("get", ORIGIN, sign_in(&[]));
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["dom"], "NotAllowedError");

    let result = browser.request("get", "https://evil.example.org", sign_in(&[]));
    assert_eq!(result["error"]["dom"], "SecurityError");
    browser.close();
}

#[test]
fn an_excluded_credential_is_an_invalid_state() {
    let store = Store::new();
    let mut browser = Browser::start(&store, None);
    let credential = browser.ok("create", registration("alice"));
    let mut again = registration("alice");
    again["excludeCredentials"] = json!([{"type": "public-key", "id": credential["id"]}]);
    let result = browser.request("create", ORIGIN, again);
    assert_eq!(result["error"]["dom"], "InvalidStateError", "{result}");
    assert_eq!(store.passkeys().len(), 1);
    browser.close();
}

#[test]
fn aborted_and_malformed_requests() {
    let store = Store::new();
    let mut browser = Browser::start(&store, None);
    // Aborted before its turn: never served, never answered.
    browser.send(json!({"type": "abort", "id": 7}));
    browser.send(json!({
        "type": "request", "id": 7, "op": "create", "origin": ORIGIN, "cross_origin": false,
        "body": registration("alice").to_string(),
    }));
    // A request frame with a bad field is refused by id.
    browser.send(json!({"type": "request", "id": 8, "op": "sign", "origin": ORIGIN}));
    assert_eq!(
        browser.receive(),
        json!({"type": "result", "id": 8, "ok": false, "error": {"dom": "NotAllowedError"}})
    );
    // Unknown frames are ignored; the connection keeps serving.
    browser.send(json!({"type": "keepalive"}));
    browser.next_id = 9;
    browser.ok("create", registration("bob"));
    assert_eq!(store.passkeys().len(), 1, "only bob's registration ran");
    browser.close();
}

#[test]
fn chromium_starts_the_host_with_the_extension_origin() {
    let args = |list: &[&str]| {
        list.iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    };
    assert!(invoked_by_browser(args(&[
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
    ])));
    assert!(invoked_by_browser(args(&[
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        "--parent-window=0"
    ])));
    assert!(!invoked_by_browser(args(&[])));
    assert!(!invoked_by_browser(args(&["--backend-type", "passage"])));
    assert!(!invoked_by_browser(args(&["config", "print"])));
}

#[test]
fn oversized_frames_end_the_connection() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&((MAX_REQUEST_BYTES + 1) as u32).to_ne_bytes());
    assert!(read_frame(&mut frame.as_slice()).is_err());
    assert!(read_frame(&mut [].as_slice()).unwrap().is_none());
}
