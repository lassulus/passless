//! WebAuthn JSON to and from CTAP2: what a browser's WebAuthn client does for a USB key.
//!
//! The request is the browser's `requestDetailsJson` (the `PublicKeyCredentialCreationOptions` /
//! `RequestOptions` JSON shape, binary fields base64url). The host builds `clientDataJSON` from
//! the browser-vouched origin, hashes it into a CTAP2 MakeCredential or GetAssertion, and turns
//! the authenticator's answer into the `responseJson` (`PublicKeyCredential.toJSON()` shape).

use crate::cose::{attested_credential, spki_from_cose_key};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

const MAKE_CREDENTIAL: u8 = 0x01;
const GET_ASSERTION: u8 = 0x02;
pub(crate) const GET_NEXT_ASSERTION: u8 = 0x08;

const MAX_CHALLENGE_BYTES: usize = 1024;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_CREDENTIAL_DESCRIPTORS: usize = 64;
const MAX_USER_ID_BYTES: usize = 64;
const MAX_TEXT_LEN: usize = 1024;
const MAX_RP_ID_LEN: usize = 253;
/// `pubKeyCredParams` when the RP passed an empty list (WebAuthn: ES256 and RS256).
const DEFAULT_ALGORITHMS: [i64; 2] = [-7, -257];

/// The DOMException a refused request gets.
pub(crate) type Dom = &'static str;
pub(crate) const NOT_ALLOWED: Dom = "NotAllowedError";
pub(crate) const NOT_SUPPORTED: Dom = "NotSupportedError";
pub(crate) const INVALID_STATE: Dom = "InvalidStateError";
pub(crate) const SECURITY: Dom = "SecurityError";

/// The ceremony a `request` frame names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Create,
    Get,
}

impl Op {
    pub(crate) fn parse(op: &str) -> Option<Self> {
        match op {
            "create" => Some(Self::Create),
            "get" => Some(Self::Get),
            _ => None,
        }
    }
}

/// A WebAuthn request, translated.
#[derive(Debug)]
pub(crate) struct Ceremony {
    pub op: Op,
    pub rp_id: String,
    /// The CTAP2 command: command byte, then the CBOR parameters.
    pub ctap: Vec<u8>,
    client_data_json: Vec<u8>,
    /// MakeCredential: the RP asked for attestation other than `none`.
    keep_attestation: bool,
    /// MakeCredential: the RP asked for the `credProps` output, and whether `rk` was set.
    cred_props: Option<bool>,
}

fn b64u_decode(value: Option<&Json>, min: usize, max: usize) -> Result<Vec<u8>, Dom> {
    let Some(Json::String(encoded)) = value else {
        return Err(NOT_ALLOWED);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| NOT_ALLOWED)?;
    if bytes.len() < min || bytes.len() > max {
        return Err(NOT_ALLOWED);
    }
    Ok(bytes)
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn optional_text(value: Option<&Json>) -> Result<Option<&str>, Dom> {
    match value {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(text)) if text.len() <= MAX_TEXT_LEN => Ok(Some(text)),
        Some(_) => Err(NOT_ALLOWED),
    }
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// The origin's host when it may use `rp_id` (WebAuthn: the RP ID is the origin's effective
/// domain or a registrable suffix of it, and the origin is secure). The browser checked this
/// before handing the request over; the host checks again rather than trust the extension.
fn check_rp_id(origin: &str, rp_id: &str) -> Result<(), Dom> {
    let url = url::Url::parse(origin).map_err(|_| SECURITY)?;
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err(SECURITY);
    };
    let secure = match url.scheme() {
        "https" => true,
        "http" => is_localhost(host),
        _ => false,
    };
    if !secure || rp_id.is_empty() || rp_id.len() > MAX_RP_ID_LEN || rp_id != rp_id.to_lowercase() {
        return Err(SECURITY);
    }
    let within = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    // A public suffix (`com`, `github.io`) is no RP ID; `localhost` is not on the list.
    let registrable = is_localhost(rp_id) || psl::domain_str(rp_id).is_some();
    if within && registrable {
        Ok(())
    } else {
        Err(SECURITY)
    }
}

/// `clientDataJSON` in the member order browsers use.
fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    let quote = |s: &str| Json::String(s.to_string()).to_string();
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        quote(kind),
        quote(&b64u(challenge)),
        quote(origin)
    )
    .into_bytes()
}

/// The ids of `allowCredentials` or `excludeCredentials` as CTAP credential descriptors.
fn descriptors(value: Option<&Json>) -> Result<Vec<Value>, Dom> {
    let list = match value {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(Json::Array(list)) if list.len() <= MAX_CREDENTIAL_DESCRIPTORS => list,
        Some(_) => return Err(NOT_ALLOWED),
    };
    list.iter()
        .filter(|descriptor| descriptor.get("type") == Some(&json!("public-key")))
        .map(|descriptor| {
            let id = b64u_decode(descriptor.get("id"), 1, MAX_CREDENTIAL_ID_BYTES)?;
            Ok(Value::Map(vec![
                (text("id"), Value::Bytes(id)),
                (text("type"), text("public-key")),
            ]))
        })
        .collect()
}

/// The RP's algorithms in order; entries of another credential type are ignored.
fn algorithms(value: Option<&Json>) -> Result<Vec<i64>, Dom> {
    let params = match value {
        None | Some(Json::Null) => return Ok(DEFAULT_ALGORITHMS.to_vec()),
        Some(Json::Array(params)) => params,
        Some(_) => return Err(NOT_ALLOWED),
    };
    if params.is_empty() {
        return Ok(DEFAULT_ALGORITHMS.to_vec());
    }
    params
        .iter()
        .filter(|param| param.get("type") == Some(&json!("public-key")))
        .map(|param| param.get("alg").and_then(Json::as_i64).ok_or(NOT_ALLOWED))
        .collect()
}

/// Whether to ask the authenticator for user verification: unless the RP discouraged it.
fn wants_uv(value: Option<&Json>) -> bool {
    value.and_then(Json::as_str) != Some("discouraged")
}

fn command(command: u8, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = vec![command];
    ciborium::into_writer(&Value::Map(params), &mut bytes).expect("CBOR to a Vec cannot fail");
    bytes
}

impl Ceremony {
    /// Translate `body` (the browser's `requestDetailsJson`) for `op`. `origin` is the origin
    /// the browser vouched for; a request from a cross-origin frame is refused.
    pub(crate) fn parse(op: Op, origin: &str, cross_origin: bool, body: &str) -> Result<Self, Dom> {
        let Ok(Json::Object(details)) = serde_json::from_str::<Json>(body) else {
            return Err(NOT_ALLOWED);
        };
        if cross_origin {
            return Err(NOT_ALLOWED);
        }
        let challenge = b64u_decode(details.get("challenge"), 1, MAX_CHALLENGE_BYTES)?;
        let extensions = match details.get("extensions") {
            None | Some(Json::Null) => Map::new(),
            Some(Json::Object(extensions)) => extensions.clone(),
            Some(_) => return Err(NOT_ALLOWED),
        };
        match op {
            Op::Create => Self::create(origin, &details, &extensions, &challenge),
            Op::Get => Self::get(origin, &details, &challenge),
        }
    }

    fn create(
        origin: &str,
        details: &Map<String, Json>,
        extensions: &Map<String, Json>,
        challenge: &[u8],
    ) -> Result<Self, Dom> {
        let Some(Json::Object(rp)) = details.get("rp") else {
            return Err(NOT_ALLOWED);
        };
        let rp_id = match rp.get("id") {
            Some(Json::String(id)) => id.clone(),
            // WebAuthn: no rp.id means the origin's effective domain.
            None | Some(Json::Null) => url::Url::parse(origin)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .ok_or(SECURITY)?,
            Some(_) => return Err(NOT_ALLOWED),
        };
        check_rp_id(origin, &rp_id)?;
        let Some(Json::Object(user)) = details.get("user") else {
            return Err(NOT_ALLOWED);
        };
        let user_id = b64u_decode(user.get("id"), 1, MAX_USER_ID_BYTES)?;
        let user_name = optional_text(user.get("name"))?.ok_or(NOT_ALLOWED)?;
        let display_name = optional_text(user.get("displayName"))?;
        let selection = match details.get("authenticatorSelection") {
            None | Some(Json::Null) => Map::new(),
            Some(Json::Object(selection)) => selection.clone(),
            Some(_) => return Err(NOT_ALLOWED),
        };
        // WebAuthn: residentKey wins; without it, requireResidentKey. `preferred` asks for one.
        let rk = match selection.get("residentKey").and_then(Json::as_str) {
            Some("required") | Some("preferred") => true,
            Some(_) => false,
            None => selection.get("requireResidentKey") == Some(&Json::Bool(true)),
        };
        let uv = wants_uv(selection.get("userVerification"));
        let attestation = details
            .get("attestation")
            .and_then(Json::as_str)
            .unwrap_or("none");
        if attestation == "enterprise" {
            return Err(NOT_SUPPORTED);
        }

        let client_data_json = client_data_json("webauthn.create", challenge, origin);
        let mut rp_map = vec![(text("id"), text(&rp_id))];
        if let Some(name) = optional_text(rp.get("name"))? {
            rp_map.push((text("name"), text(name)));
        }
        let mut user_map = vec![
            (text("id"), Value::Bytes(user_id)),
            (text("name"), text(user_name)),
        ];
        if let Some(display_name) = display_name {
            user_map.push((text("displayName"), text(display_name)));
        }
        let params = algorithms(details.get("pubKeyCredParams"))?
            .into_iter()
            .map(|alg| {
                Value::Map(vec![
                    (text("alg"), int(alg)),
                    (text("type"), text("public-key")),
                ])
            })
            .collect();
        let mut request = vec![
            (
                int(1),
                Value::Bytes(Sha256::digest(&client_data_json).to_vec()),
            ),
            (int(2), Value::Map(rp_map)),
            (int(3), Value::Map(user_map)),
            (int(4), Value::Array(params)),
        ];
        let exclude = descriptors(details.get("excludeCredentials"))?;
        if !exclude.is_empty() {
            request.push((int(5), Value::Array(exclude)));
        }
        let cred_protect = match extensions
            .get("credentialProtectionPolicy")
            .and_then(Json::as_str)
        {
            Some("userVerificationOptional") => Some(1),
            Some("userVerificationOptionalWithCredentialIDList") => Some(2),
            Some("userVerificationRequired") => Some(3),
            _ => None,
        };
        if let Some(level) = cred_protect {
            request.push((int(6), Value::Map(vec![(text("credProtect"), int(level))])));
        }
        request.push((
            int(7),
            Value::Map(vec![
                (text("rk"), Value::Bool(rk)),
                (text("uv"), Value::Bool(uv)),
            ]),
        ));
        let cred_props = (extensions.get("credProps") == Some(&Json::Bool(true))).then_some(rk);
        Ok(Self {
            op: Op::Create,
            rp_id,
            ctap: command(MAKE_CREDENTIAL, request),
            client_data_json,
            keep_attestation: attestation != "none",
            cred_props,
        })
    }

    fn get(origin: &str, details: &Map<String, Json>, challenge: &[u8]) -> Result<Self, Dom> {
        let rp_id = match details.get("rpId") {
            Some(Json::String(id)) => id.clone(),
            None | Some(Json::Null) => url::Url::parse(origin)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .ok_or(SECURITY)?,
            Some(_) => return Err(NOT_ALLOWED),
        };
        check_rp_id(origin, &rp_id)?;
        let client_data_json = client_data_json("webauthn.get", challenge, origin);
        let mut request = vec![
            (int(1), text(&rp_id)),
            (
                int(2),
                Value::Bytes(Sha256::digest(&client_data_json).to_vec()),
            ),
        ];
        let allow = descriptors(details.get("allowCredentials"))?;
        if !allow.is_empty() {
            request.push((int(3), Value::Array(allow)));
        }
        request.push((
            int(5),
            Value::Map(vec![
                (text("up"), Value::Bool(true)),
                (
                    text("uv"),
                    Value::Bool(wants_uv(details.get("userVerification"))),
                ),
            ]),
        ));
        Ok(Self {
            op: Op::Get,
            rp_id,
            ctap: command(GET_ASSERTION, request),
            client_data_json,
            keep_attestation: false,
            cred_props: None,
        })
    }

    /// The `responseJson` of a MakeCredential answer.
    pub(crate) fn attestation_response(&self, response: &[u8]) -> Result<String, Dom> {
        let map = success(response)?;
        let fmt = field(&map, 1).and_then(Value::as_text).ok_or(NOT_ALLOWED)?;
        let auth_data = field(&map, 2)
            .and_then(Value::as_bytes)
            .ok_or(NOT_ALLOWED)?;
        let att_stmt = field(&map, 3).cloned().unwrap_or(Value::Map(Vec::new()));
        let (fmt, att_stmt) = if self.keep_attestation {
            (fmt.to_string(), att_stmt)
        } else {
            ("none".to_string(), Value::Map(Vec::new()))
        };
        // Canonical CBOR order: "fmt", "attStmt", "authData".
        let mut attestation_object = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (text("fmt"), Value::Text(fmt)),
                (text("attStmt"), att_stmt),
                (text("authData"), Value::Bytes(auth_data.clone())),
            ]),
            &mut attestation_object,
        )
        .map_err(|_| NOT_ALLOWED)?;
        let (credential_id, cose_key) = attested_credential(auth_data).map_err(|_| NOT_ALLOWED)?;
        let algorithm = cose_key
            .as_map()
            .and_then(|key| {
                key.iter()
                    .find(|(label, _)| label.as_integer() == Some(3.into()))
                    .and_then(|(_, alg)| alg.as_integer())
            })
            .map(i128::from)
            .ok_or(NOT_ALLOWED)?;
        let mut response_fields = json!({
            "clientDataJSON": b64u(&self.client_data_json),
            "attestationObject": b64u(&attestation_object),
            "authenticatorData": b64u(auth_data),
            "transports": ["usb"],
            "publicKeyAlgorithm": algorithm,
        });
        // RS256 and other keys without an SPKI here leave `publicKey` out, as WebAuthn allows.
        if let Some(spki) = spki_from_cose_key(&cose_key) {
            response_fields["publicKey"] = json!(b64u(&spki));
        }
        let mut extension_results = Map::new();
        if let Some(rk) = self.cred_props {
            extension_results.insert("credProps".into(), json!({ "rk": rk }));
        }
        let id = b64u(credential_id);
        Ok(json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": extension_results,
            "response": response_fields,
        })
        .to_string())
    }

    /// The `responseJson` of a GetAssertion (or GetNextAssertion) answer.
    pub(crate) fn assertion_response(&self, assertion: &Assertion) -> String {
        let id = b64u(&assertion.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": b64u(&self.client_data_json),
                "authenticatorData": b64u(&assertion.auth_data),
                "signature": b64u(&assertion.signature),
                "userHandle": assertion.user_id.as_deref().map(b64u),
            },
        })
        .to_string()
    }
}

/// One GetAssertion answer.
#[derive(Debug)]
pub(crate) struct Assertion {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Option<Vec<u8>>,
    /// The account, for choosing between several (`name`, else `displayName`).
    pub user_name: Option<String>,
    /// numberOfCredentials: set on the first answer when there are several.
    pub count: Option<usize>,
}

impl Assertion {
    pub(crate) fn parse(response: &[u8]) -> Result<Self, Dom> {
        let map = success(response)?;
        let credential_id = field(&map, 1)
            .and_then(|credential| map_text(credential, "id"))
            .and_then(Value::as_bytes)
            .ok_or(NOT_ALLOWED)?
            .clone();
        let auth_data = field(&map, 2)
            .and_then(Value::as_bytes)
            .ok_or(NOT_ALLOWED)?;
        let signature = field(&map, 3)
            .and_then(Value::as_bytes)
            .ok_or(NOT_ALLOWED)?;
        let user = field(&map, 4);
        let user_text = |key| {
            user.and_then(|user| map_text(user, key))
                .and_then(Value::as_text)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
        };
        Ok(Self {
            credential_id,
            auth_data: auth_data.clone(),
            signature: signature.clone(),
            user_id: user
                .and_then(|user| map_text(user, "id"))
                .and_then(Value::as_bytes)
                .cloned(),
            user_name: user_text("name").or_else(|| user_text("displayName")),
            count: field(&map, 5)
                .and_then(Value::as_integer)
                .and_then(|count| usize::try_from(i128::from(count)).ok()),
        })
    }
}

/// The CBOR map of a successful CTAP response, or the DOMException its status maps to.
fn success(response: &[u8]) -> Result<Vec<(Value, Value)>, Dom> {
    let (&status, body) = response.split_first().ok_or(NOT_ALLOWED)?;
    if status != 0 {
        return Err(dom_for_status(status));
    }
    match ciborium::from_reader::<Value, _>(body) {
        Ok(Value::Map(map)) => Ok(map),
        _ => Err(NOT_ALLOWED),
    }
}

/// What a browser makes of a CTAP error status.
pub(crate) fn dom_for_status(status: u8) -> Dom {
    match status {
        0x19 => INVALID_STATE, // CTAP2_ERR_CREDENTIAL_EXCLUDED
        0x26 => NOT_SUPPORTED, // CTAP2_ERR_UNSUPPORTED_ALGORITHM
        0x2B => NOT_SUPPORTED, // CTAP2_ERR_UNSUPPORTED_OPTION
        _ => NOT_ALLOWED,
    }
}

fn field(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer() == Some(key.into()))
        .map(|(_, v)| v)
}

fn map_text<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://login.example.com";

    fn decode_request(ctap: &[u8]) -> Vec<(Value, Value)> {
        match ciborium::from_reader::<Value, _>(&ctap[1..]).unwrap() {
            Value::Map(map) => map,
            other => panic!("not a map: {other:?}"),
        }
    }

    fn create_body(rp_id: &str) -> String {
        json!({
            "rp": {"id": rp_id, "name": "Example"},
            "user": {"id": "dXNlcg", "name": "alice", "displayName": "Alice"},
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "x", "alg": -8}],
            "excludeCredentials": [{"type": "public-key", "id": "AQID"}],
            "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
            "extensions": {
                "credProps": true,
                "remoteDesktopClientOverride": {"origin": ORIGIN, "sameOriginWithAncestors": true}
            }
        })
        .to_string()
    }

    #[test]
    fn a_registration_becomes_make_credential_over_the_client_data_hash() {
        let ceremony =
            Ceremony::parse(Op::Create, ORIGIN, false, &create_body("example.com")).unwrap();
        assert_eq!(ceremony.ctap[0], MAKE_CREDENTIAL);
        assert_eq!(
            String::from_utf8(ceremony.client_data_json.clone()).unwrap(),
            "{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\
             \"origin\":\"https://login.example.com\",\"crossOrigin\":false}"
        );
        let request = decode_request(&ceremony.ctap);
        assert_eq!(
            field(&request, 1).unwrap().as_bytes().unwrap().as_slice(),
            Sha256::digest(&ceremony.client_data_json).as_slice()
        );
        assert_eq!(
            map_text(field(&request, 2).unwrap(), "id"),
            Some(&text("example.com"))
        );
        assert_eq!(
            map_text(field(&request, 3).unwrap(), "id"),
            Some(&Value::Bytes(b"user".to_vec()))
        );
        // Only public-key algorithms, in the RP's order.
        assert_eq!(field(&request, 4).unwrap().as_array().unwrap().len(), 1);
        assert_eq!(field(&request, 5).unwrap().as_array().unwrap().len(), 1);
        assert_eq!(
            map_text(field(&request, 7).unwrap(), "rk"),
            Some(&Value::Bool(true))
        );
        assert_eq!(ceremony.cred_props, Some(true));
    }

    #[test]
    fn rp_ids_must_belong_to_the_origin() {
        for (origin, rp_id, ok) in [
            ("https://login.example.com", "example.com", true),
            ("https://login.example.com", "login.example.com", true),
            ("https://example.com", "login.example.com", false),
            ("https://example.com", "notexample.com", false),
            ("https://evil-example.com", "example.com", false),
            ("https://login.example.com", "com", false),
            ("https://a.github.io", "github.io", false),
            ("http://example.com", "example.com", false),
            ("http://localhost:8080", "localhost", true),
            ("http://rp.localhost:8080", "rp.localhost", true),
            ("https://127.0.0.1", "127.0.0.1", false),
            ("https://Example.com", "Example.com", false),
        ] {
            assert_eq!(check_rp_id(origin, rp_id).is_ok(), ok, "{origin} {rp_id}");
        }
        assert_eq!(
            Ceremony::parse(Op::Create, ORIGIN, false, &create_body("other.org")).unwrap_err(),
            SECURITY
        );
    }

    #[test]
    fn cross_origin_frames_and_malformed_requests_are_refused() {
        assert_eq!(
            Ceremony::parse(Op::Create, ORIGIN, true, &create_body("example.com")).unwrap_err(),
            NOT_ALLOWED
        );
        for body in ["", "[]", "{\"challenge\":\"***\"}", "{\"challenge\":7}"] {
            assert!(
                Ceremony::parse(Op::Get, ORIGIN, false, body).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn a_sign_in_becomes_get_assertion() {
        let body = json!({
            "rpId": "example.com",
            "challenge": "AAEC",
            "allowCredentials": [{"type": "public-key", "id": "AQID", "transports": ["usb"]}],
            "userVerification": "discouraged"
        })
        .to_string();
        let ceremony = Ceremony::parse(Op::Get, ORIGIN, false, &body).unwrap();
        let request = decode_request(&ceremony.ctap);
        assert_eq!(ceremony.ctap[0], GET_ASSERTION);
        assert_eq!(field(&request, 1), Some(&text("example.com")));
        assert_eq!(field(&request, 3).unwrap().as_array().unwrap().len(), 1);
        let options = field(&request, 5).unwrap();
        assert_eq!(map_text(options, "up"), Some(&Value::Bool(true)));
        assert_eq!(map_text(options, "uv"), Some(&Value::Bool(false)));
    }

    #[test]
    fn ctap_errors_map_to_dom_exceptions() {
        assert_eq!(dom_for_status(0x19), INVALID_STATE);
        assert_eq!(dom_for_status(0x26), NOT_SUPPORTED);
        assert_eq!(dom_for_status(0x2E), NOT_ALLOWED);
        assert_eq!(dom_for_status(0x27), NOT_ALLOWED);
        let ceremony =
            Ceremony::parse(Op::Create, ORIGIN, false, &create_body("example.com")).unwrap();
        assert_eq!(
            ceremony.attestation_response(&[0x19]).unwrap_err(),
            INVALID_STATE
        );
        assert_eq!(Assertion::parse(&[]).unwrap_err(), NOT_ALLOWED);
    }
}
