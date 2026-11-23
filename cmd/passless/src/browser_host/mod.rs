//! The human authenticator as a browser's native messaging host.
//!
//! macOS has no UHID, so there passless cannot be a virtual USB key. Instead a browser extension
//! intercepts WebAuthn (Chromium: `chrome.webAuthenticationProxy`) and sends every request over
//! native messaging to this process, which the browser starts with the extension's origin as its
//! only argument. A request is translated into the CTAP2 command a browser would send to a USB
//! key (`webauthn.rs`) and served by the same `AuthenticatorService` as the UHID key: same
//! storage backends, prompts, user verification settings and one decrypt per sign-in. Nothing
//! runs between browser sessions: the browser starts the host and ends it by closing the port.
//!
//! Wire protocol, both directions a 32-bit native-endian length followed by UTF-8 JSON:
//! - extension to host: `{"type":"request","id":N,"op":"create"|"get","origin":"https://…",
//!   "cross_origin":false,"body":"<requestDetailsJson>"}` and `{"type":"abort","id":N}`;
//! - host to extension: `{"type":"result","id":N,"ok":true,"body":"<responseJson>"}` or
//!   `{"type":"result","id":N,"ok":false,"error":{"dom":"NotAllowedError"}}`.
//!
//! `origin` is the origin the browser vouches for (Chromium writes it into the request's
//! `remoteDesktopClientOverride`; a page cannot set it). Only the extensions the host manifest
//! lists in `allowed_origins` can start the host.

mod webauthn;

use crate::authenticator::AuthenticatorService;
use crate::ctap_request::{self, RequestSignals};
use crate::instance_lock::InstanceLock;
use crate::pin_storage::PinStorage;
use crate::storage::{self, CredentialStorage};
use crate::{Frontend, ServiceHandler};

use self::webauthn::{Assertion, Ceremony, Dom, GET_NEXT_ASSERTION, NOT_ALLOWED, Op};

use passless_core::{BackendConfig, Error, Result};

use soft_fido2::CredentialKeyProvider;
use soft_fido2_transport::{Cmd, CommandHandler};

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use serde_json::{Value, json};

/// Largest frame accepted from the browser.
const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Chromium refuses messages from a host above 1 MiB.
const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// How long a request waits for another passless process to release the store.
const LOCK_WAIT: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(100);
/// How long the account choice stays up.
const CHOICE_TIMEOUT_SECONDS: u32 = 60;

/// Whether the browser started this process as its native messaging host: Chromium-family
/// browsers pass the calling extension's origin (`chrome-extension://<id>/`) as the first
/// argument.
pub(crate) fn invoked_by_browser(mut args: impl Iterator<Item = OsString>) -> bool {
    args.next()
        .and_then(|arg| arg.into_string().ok())
        .is_some_and(|arg| arg.starts_with("chrome-extension://"))
}

/// Serves the browser on stdin/stdout.
pub(crate) struct BrowserHost {
    backend: BackendConfig,
}

impl BrowserHost {
    pub(crate) fn new(backend: BackendConfig) -> Self {
        Self { backend }
    }
}

impl Frontend for BrowserHost {
    fn serve<
        S: CredentialStorage + 'static,
        P: PinStorage + 'static,
        K: CredentialKeyProvider + Send + Sync + 'static,
    >(
        self,
        service: AuthenticatorService<S, P, K>,
    ) -> Result<()> {
        info!("{}", service.storage_info());
        let protocol = protocol_stdout()?;
        let choose = |rp_id: &str, accounts: &[String]| {
            crate::notification::choose_account(rp_id, accounts, CHOICE_TIMEOUT_SECONDS)
        };
        serve_frames(
            io::stdin(),
            protocol,
            ctap_service(self.backend, service),
            choose,
        );
        info!("Browser closed the connection");
        Ok(())
    }
}

/// A CTAP request answered by `service`, as the UHID key answers it (`ServiceHandler`).
fn ctap_service<
    S: CredentialStorage + 'static,
    P: PinStorage + 'static,
    K: CredentialKeyProvider + Send + Sync + 'static,
>(
    backend: BackendConfig,
    service: AuthenticatorService<S, P, K>,
) -> impl FnMut(&[u8], &RequestSignals) -> std::result::Result<Vec<u8>, Dom> {
    let storage = service.storage.clone();
    let mut handler = ServiceHandler::new(service);
    move |request, signals| {
        // One passless process at a time may use a store; several browsers each start a host,
        // so a request holds the store's lock only while it runs.
        let _lock = wait_for_store(&backend, signals)?;
        let response = ctap_request::serve(signals, || handler.handle_command(Cmd::Cbor, request));
        storage::lock_shared_storage(&storage).cleanup_expired_cache();
        response.map_err(|e| {
            warn!("CTAP request failed: {e:?}");
            NOT_ALLOWED
        })
    }
}

/// The real stdout for the protocol. File descriptor 1 is pointed at stderr afterwards, so
/// nothing else in the process (or a child it starts) can write into the protocol stream.
fn protocol_stdout() -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;

    // SAFETY: plain descriptor calls; the duplicate is owned by the returned File only.
    unsafe {
        let protocol = libc::dup(libc::STDOUT_FILENO);
        if protocol < 0 || libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) < 0 {
            return Err(Error::Other(format!(
                "Failed to set up the native messaging channel: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(std::fs::File::from_raw_fd(protocol))
    }
}

/// Take the store's instance lock, waiting while another passless process holds it.
fn wait_for_store(
    backend: &BackendConfig,
    signals: &RequestSignals,
) -> std::result::Result<InstanceLock, Dom> {
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match InstanceLock::acquire(backend) {
            Ok(lock) => return Ok(lock),
            Err(Error::AlreadyRunning { .. })
                if Instant::now() < deadline && !signals.is_cancelled() =>
            {
                thread::sleep(LOCK_POLL);
            }
            Err(e) => {
                warn!("The credential store is busy or unavailable: {e}");
                return Err(NOT_ALLOWED);
            }
        }
    }
}

fn read_frame(input: &mut impl Read) -> io::Result<Option<Value>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {length} bytes"),
        ));
    }
    let mut frame = vec![0u8; length];
    input.read_exact(&mut frame)?;
    serde_json::from_slice(&frame)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn write_frame(output: &mut impl Write, frame: &Value) -> io::Result<()> {
    let bytes = frame.to_string().into_bytes();
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    output.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

/// A request frame, validated.
struct Request {
    id: u64,
    op: Op,
    origin: String,
    cross_origin: bool,
    body: String,
}

fn parse_request(frame: &Value) -> Option<Request> {
    Some(Request {
        id: frame.get("id")?.as_u64()?,
        op: Op::parse(frame.get("op")?.as_str()?)?,
        origin: frame.get("origin")?.as_str()?.to_string(),
        cross_origin: frame.get("cross_origin")?.as_bool()?,
        body: frame.get("body")?.as_str()?.to_string(),
    })
}

fn result_frame(id: u64, result: std::result::Result<String, Dom>) -> Value {
    match result {
        Ok(body) => json!({"type": "result", "id": id, "ok": true, "body": body}),
        Err(dom) => json!({"type": "result", "id": id, "ok": false, "error": {"dom": dom}}),
    }
}

/// The request being served and the ones aborted before their turn.
#[derive(Default)]
struct Inflight {
    current: Option<(u64, RequestSignals)>,
    aborted: HashSet<u64>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serve request frames from `input` one at a time through `ctap`, answering on `output`,
/// until `input` ends. An abort cancels its request: the running CTAP request sees the cancel
/// (an `age` run is killed), a queued one is dropped. The extension answers the page itself
/// once it sent an abort, so neither gets a result.
fn serve_frames<W: Write + Send + 'static>(
    input: impl Read + Send,
    output: W,
    mut ctap: impl FnMut(&[u8], &RequestSignals) -> std::result::Result<Vec<u8>, Dom>,
    mut choose: impl FnMut(&str, &[String]) -> std::result::Result<Option<usize>, String>,
) {
    let output = Arc::new(Mutex::new(output));
    let inflight = Arc::new(Mutex::new(Inflight::default()));
    let (queue, requests) = mpsc::channel::<Request>();

    thread::scope(|scope| {
        let reader_output = output.clone();
        let reader_inflight = inflight.clone();
        scope.spawn(move || {
            let mut input = input;
            loop {
                let frame = match read_frame(&mut input) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(e) => {
                        warn!("Bad frame from the browser: {e}");
                        break;
                    }
                };
                match frame.get("type").and_then(Value::as_str) {
                    Some("request") => match parse_request(&frame) {
                        Some(request) => {
                            let _ = queue.send(request);
                        }
                        None => {
                            if let Some(id) = frame.get("id").and_then(Value::as_u64) {
                                let mut output = lock(&reader_output);
                                let _ =
                                    write_frame(&mut *output, &result_frame(id, Err(NOT_ALLOWED)));
                            }
                        }
                    },
                    Some("abort") => {
                        let Some(id) = frame.get("id").and_then(Value::as_u64) else {
                            continue;
                        };
                        let mut inflight = lock(&reader_inflight);
                        match &inflight.current {
                            Some((current, signals)) if *current == id => signals.cancel(),
                            _ => {
                                inflight.aborted.insert(id);
                            }
                        }
                    }
                    other => debug!("Ignoring frame of type {other:?}"),
                }
            }
            // The browser is gone: whatever runs now has nobody to answer to.
            if let Some((_, signals)) = &lock(&reader_inflight).current {
                signals.cancel();
            }
            drop(queue);
        });

        for request in requests {
            let signals = RequestSignals::default();
            {
                let mut inflight = lock(&inflight);
                if inflight.aborted.remove(&request.id) {
                    continue;
                }
                inflight.current = Some((request.id, signals.clone()));
            }
            let result = handle(&request, &signals, &mut ctap, &mut choose);
            let cancelled = signals.is_cancelled();
            lock(&inflight).current = None;
            if cancelled {
                debug!("Request {} aborted", request.id);
                continue;
            }
            let mut output = lock(&output);
            if let Err(e) = write_frame(&mut *output, &result_frame(request.id, result)) {
                warn!("Cannot answer the browser: {e}");
            }
        }
    });
}

/// Serve one WebAuthn request through `ctap`.
fn handle(
    request: &Request,
    signals: &RequestSignals,
    ctap: &mut impl FnMut(&[u8], &RequestSignals) -> std::result::Result<Vec<u8>, Dom>,
    choose: &mut impl FnMut(&str, &[String]) -> std::result::Result<Option<usize>, String>,
) -> std::result::Result<String, Dom> {
    let ceremony = Ceremony::parse(
        request.op,
        &request.origin,
        request.cross_origin,
        &request.body,
    )
    .inspect_err(|dom| {
        info!(
            "Refusing a {:?} request from {}: {dom}",
            request.op, request.origin
        )
    })?;
    info!(
        "{:?} for {} from {}",
        ceremony.op, ceremony.rp_id, request.origin
    );
    let response = ctap(&ceremony.ctap, signals)?;
    match ceremony.op {
        Op::Create => ceremony.attestation_response(&response),
        Op::Get => {
            let first = Assertion::parse(&response)?;
            let count = first.count.unwrap_or(1);
            if count <= 1 {
                return Ok(ceremony.assertion_response(&first));
            }
            // Several accounts at this RP and no allowList to pick one: the user chooses, as a
            // browser's account picker would let them.
            let mut assertions = vec![first];
            for _ in 1..count {
                assertions.push(Assertion::parse(&ctap(&[GET_NEXT_ASSERTION], signals)?)?);
            }
            let names: Vec<String> = assertions
                .iter()
                .map(|assertion| {
                    assertion.user_name.clone().unwrap_or_else(|| {
                        let id = hex::encode(&assertion.credential_id);
                        format!("passkey {}", &id[..id.len().min(8)])
                    })
                })
                .collect();
            let chosen = choose(&ceremony.rp_id, &names)
                .map_err(|e| {
                    warn!("Cannot ask which account to use: {e}");
                    NOT_ALLOWED
                })?
                .ok_or(NOT_ALLOWED)?;
            let assertion = assertions.get(chosen).ok_or(NOT_ALLOWED)?;
            Ok(ceremony.assertion_response(assertion))
        }
    }
}

#[cfg(test)]
mod tests;
