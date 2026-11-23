use crate::ctap_request::{self, RequestSignals};

use soft_fido2_transport::ctaphid::ErrorCode;
use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, Message, Packet, UhidDevice};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};

/// CTAPHID_KEEPALIVE interval while a request runs (CTAP 2.1, 11.2.9.1.5: every 100 ms).
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
/// CTAPHID_KEEPALIVE status: the authenticator is still processing.
const STATUS_PROCESSING: u8 = 1;
/// CTAPHID_KEEPALIVE status: the authenticator waits for the user.
const STATUS_UPNEEDED: u8 = 2;
/// CTAP2_ERR_KEEPALIVE_CANCEL: the answer to a request the host cancelled.
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

#[derive(Debug, Clone)]
pub enum WorkerError {
    Read(String),
    Write(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Read(msg) => write!(f, "read error: {}", msg),
            WorkerError::Write(msg) => write!(f, "write error: {}", msg),
        }
    }
}

impl std::error::Error for WorkerError {}

pub enum WorkerOutcome {
    Clean,
    Error(WorkerError),
    Panicked,
}

pub trait HidEndpoint: Send {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError>;
    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError>;
}

impl HidEndpoint for Box<dyn HidEndpoint> {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
        (**self).read_packet(buffer)
    }

    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
        (**self).write_packet(data)
    }
}

pub struct UhidEndpoint(UhidDevice);

impl UhidEndpoint {
    pub fn new(device: UhidDevice) -> Self {
        Self(device)
    }
}

impl HidEndpoint for UhidEndpoint {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
        self.0
            .read_packet(buffer)
            .map_err(|e| WorkerError::Read(format!("{:?}", e)))
    }

    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
        self.0
            .write_packet(data)
            .map_err(|e| WorkerError::Write(format!("{:?}", e)))
    }
}

#[derive(Clone)]
pub struct WorkerConfig {
    pub poll_interval: Duration,
    pub cache_cleanup_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            cache_cleanup_interval: Duration::from_secs(5),
        }
    }
}

pub struct WorkerHandle {
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), WorkerError>>>,
}

impl WorkerHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn join(mut self) -> WorkerOutcome {
        let thread = match self.thread.take() {
            Some(t) => t,
            None => return WorkerOutcome::Clean,
        };
        match thread.join() {
            Ok(Ok(())) => WorkerOutcome::Clean,
            Ok(Err(e)) => WorkerOutcome::Error(e),
            Err(_) => WorkerOutcome::Panicked,
        }
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct WorkerHooks {
    pub on_response_sent: Option<Box<dyn FnMut() + Send + 'static>>,
}

impl WorkerHooks {
    pub fn noop() -> Self {
        Self {
            on_response_sent: None,
        }
    }
}

pub fn spawn<E, H>(
    endpoint: E,
    ctaphid: CtapHidHandler<H>,
    config: WorkerConfig,
    cancel: Arc<AtomicBool>,
    cache_cleanup: Box<dyn FnMut() + Send + 'static>,
) -> WorkerHandle
where
    E: HidEndpoint + 'static,
    H: CommandHandler + Send + 'static,
{
    spawn_with_hooks(
        endpoint,
        ctaphid,
        config,
        cancel,
        cache_cleanup,
        WorkerHooks::noop(),
    )
}

pub fn spawn_with_hooks<E, H>(
    endpoint: E,
    ctaphid: CtapHidHandler<H>,
    config: WorkerConfig,
    cancel: Arc<AtomicBool>,
    mut cache_cleanup: Box<dyn FnMut() + Send + 'static>,
    mut hooks: WorkerHooks,
) -> WorkerHandle
where
    E: HidEndpoint + 'static,
    H: CommandHandler + Send + 'static,
{
    let cancel_for_thread = Arc::clone(&cancel);
    let thread = std::thread::spawn(move || {
        run_loop(
            endpoint,
            ctaphid,
            &config,
            &cancel_for_thread,
            &mut cache_cleanup,
            &mut hooks,
        )
    });

    WorkerHandle {
        cancel,
        thread: Some(thread),
    }
}

fn run_loop<E: HidEndpoint, H: CommandHandler>(
    endpoint: E,
    mut ctaphid: CtapHidHandler<H>,
    config: &WorkerConfig,
    cancel: &AtomicBool,
    cache_cleanup: &mut dyn FnMut(),
    hooks: &mut WorkerHooks,
) -> Result<(), WorkerError> {
    let endpoint = Mutex::new(endpoint);
    let mut buffer = [0u8; 64];
    let mut last_cache_cleanup = Instant::now();
    let mut draining = false;

    info!("Worker started");

    'outer: loop {
        if cancel.load(Ordering::Relaxed) && !draining {
            info!("Worker received cancellation, draining...");
            draining = true;
        }

        if last_cache_cleanup.elapsed() >= config.cache_cleanup_interval {
            cache_cleanup();
            last_cache_cleanup = Instant::now();
        }

        let read = lock_endpoint(&endpoint).read_packet(&mut buffer);
        match read {
            Ok(Some(_)) => {
                debug!("Worker received packet from host");
                let packet = Packet::from_bytes(buffer);

                match process_with_keepalive(&endpoint, &mut ctaphid, packet) {
                    Ok(response_packets) => {
                        let batch_len = response_packets.len();
                        if batch_len == 0 {
                            debug!("Worker no response packets to send");
                            continue;
                        }

                        debug!("Worker sending {} response packets", batch_len);
                        for response_packet in &response_packets {
                            let written =
                                lock_endpoint(&endpoint).write_packet(response_packet.as_bytes());
                            if let Err(e) = written {
                                error!("Worker failed to write response packet: {}", e);
                                if draining {
                                    break 'outer;
                                }
                                return Err(e);
                            }
                        }

                        debug!("Worker response sent successfully");
                        if let Some(ref mut cb) = hooks.on_response_sent {
                            cb();
                        }
                    }
                    Err(e) => {
                        error!("Worker CTAP HID processing failed: {:?}", e);
                        if draining {
                            break;
                        }
                    }
                }
            }
            Ok(None) => {
                if draining {
                    info!("Worker drain complete");
                    break;
                }
                std::thread::sleep(config.poll_interval);
            }
            Err(e) => {
                if draining {
                    info!("Worker drain ended on read error: {}", e);
                    break;
                }
                error!("Worker read error: {}", e);
                return Err(e);
            }
        }
    }

    cache_cleanup();
    info!("Worker stopped gracefully");
    Ok(())
}

fn lock_endpoint<E>(endpoint: &Mutex<E>) -> MutexGuard<'_, E> {
    endpoint
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Process `packet`. When it completes a request that takes a while (a storage decrypt that asks
/// for a hardware PIN, a confirmation prompt, a Git pull), a helper thread meanwhile sends
/// CTAPHID_KEEPALIVE every [`KEEPALIVE_INTERVAL`], so the host keeps waiting, and watches for
/// CTAPHID_CANCEL. A cancelled CBOR request is answered with CTAP2_ERR_KEEPALIVE_CANCEL.
fn process_with_keepalive<E: HidEndpoint, H: CommandHandler>(
    endpoint: &Mutex<E>,
    ctaphid: &mut CtapHidHandler<H>,
    packet: Packet,
) -> soft_fido2_transport::Result<Vec<Packet>> {
    let cid = packet.cid();
    let signals = RequestSignals::default();
    let result = std::thread::scope(|scope| {
        let (stop, stopped) = mpsc::channel::<()>();
        let helper_signals = signals.clone();
        scope.spawn(move || keep_alive(endpoint, cid, &helper_signals, &stopped));
        let result = ctap_request::serve(&signals, || ctaphid.process_packet(packet));
        // The helper is joined before the response is written, so no keepalive follows it.
        drop(stop);
        result
    })?;
    let is_cbor = result.first().and_then(Packet::cmd) == Some(Cmd::Cbor);
    if signals.is_cancelled() && is_cbor {
        info!("Request cancelled by the host");
        return Message::new(cid, Cmd::Cbor, vec![CTAP2_ERR_KEEPALIVE_CANCEL], None).to_packets();
    }
    Ok(result)
}

fn keep_alive<E: HidEndpoint>(
    endpoint: &Mutex<E>,
    cid: u32,
    signals: &RequestSignals,
    stopped: &mpsc::Receiver<()>,
) {
    let mut buffer = [0u8; 64];
    while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(KEEPALIVE_INTERVAL) {
        let status = if signals.user_prompt_pending() {
            STATUS_UPNEEDED
        } else {
            STATUS_PROCESSING
        };
        let mut endpoint = lock_endpoint(endpoint);
        let keepalive = Message::new(cid, Cmd::Keepalive, vec![status], None).to_packets();
        if let Some(keepalive) = keepalive.ok().as_ref().and_then(|packets| packets.first())
            && let Err(e) = endpoint.write_packet(keepalive.as_bytes())
        {
            warn!("Failed to send keepalive: {}", e);
        }
        // What the host sent meanwhile: CANCEL of this request, else the channel is busy.
        while let Ok(Some(_)) = endpoint.read_packet(&mut buffer) {
            let packet = Packet::from_bytes(buffer);
            if packet.cid() == cid && packet.cmd() == Some(Cmd::Cancel) {
                debug!("Host cancelled the running request");
                signals.cancel();
            } else if packet.is_init() {
                let busy = Packet::new_error(packet.cid(), ErrorCode::ChannelBusy);
                if let Err(e) = endpoint.write_packet(busy.as_bytes()) {
                    warn!("Failed to answer a packet while busy: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use soft_fido2_transport::{Cmd, Message};

    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct FakeEndpoint {
        inner: Arc<FakeEndpointInner>,
    }

    struct FakeEndpointInner {
        inbound: Mutex<VecDeque<[u8; 64]>>,
        outbound: Mutex<Vec<[u8; 64]>>,
        read_errors: Mutex<VecDeque<WorkerError>>,
        write_errors: Mutex<VecDeque<WorkerError>>,
    }

    impl FakeEndpoint {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeEndpointInner {
                    inbound: Mutex::new(VecDeque::new()),
                    outbound: Mutex::new(Vec::new()),
                    read_errors: Mutex::new(VecDeque::new()),
                    write_errors: Mutex::new(VecDeque::new()),
                }),
            }
        }

        fn push_packet(&self, packet: &Packet) {
            self.inner
                .inbound
                .lock()
                .unwrap()
                .push_back(*packet.as_bytes());
        }

        fn outbound_packets(&self) -> Vec<[u8; 64]> {
            self.inner.outbound.lock().unwrap().clone()
        }

        fn push_read_error(&self, err: WorkerError) {
            self.inner.read_errors.lock().unwrap().push_back(err);
        }
    }

    impl HidEndpoint for FakeEndpoint {
        fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
            {
                let mut errors = self.inner.read_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }

            let maybe = self.inner.inbound.lock().unwrap().pop_front();

            match maybe {
                Some(pkt) => {
                    buffer.copy_from_slice(&pkt);
                    Ok(Some(64))
                }
                None => Ok(None),
            }
        }

        fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
            {
                let mut errors = self.inner.write_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }
            self.inner.outbound.lock().unwrap().push(*data);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeHandler {
        inner: Arc<FakeHandlerInner>,
    }

    struct FakeHandlerInner {
        commands: Mutex<Vec<(Cmd, Vec<u8>)>>,
        responses: Mutex<VecDeque<Vec<u8>>>,
    }

    impl FakeHandler {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeHandlerInner {
                    commands: Mutex::new(Vec::new()),
                    responses: Mutex::new(VecDeque::new()),
                }),
            }
        }

        fn enqueue_response(&self, data: Vec<u8>) {
            self.inner.responses.lock().unwrap().push_back(data);
        }

        fn received_commands(&self) -> Vec<(Cmd, Vec<u8>)> {
            self.inner.commands.lock().unwrap().clone()
        }
    }

    impl CommandHandler for FakeHandler {
        fn handle_command(
            &mut self,
            cmd: Cmd,
            data: &[u8],
        ) -> soft_fido2_transport::Result<Vec<u8>> {
            self.inner
                .commands
                .lock()
                .unwrap()
                .push((cmd, data.to_vec()));

            let response = self
                .inner
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default();
            Ok(response)
        }
    }

    fn make_cbor_packet(cid: u32, data: &[u8]) -> Packet {
        let msg = Message::new(cid, Cmd::Cbor, data.to_vec(), None);
        let packets = msg.to_packets().unwrap();
        packets.into_iter().next().unwrap()
    }

    fn extract_response_message(packets: &[[u8; 64]]) -> Option<Message> {
        let owned: Vec<Packet> = packets.iter().map(|p| Packet::from_bytes(*p)).collect();
        Message::from_packets(&owned, None).ok()
    }

    #[test]
    fn test_routing_delivers_to_injected_handler() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        let payload = vec![0xA1, 0x01, 0x02];
        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0x12345678, &payload);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].0, Cmd::Cbor);
        assert_eq!(cmds[0].1, payload);
    }

    #[test]
    fn test_cancellation_stops_worker() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel.clone(),
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(20));

        handle.cancel();
        assert!(cancel.load(Ordering::Relaxed));

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_daemon_shutdown_via_shared_cancel() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let daemon_cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            daemon_cancel.clone(),
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(20));
        daemon_cancel.store(true, Ordering::Relaxed);

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_error_isolation_on_handler_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0xAABBCCDD, &[0x01, 0x02]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_error_isolation_on_read_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        endpoint.push_read_error(WorkerError::Read("device disconnected".into()));

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        let outcome = handle.join();
        match outcome {
            WorkerOutcome::Error(WorkerError::Read(msg)) => {
                assert!(msg.contains("device disconnected"));
            }
            _other => panic!("expected Error(Read), got other outcome"),
        }
    }

    #[test]
    fn test_response_completion() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let response_data = vec![0xBE, 0xEF];
        handler.enqueue_response(response_data.clone());

        let packet = make_cbor_packet(0x99999999, &[0xDE, 0xAD]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(
            !outbound.is_empty(),
            "expected at least one response packet"
        );

        let msg = extract_response_message(&outbound);
        assert!(
            msg.is_some(),
            "response packets should form a valid message"
        );
        let msg = msg.unwrap();
        assert_eq!(msg.cmd, Cmd::Cbor);
        assert_eq!(msg.data, response_data);
    }

    #[test]
    fn test_drain_before_destroy() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        for i in 0u8..3 {
            handler.enqueue_response(vec![i]);
            let pkt = make_cbor_packet(0x11111111, &[i]);
            endpoint.push_packet(&pkt);
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), 3, "all queued packets should be drained");
    }

    #[test]
    fn test_cache_cleanup_called_periodically() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cleanup_count = Arc::new(Mutex::new(0u32));
        let cleanup_count_clone = cleanup_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_millis(10),
            },
            cancel,
            Box::new(move || {
                *cleanup_count_clone.lock().unwrap() += 1;
            }),
        );

        std::thread::sleep(Duration::from_millis(80));
        handle.cancel();
        let _ = handle.join();

        let count = *cleanup_count.lock().unwrap();
        assert!(
            count >= 2,
            "cache cleanup should have been called multiple times, got {}",
            count
        );
    }

    #[test]
    fn test_thread_join_outcome_clean() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(10));
        handle.cancel();

        assert!(matches!(handle.join(), WorkerOutcome::Clean));
    }

    #[test]
    fn test_thread_join_outcome_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        endpoint.push_read_error(WorkerError::Read("fatal".into()));

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        assert!(matches!(handle.join(), WorkerOutcome::Error(_)));
    }

    #[test]
    fn test_multiple_packets_routed_sequentially() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        let payloads: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        for p in &payloads {
            handler.enqueue_response(p.clone());
        }
        for (i, p) in payloads.iter().enumerate() {
            let pkt = make_cbor_packet(0xAAAA0000 + i as u32, p);
            endpoint.push_packet(&pkt);
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(100));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(outbound.len() >= payloads.len());

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), payloads.len());
        for (i, (cmd, data)) in cmds.iter().enumerate() {
            assert_eq!(*cmd, Cmd::Cbor);
            assert_eq!(*data, payloads[i]);
        }
    }

    #[test]
    fn test_drop_handle_triggers_cancel_and_join() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_check = cancel.clone();

        {
            let _handle = spawn(
                endpoint,
                CtapHidHandler::new(handler),
                WorkerConfig {
                    poll_interval: Duration::from_millis(1),
                    cache_cleanup_interval: Duration::from_secs(3600),
                },
                cancel,
                Box::new(|| {}),
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(cancel_check.load(Ordering::Relaxed));
    }

    #[test]
    fn test_write_error_isolation_during_drain() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x01]);

        let packet = make_cbor_packet(0xBBBBBBBB, &[0x42]);
        endpoint.push_packet(&packet);

        {
            let mut errors = endpoint.inner.write_errors.lock().unwrap();
            errors.push_back(WorkerError::Write("write failed".into()));
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        let outcome = handle.join();
        match outcome {
            WorkerOutcome::Error(WorkerError::Write(msg)) => {
                assert!(msg.contains("write failed"));
            }
            _other => panic!("expected Error(Write), got other outcome"),
        }
    }

    #[test]
    fn test_hook_called_exactly_once_for_multi_packet_batch() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let large_response = vec![0xAA; 120];
        handler.enqueue_response(large_response);

        let packet = make_cbor_packet(0x12345678, &[0x01]);
        endpoint.push_packet(&packet);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(
            outbound.len() > 1,
            "expected multi-packet response, got {} packets",
            outbound.len()
        );

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 1, "hook should be called exactly once");
    }

    #[test]
    fn test_hook_not_called_on_partial_write() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let large_response = vec![0xBB; 120];
        handler.enqueue_response(large_response);

        let packet = make_cbor_packet(0xAABBCCDD, &[0x02]);
        endpoint.push_packet(&packet);

        {
            let mut errors = endpoint.inner.write_errors.lock().unwrap();
            errors.push_back(WorkerError::Write("write failed mid-batch".into()));
        }

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Error(_)));

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 0, "hook should not be called on partial write");
    }

    #[test]
    fn test_hook_called_on_handler_error_response() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0x99999999, &[0x03]);
        endpoint.push_packet(&packet);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(!outbound.is_empty(), "expected response packet");

        let count = *hook_count.lock().unwrap();
        assert_eq!(
            count, 1,
            "hook should be called after successful write of error response"
        );
    }

    #[test]
    fn test_drain_after_hook_callback() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x01]);
        handler.enqueue_response(vec![0x02]);

        let pkt1 = make_cbor_packet(0x11111111, &[0x10]);
        let pkt2 = make_cbor_packet(0x22222222, &[0x20]);
        endpoint.push_packet(&pkt1);
        endpoint.push_packet(&pkt2);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel.clone(),
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 2, "hook should be called for each successful batch");
    }

    #[test]
    fn test_spawn_without_hooks_works() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x55]);

        let packet = make_cbor_packet(0xAAAAAAAA, &[0x04]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let outbound = endpoint.outbound_packets();
        assert!(!outbound.is_empty(), "expected response packet");
    }

    /// A request handler that decrypts through `age`, like the passage backend does.
    struct AgeDecryptHandler(crate::storage::pass::age::AgeCrypto);

    impl CommandHandler for AgeDecryptHandler {
        fn handle_command(
            &mut self,
            _cmd: Cmd,
            data: &[u8],
        ) -> soft_fido2_transport::Result<Vec<u8>> {
            Ok(match self.0.decrypt(data) {
                Ok(plaintext) => plaintext.to_vec(),
                Err(_) => vec![0x7F],
            })
        }
    }

    /// Spawn a worker whose requests run a fake `age` with `body`, and send it one request.
    fn serve_through_fake_age(body: &str) -> (FakeEndpoint, WorkerHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let age = dir.path().join("age");
        crate::util::install_test_script(&age, body);
        let endpoint = FakeEndpoint::new();
        endpoint.push_packet(&make_cbor_packet(0x0bad_cafe, b"ciphertext"));
        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(AgeDecryptHandler(
                crate::storage::pass::age::AgeCrypto::new(age, dir.path().join("identities")),
            )),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            Arc::new(AtomicBool::new(false)),
            Box::new(|| {}),
        );
        (endpoint, handle, dir)
    }

    /// The packets sent so far: keepalive statuses and, once there, the CBOR response payload.
    fn keepalives_and_response(endpoint: &FakeEndpoint) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut statuses = Vec::new();
        let mut response = Vec::new();
        for bytes in endpoint.outbound_packets() {
            let packet = Packet::from_bytes(bytes);
            match packet.cmd() {
                Some(Cmd::Keepalive) => {
                    assert!(response.is_empty(), "keepalive after the response");
                    statuses.push(packet.payload()[0]);
                }
                _ => response.push(bytes),
            }
        }
        let message = extract_response_message(&response).map(|message| {
            assert_eq!(message.cmd, Cmd::Cbor);
            message.data
        });
        (statuses, message)
    }

    fn wait_for_response(endpoint: &FakeEndpoint, limit: Duration) -> (Vec<u8>, Vec<u8>) {
        let deadline = Instant::now() + limit;
        loop {
            if let (statuses, Some(response)) = keepalives_and_response(endpoint) {
                return (statuses, response);
            }
            assert!(Instant::now() < deadline, "no response within {limit:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A decrypt that takes 5 s (an age plugin waiting for a hardware PIN) keeps the host waiting:
    /// CTAPHID_KEEPALIVE with UPNEEDED every 100 ms, then the response.
    #[test]
    fn a_slow_age_decrypt_sends_keepalives_until_the_response() {
        let started = Instant::now();
        let (endpoint, handle, _dir) =
            serve_through_fake_age("cat >/dev/null\nsleep 5\nprintf plaintext\n");

        let (statuses, response) = wait_for_response(&endpoint, Duration::from_secs(15));

        assert!(started.elapsed() >= Duration::from_secs(5));
        assert_eq!(response, b"plaintext");
        assert!(statuses.len() >= 30, "{} keepalives", statuses.len());
        assert!(
            statuses.iter().all(|&status| status == STATUS_UPNEEDED),
            "{statuses:?}"
        );
        handle.cancel();
        assert!(matches!(handle.join(), WorkerOutcome::Clean));
    }

    /// CTAPHID_CANCEL from the host kills the running `age` and answers the request with
    /// CTAP2_ERR_KEEPALIVE_CANCEL instead of waiting for it.
    #[test]
    fn a_host_cancel_stops_a_slow_age_decrypt() {
        let started = Instant::now();
        let (endpoint, handle, _dir) = serve_through_fake_age("cat >/dev/null\nexec sleep 30\n");
        std::thread::sleep(Duration::from_millis(500));
        let cancel = Message::new(0x0bad_cafe, Cmd::Cancel, vec![], None)
            .to_packets()
            .unwrap();
        endpoint.push_packet(&cancel[0]);

        let (statuses, response) = wait_for_response(&endpoint, Duration::from_secs(10));

        assert_eq!(response, [CTAP2_ERR_KEEPALIVE_CANCEL]);
        assert!(!statuses.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
        handle.cancel();
        assert!(matches!(handle.join(), WorkerOutcome::Clean));
    }

    /// A quick request gets no keepalive.
    #[test]
    fn a_quick_request_sends_no_keepalive() {
        let (endpoint, handle, _dir) = serve_through_fake_age("cat >/dev/null\nprintf ok\n");

        let (statuses, response) = wait_for_response(&endpoint, Duration::from_secs(10));

        assert_eq!(response, b"ok");
        assert!(statuses.len() <= 1, "{statuses:?}");
        handle.cancel();
        assert!(matches!(handle.join(), WorkerOutcome::Clean));
    }
}
