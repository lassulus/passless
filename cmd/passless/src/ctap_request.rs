//! Signals between the CTAP request being served and the HID worker that serves it.
//!
//! The HID worker runs a request synchronously on its own thread and, while it runs, sends
//! CTAPHID_KEEPALIVE from a helper thread (`worker.rs`). Code deep in the request (an `age`
//! decrypt that may ask for a hardware PIN, a desktop notification) reports through these
//! signals that a user prompt is pending, so the keepalive says UPNEEDED instead of PROCESSING,
//! and polls whether the host sent CTAPHID_CANCEL. The signals are installed per thread for the
//! duration of one request, so code outside a HID request (agents, the CLI, tests running in
//! parallel) never sees another request's cancel.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The shared state of one CTAP request.
#[derive(Clone, Default)]
pub struct RequestSignals {
    cancelled: Arc<AtomicBool>,
    user_prompts: Arc<AtomicUsize>,
}

impl RequestSignals {
    /// The host cancelled the request (CTAPHID_CANCEL, or CTAPHID_INIT on its channel).
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Whether the request is waiting for the user (a prompt is shown or may be).
    pub fn user_prompt_pending(&self) -> bool {
        self.user_prompts.load(Ordering::Relaxed) > 0
    }
}

thread_local! {
    static CURRENT: RefCell<Option<RequestSignals>> = const { RefCell::new(None) };
}

/// Run `f` as the request that `signals` belong to.
pub fn serve<R>(signals: &RequestSignals, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CURRENT.with(|current| current.borrow_mut().take());
        }
    }
    CURRENT.with(|current| *current.borrow_mut() = Some(signals.clone()));
    let _reset = Reset;
    f()
}

/// Whether the host cancelled the request this thread serves (`false` outside a request).
pub fn cancelled() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(RequestSignals::is_cancelled)
    })
}

/// Marks a possible user prompt for as long as it lives.
pub struct UserPrompt(Option<Arc<AtomicUsize>>);

/// Report that the current request may wait for the user until the returned guard is dropped.
pub fn user_prompt() -> UserPrompt {
    let counter = CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .map(|signals| signals.user_prompts.clone())
    });
    if let Some(counter) = &counter {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    UserPrompt(counter)
}

impl Drop for UserPrompt {
    fn drop(&mut self) {
        if let Some(counter) = &self.0 {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_reach_the_serving_thread_only_while_it_serves() {
        let signals = RequestSignals::default();
        assert!(!cancelled());
        serve(&signals, || {
            assert!(!cancelled());
            let prompt = user_prompt();
            assert!(signals.user_prompt_pending());
            signals.cancel();
            assert!(cancelled());
            drop(prompt);
            assert!(!signals.user_prompt_pending());
            std::thread::spawn(|| assert!(!cancelled())).join().unwrap();
        });
        assert!(!cancelled());
        drop(user_prompt());
    }
}
