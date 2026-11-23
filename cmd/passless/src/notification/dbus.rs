//! Prompts as desktop notifications over D-Bus (notify-rust), with compatibility for
//! different notification servers (notify-osd, mako, Dunst, etc.).

use super::{NotificationResult, PromptKind, YesNoResult};

use std::sync::{Arc, Mutex};

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout, Urgency};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationActionMode {
    Explicit,
    Default,
    DunstDefault,
}

impl NotificationActionMode {
    fn uses_default_action(self) -> bool {
        matches!(self, Self::Default | Self::DunstDefault)
    }
}

/// Determine how actions should be exposed for a notification server.
///
/// Legacy compatibility servers use a default action for all prompt types.
/// Dunst gets that behavior only for CTAP user presence: its actions are
/// supported but normally invoked through Dunst's interaction model instead
/// of visible buttons. User verification deliberately keeps explicit actions
/// so the UP compatibility path cannot silently weaken UV semantics.
fn action_mode_for_server(
    server_name: &str,
    server_version: &str,
    prompt_kind: PromptKind,
) -> NotificationActionMode {
    let server_name = server_name.to_lowercase();

    match (server_name.as_str(), server_version) {
        ("notify-osd", "1.0") | ("mako", "0.0.0") | ("quickshell", "") => {
            NotificationActionMode::Default
        }
        ("dunst", _) if prompt_kind == PromptKind::UserPresence => {
            NotificationActionMode::DunstDefault
        }
        _ => NotificationActionMode::Explicit,
    }
}

fn notification_action_mode(prompt_kind: PromptKind) -> NotificationActionMode {
    notify_rust::get_server_information()
        .map(|server| {
            let mode = action_mode_for_server(&server.name, &server.version, prompt_kind);
            debug!(
                "Notification server: {} (version: {})",
                server.name, server.version
            );

            match mode {
                NotificationActionMode::Default => {
                    info!("Detected {} - using default action mode", server.name);
                }
                NotificationActionMode::DunstDefault => {
                    info!("Detected Dunst - using UP-specific default action mode");
                }
                NotificationActionMode::Explicit => {}
            }

            mode
        })
        .unwrap_or_else(|e| {
            warn!("Failed to get notification server info: {}", e);
            NotificationActionMode::Explicit
        })
}

fn action_is_accepted(
    action: &str,
    affirmative_action: &str,
    action_mode: NotificationActionMode,
) -> bool {
    if action == affirmative_action {
        return true;
    }

    action == "default" && action_mode.uses_default_action()
}

/// Name `notify-rust` gives the action reported when a notification is closed without an answer
/// (dismissed by the user or timed out).
const CLOSED_ACTION: &str = "__closed";

/// The action of our own Deny button.
const DENY_ACTION: &str = "deny";

/// Classify the action a notification reported. Only our own affirmative action approves and
/// only our own explicit `deny` action is a denial that may count against a retry budget.
///
/// Everything else refuses without counting as a refusal: a close (dismissed or timed out), and
/// any action the prompt never offered. The listener has no sender filter, and notify-osd gives
/// every fallback dialog id 0, so the action of an unrelated dialog (for example an agent
/// escalation's `deny:<nonce>`) can reach this prompt. It must not approve and must not spend a
/// retry.
fn answer_from_action(
    action: &str,
    affirmative_action: &str,
    action_mode: NotificationActionMode,
) -> NotificationResult {
    if action_is_accepted(action, affirmative_action, action_mode) {
        NotificationResult::Accepted
    } else if action == DENY_ACTION && !action_mode.uses_default_action() {
        NotificationResult::Denied
    } else {
        if action != CLOSED_ACTION {
            debug!(
                "Unrecognised action '{}' - refusing without a denial",
                action
            );
        }
        NotificationResult::Dismissed
    }
}

/// Classify what the notification reported, if anything. No report at all, which is what a
/// notification stream that ends without an action (for example a D-Bus error) leaves behind,
/// fails closed as a close: refused, never approved.
fn answer_from_reported_action(
    reported: Option<&str>,
    affirmative_action: &str,
    action_mode: NotificationActionMode,
) -> NotificationResult {
    answer_from_action(
        reported.unwrap_or(CLOSED_ACTION),
        affirmative_action,
        action_mode,
    )
}

/// Show `message` under `summary` with Accept and Deny actions and wait for the answer.
/// Clicking Deny denies. Closing the notification, letting it time out or receiving an action
/// the prompt never offered is `Dismissed`: the operation is refused, but nobody refused it.
pub(super) fn show_prompt(
    summary: &str,
    mut message: String,
    timeout_seconds: u32,
    prompt_kind: PromptKind,
) -> Result<NotificationResult, String> {
    let action_mode = notification_action_mode(prompt_kind);

    if action_mode == NotificationActionMode::DunstDefault {
        message.push_str(
            "\n\nDunst: confirm by invoking this notification's action \
             (middle-click by default). Closing the notification refuses the request.",
        );
    }

    info!("Showing {} notification", summary);

    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    let mut notification = Notification::new();
    notification
        .summary(summary)
        .body(&message)
        .icon("security-high")
        .timeout(Timeout::Milliseconds(timeout_seconds * 1000))
        .urgency(Urgency::Critical);

    if action_mode.uses_default_action() {
        notification.action("default", "");
    } else {
        notification.action("approve", "Accept");
        notification.action("deny", "Deny");
    }

    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    let reported = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone();

    let answer = answer_from_reported_action(reported.as_deref(), "approve", action_mode);
    match answer {
        NotificationResult::Accepted => info!("Notification accepted"),
        NotificationResult::Denied => info!("Notification denied"),
        NotificationResult::Dismissed => info!("Notification closed or timed out"),
    }
    Ok(answer)
}

/// Show a yes/no question notification and wait for response
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `question` - The question to ask
///
/// # Returns
///
/// Result indicating whether the user answered yes (Accepted) or no or closed it (Denied)
pub fn show_yes_no_notification(title: &str, question: &str) -> Result<YesNoResult, String> {
    info!("Showing yes/no notification: {}", title);

    let action_mode = notification_action_mode(PromptKind::YesNo);

    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    let mut notification = Notification::new();
    notification
        .summary(title)
        .body(question)
        .icon("dialog-question")
        .timeout(Timeout::Never)
        .urgency(Urgency::Critical);

    if action_mode.uses_default_action() {
        notification.action("default", "");
    } else {
        notification.action("yes", "Yes");
        notification.action("no", "No");
    }

    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    let action = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone()
        .unwrap_or_else(|| CLOSED_ACTION.to_string());

    if action_is_accepted(&action, "yes", action_mode) {
        info!("User answered yes");
        Ok(YesNoResult::Accepted)
    } else {
        if action != "no" && action != CLOSED_ACTION {
            debug!("Unknown action '{}' - treating as no", action);
        }
        info!("User answered no or closed notification");
        Ok(YesNoResult::Denied)
    }
}

/// Show an informational notification (no user response needed)
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `message` - The message to display
///
/// # Returns
///
/// Ok if notification was shown successfully
pub fn show_info_notification(title: &str, message: &str) -> Result<(), String> {
    info!("Showing info notification: {}", title);

    Notification::new()
        .summary(title)
        .body(message)
        .icon("dialog-information")
        .timeout(Timeout::Milliseconds(5000))
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    Ok(())
}

/// Show an error notification
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `error_message` - The error message to display
///
/// # Returns
///
/// Ok if notification was shown successfully
pub fn show_error_notification(title: &str, error_message: &str) -> Result<(), String> {
    warn!("Showing error notification: {}", title);

    Notification::new()
        .summary(title)
        .body(error_message)
        .icon("dialog-error")
        .timeout(Timeout::Milliseconds(8000))
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    Ok(())
}

/// The action of the choice at `index`.
fn choice_action(index: usize) -> String {
    format!("choose:{index}")
}

/// The choice an action reported: only one of our own `choose:<index>` actions.
fn choice_from_action(action: Option<&str>, choices: usize) -> Option<usize> {
    let index = action?.strip_prefix("choose:")?.parse().ok()?;
    (index < choices).then_some(index)
}

/// Offer `choices` as the actions of one notification and wait for the one taken. `None` when
/// the notification was closed or timed out.
pub(super) fn choose_one(
    summary: &str,
    message: &str,
    choices: &[String],
    timeout_seconds: u32,
) -> Result<Option<usize>, String> {
    info!("Showing choice notification: {}", summary);

    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    let mut notification = Notification::new();
    notification
        .summary(summary)
        .body(message)
        .icon("dialog-question")
        .timeout(Timeout::Milliseconds(timeout_seconds * 1000))
        .urgency(Urgency::Critical);
    for (index, choice) in choices.iter().enumerate() {
        notification.action(&choice_action(index), choice);
    }

    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;
    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        *action_result_clone
            .lock()
            .expect("Failed to lock action result") = Some(action.to_string());
    });

    let action = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone();
    Ok(choice_from_action(action.as_deref(), choices.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_our_own_deny_action_is_a_denial() {
        let mode = NotificationActionMode::Explicit;
        let answer = |action: &str| answer_from_action(action, "approve", mode);

        assert_eq!(answer("approve"), NotificationResult::Accepted);
        assert_eq!(answer("deny"), NotificationResult::Denied);
        // Dismissed by the user or timed out: neither accepted nor denied.
        assert_eq!(answer("__closed"), NotificationResult::Dismissed);
        // Actions the prompt never offered (for example another dialog's, which notify-osd
        // reports under the same id 0) refuse but cost nothing, and never approve.
        for foreign in [
            "whatever",
            "",
            "deny:0123abcd",
            "approve:0123abcd",
            "default",
            "yes",
        ] {
            assert_eq!(
                answer(foreign),
                NotificationResult::Dismissed,
                "{foreign:?}"
            );
        }
    }

    #[test]
    fn test_a_missing_action_fails_closed_as_a_close() {
        for mode in [
            NotificationActionMode::Explicit,
            NotificationActionMode::Default,
            NotificationActionMode::DunstDefault,
        ] {
            assert_eq!(
                answer_from_reported_action(None, "approve", mode),
                NotificationResult::Dismissed,
                "{mode:?}"
            );
            assert_eq!(
                answer_from_reported_action(Some("deny"), "approve", mode),
                if mode.uses_default_action() {
                    NotificationResult::Dismissed
                } else {
                    NotificationResult::Denied
                },
                "{mode:?}"
            );
        }
    }

    #[test]
    fn test_dunst_default_action_accepts_and_close_is_dismissed() {
        let mode = NotificationActionMode::DunstDefault;
        assert_eq!(
            answer_from_action("default", "approve", mode),
            NotificationResult::Accepted
        );
        assert_eq!(
            answer_from_action("__closed", "approve", mode),
            NotificationResult::Dismissed
        );
    }

    #[test]
    fn test_dunst_default_action_is_up_only() {
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::UserPresence),
            NotificationActionMode::DunstDefault
        );
        assert_eq!(
            action_mode_for_server("Dunst", "1.13.0", PromptKind::UserPresence),
            NotificationActionMode::DunstDefault
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::UserVerification),
            NotificationActionMode::Explicit
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::YesNo),
            NotificationActionMode::Explicit
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::CredentialProtection),
            NotificationActionMode::Explicit,
            "the lowering consent needs the explicit Accept action"
        );
    }

    #[test]
    fn test_legacy_default_action_servers_are_preserved() {
        for (name, version) in [("notify-osd", "1.0"), ("mako", "0.0.0"), ("quickshell", "")] {
            for prompt_kind in [
                PromptKind::UserPresence,
                PromptKind::UserVerification,
                PromptKind::CredentialProtection,
                PromptKind::YesNo,
            ] {
                assert_eq!(
                    action_mode_for_server(name, version, prompt_kind),
                    NotificationActionMode::Default
                );
            }
        }
    }

    #[test]
    fn test_unknown_servers_use_explicit_actions() {
        assert_eq!(
            action_mode_for_server("gnome-shell", "47", PromptKind::UserPresence),
            NotificationActionMode::Explicit
        );
    }

    #[test]
    fn test_default_action_acceptance_is_mode_specific() {
        assert!(action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::DunstDefault
        ));
        assert!(action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::Default
        ));
        assert!(!action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::Explicit
        ));
        assert!(action_is_accepted(
            "approve",
            "approve",
            NotificationActionMode::Explicit
        ));
        assert!(!action_is_accepted(
            "deny",
            "approve",
            NotificationActionMode::DunstDefault
        ));
        assert!(!action_is_accepted(
            "__closed",
            "approve",
            NotificationActionMode::DunstDefault
        ));
    }

    #[test]
    fn only_our_own_choice_actions_choose() {
        assert_eq!(choice_from_action(Some(&choice_action(1)), 2), Some(1));
        for foreign in [
            None,
            Some("choose:2"),
            Some("__closed"),
            Some("default"),
            Some("choose:x"),
        ] {
            assert_eq!(choice_from_action(foreign, 2), None, "{foreign:?}");
        }
    }
}
