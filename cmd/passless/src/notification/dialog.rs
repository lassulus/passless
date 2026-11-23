//! Prompts as macOS dialogs, shown by `osascript` (AppleScript `display dialog`).
//!
//! macOS has no D-Bus notification server, and its notifications cannot carry the Accept and
//! Deny buttons a prompt needs, so prompts are modal dialogs. The texts reach the script as
//! arguments (`on run argv`), never as script source, so no text can change the script.

use super::{NotificationResult, YesNoResult};

use std::path::Path;
use std::process::{Command, Stdio};

use log::{debug, info, warn};

const OSASCRIPT: &str = "/usr/bin/osascript";

/// `display dialog` with two buttons; prints the label of the button pressed, or `gave up`
/// when the dialog timed out. Arguments: title, message, affirmative label, negative label,
/// seconds until it gives up (0: never).
const DIALOG_SCRIPT: &str = "on run argv
set {theTitle, theMessage, yesLabel, noLabel, waitSeconds} to argv
activate
if waitSeconds is \"0\" then
return button returned of (display dialog theMessage with title theTitle buttons {noLabel, yesLabel} default button yesLabel with icon caution)
end if
set answer to display dialog theMessage with title theTitle buttons {noLabel, yesLabel} default button yesLabel with icon caution giving up after (waitSeconds as integer)
if gave up of answer then return \"gave up\"
return button returned of answer
end run";

/// `display notification`. Arguments: title, message.
const NOTIFICATION_SCRIPT: &str = "on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run";

/// `choose from list`; prints the item chosen, or nothing. Arguments: title, prompt, items.
const CHOICE_SCRIPT: &str = "on run argv
set theTitle to item 1 of argv
set thePrompt to item 2 of argv
set choices to items 3 thru -1 of argv
activate
set picked to choose from list choices with title theTitle with prompt thePrompt
if picked is false then return \"\"
return item 1 of picked
end run";

const ACCEPT: &str = "Accept";
const DENY: &str = "Deny";
const GAVE_UP: &str = "gave up";

/// Run `script` with `args` through `osascript` at `program` and return what it printed.
/// `None` when the script failed (for example the dialog was closed with Escape).
fn run_script(program: &Path, script: &str, args: &[&str]) -> Result<Option<String>, String> {
    let output = Command::new(program)
        .arg("-e")
        .arg(script)
        .arg("--")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("Failed to run {}: {}", program.display(), e))?;
    if !output.status.success() {
        debug!(
            "osascript failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

/// Classify what the dialog printed. Only our own Accept button approves and only our own
/// Deny button is a denial; a timeout, a failed script or anything else is `Dismissed`.
fn answer_from_output(output: Option<&str>) -> NotificationResult {
    match output {
        Some(ACCEPT) => NotificationResult::Accepted,
        Some(DENY) => NotificationResult::Denied,
        Some(GAVE_UP) | None => NotificationResult::Dismissed,
        Some(other) => {
            debug!("Unrecognised dialog answer '{other}' - refusing without a denial");
            NotificationResult::Dismissed
        }
    }
}

fn show_prompt_with(
    program: &Path,
    summary: &str,
    message: &str,
    timeout_seconds: u32,
) -> Result<NotificationResult, String> {
    info!("Showing {summary} dialog");
    let seconds = timeout_seconds.max(1).to_string();
    let output = run_script(
        program,
        DIALOG_SCRIPT,
        &[summary, message, ACCEPT, DENY, &seconds],
    )?;
    let answer = answer_from_output(output.as_deref());
    info!("Dialog answered: {answer:?}");
    Ok(answer)
}

/// Show `message` under `summary` with Accept and Deny buttons and wait for the answer.
pub(super) fn show_prompt(
    summary: &str,
    message: String,
    timeout_seconds: u32,
    _prompt_kind: super::PromptKind,
) -> Result<NotificationResult, String> {
    show_prompt_with(Path::new(OSASCRIPT), summary, &message, timeout_seconds)
}

/// Ask a yes/no question and wait for the answer. Anything but Yes is no.
pub fn show_yes_no_notification(title: &str, question: &str) -> Result<YesNoResult, String> {
    info!("Showing yes/no dialog: {title}");
    let output = run_script(
        Path::new(OSASCRIPT),
        DIALOG_SCRIPT,
        &[title, question, "Yes", "No", "0"],
    )?;
    Ok(match output.as_deref() {
        Some("Yes") => YesNoResult::Accepted,
        _ => YesNoResult::Denied,
    })
}

/// Show an informational notification (no user response needed).
pub fn show_info_notification(title: &str, message: &str) -> Result<(), String> {
    info!("Showing info notification: {title}");
    run_script(Path::new(OSASCRIPT), NOTIFICATION_SCRIPT, &[title, message]).map(drop)
}

/// Show an error notification.
pub fn show_error_notification(title: &str, error_message: &str) -> Result<(), String> {
    warn!("Showing error notification: {title}");
    run_script(
        Path::new(OSASCRIPT),
        NOTIFICATION_SCRIPT,
        &[title, error_message],
    )
    .map(drop)
}

/// The label of the choice at `index`: numbered, so equal names stay apart.
fn choice_label(index: usize, choice: &str) -> String {
    format!("{}. {}", index + 1, choice)
}

fn choose_one_with(
    program: &Path,
    summary: &str,
    message: &str,
    choices: &[String],
) -> Result<Option<usize>, String> {
    info!("Showing choice dialog: {summary}");
    let labels: Vec<String> = choices
        .iter()
        .enumerate()
        .map(|(index, choice)| choice_label(index, choice))
        .collect();
    let mut args = vec![summary, message];
    args.extend(labels.iter().map(String::as_str));
    let output = run_script(program, CHOICE_SCRIPT, &args)?;
    Ok(output.and_then(|picked| labels.iter().position(|label| *label == picked)))
}

/// Let the user pick one of `choices`. `None` when they cancelled. `choose from list` cannot
/// time out, so `_timeout_seconds` is not used.
pub(super) fn choose_one(
    summary: &str,
    message: &str,
    choices: &[String],
    _timeout_seconds: u32,
) -> Result<Option<usize>, String> {
    choose_one_with(Path::new(OSASCRIPT), summary, message, choices)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::install_test_script;

    #[test]
    fn only_our_own_buttons_answer() {
        assert_eq!(
            answer_from_output(Some("Accept")),
            NotificationResult::Accepted
        );
        assert_eq!(answer_from_output(Some("Deny")), NotificationResult::Denied);
        assert_eq!(
            answer_from_output(Some("gave up")),
            NotificationResult::Dismissed
        );
        assert_eq!(answer_from_output(None), NotificationResult::Dismissed);
        for foreign in ["", "accept", "Yes", "Accept\nDeny"] {
            assert_eq!(
                answer_from_output(Some(foreign)),
                NotificationResult::Dismissed,
                "{foreign:?}"
            );
        }
    }

    /// The texts reach osascript as arguments after the script, never inside it.
    #[test]
    fn texts_are_arguments_not_script() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv");
        let fake = dir.path().join("osascript");
        install_test_script(
            &fake,
            &format!("printf '%s\\n' \"$@\" > '{}'\necho Accept\n", log.display()),
        );

        let message = "Operation: Registration\nRelying Party: \"x\" & do shell script \"id\"";
        let answer = show_prompt_with(&fake, "Passless", message, 30).unwrap();
        assert_eq!(answer, NotificationResult::Accepted);

        let argv = std::fs::read_to_string(&log).unwrap();
        let mut lines = argv.lines();
        assert_eq!(lines.next(), Some("-e"));
        assert!(argv.contains(&format!("--\nPassless\n{message}\nAccept\nDeny\n30\n")));
    }

    #[test]
    fn a_failing_dialog_is_dismissed() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("osascript");
        install_test_script(&fake, "echo 'User canceled. (-128)' >&2\nexit 1\n");
        assert_eq!(
            show_prompt_with(&fake, "Passless", "m", 0).unwrap(),
            NotificationResult::Dismissed
        );
        assert!(show_prompt_with(&dir.path().join("missing"), "Passless", "m", 1).is_err());
    }

    #[test]
    fn a_choice_is_the_position_of_the_label_picked() {
        let dir = tempfile::tempdir().unwrap();
        let picks_last = dir.path().join("picks-last");
        // Picks the last argument, the label of the last choice.
        install_test_script(&picks_last, "for a; do last=$a; done\necho \"$last\"\n");
        let choices = vec!["alice".to_string(), "alice".to_string()];
        assert_eq!(
            choose_one_with(&picks_last, "Passless", "Sign in as:", &choices).unwrap(),
            Some(1)
        );

        let cancels = dir.path().join("cancels");
        install_test_script(&cancels, "echo\n");
        assert_eq!(
            choose_one_with(&cancels, "Passless", "Sign in as:", &choices).unwrap(),
            None
        );
    }
}
