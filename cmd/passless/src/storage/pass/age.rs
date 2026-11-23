//! age encryption for [passage](https://github.com/FiloSottile/passage) stores.
//!
//! Every operation runs the `age` binary the way passage does: `age -d -i <identities>` to decrypt
//! and `age -e` with the recipients passage's `set_age_recipients` picks to encrypt. age plugins
//! (age-plugin-se, age-plugin-yubikey, age-plugin-fido2-hmac, ...) therefore behave exactly as
//! they do in passage.

use passless_core::error::{Error, Result};

use crate::ctap_request;

use std::ffi::OsString;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use log::{debug, warn};
use zeroize::Zeroizing;

/// How often a running `age` is checked for a cancelled CTAP request.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// passage's per-directory recipients file. The nearest one between an entry's directory and the
/// store root applies.
pub const AGE_RECIPIENTS_FILE: &str = ".age-recipients";

const PASSAGE_RECIPIENTS_FILE_ENV: &str = "PASSAGE_RECIPIENTS_FILE";
const PASSAGE_RECIPIENTS_ENV: &str = "PASSAGE_RECIPIENTS";

/// age encryption of passage store entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeCrypto {
    binary: PathBuf,
    identities_file: PathBuf,
    recipients_override: Option<AgeRecipients>,
}

/// The recipients an entry is encrypted to, as passage's `set_age_recipients` picks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgeRecipients {
    /// `-R <file>`: `$PASSAGE_RECIPIENTS_FILE` or the nearest `.age-recipients`.
    File(PathBuf),
    /// `-r <recipient>` for each whitespace-separated entry of `$PASSAGE_RECIPIENTS`.
    List(Vec<String>),
    /// `-i <identities>`: no `.age-recipients` up to the store root, so passage encrypts to the
    /// recipients of its own identities.
    Identities(PathBuf),
}

impl AgeRecipients {
    fn add_args(&self, command: &mut Command) {
        match self {
            Self::File(path) => {
                command.arg("-R").arg(path);
            }
            Self::List(recipients) => {
                for recipient in recipients {
                    command.arg("-r").arg(recipient);
                }
            }
            Self::Identities(path) => {
                command.arg("-i").arg(path);
            }
        }
    }
}

impl AgeCrypto {
    /// `binary` is the age executable and `identities_file` passage's identities file. Like in
    /// passage, a non-empty `$PASSAGE_RECIPIENTS_FILE`, else a non-empty `$PASSAGE_RECIPIENTS`,
    /// replaces the `.age-recipients` lookup.
    pub fn new(binary: PathBuf, identities_file: PathBuf) -> Self {
        Self {
            binary,
            identities_file,
            recipients_override: recipients_override(
                std::env::var_os(PASSAGE_RECIPIENTS_FILE_ENV),
                std::env::var_os(PASSAGE_RECIPIENTS_ENV),
            ),
        }
    }

    /// passage refuses to run without its identities file; so does this backend.
    pub fn ensure_identities(&self) -> Result<()> {
        if self.identities_file.is_file() {
            return Ok(());
        }
        Err(Error::Storage(format!(
            "No age identity at {}. Create one with: age-keygen -o {}",
            self.identities_file.display(),
            self.identities_file.display()
        )))
    }

    /// The recipients a new `target` entry of the store at `store_root` is encrypted to.
    pub fn recipients_for(&self, store_root: &Path, target: &Path) -> Result<AgeRecipients> {
        if let Some(recipients) = &self.recipients_override {
            return Ok(recipients.clone());
        }
        let dir = target.parent().ok_or_else(|| {
            Error::Storage(format!(
                "Target path '{}' has no parent directory",
                target.display()
            ))
        })?;
        Ok(match find_nearest_age_recipients(store_root, dir)? {
            Some(file) => AgeRecipients::File(file),
            None => AgeRecipients::Identities(self.identities_file.clone()),
        })
    }

    /// Encrypt `plaintext` to `output_path`, an entry of the store at `store_root`, replacing any
    /// previous file atomically.
    pub fn encrypt_file(
        &self,
        store_root: &Path,
        plaintext: &[u8],
        output_path: &Path,
    ) -> Result<()> {
        let recipients = self.recipients_for(store_root, output_path)?;
        super::write_atomically(output_path, |tmp_path| {
            let mut command = Command::new(&self.binary);
            command.arg("-e");
            recipients.add_args(&mut command);
            command.arg("-o").arg(tmp_path);
            // Encrypting to recipients needs no secret; to the identities file (`-i`) an age
            // plugin may have to ask for its hardware.
            let may_prompt = matches!(recipients, AgeRecipients::Identities(_));
            self.run(command, plaintext, "encryption", may_prompt)
                .map(drop)
        })
    }

    /// Decrypt `ciphertext` with the identities file. An age plugin may ask the user (a hardware
    /// PIN or touch) meanwhile; the running CTAP request reports that to the host.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut command = Command::new(&self.binary);
        command.arg("-d").arg("-i").arg(&self.identities_file);
        self.run(command, ciphertext, "decryption", true)
    }

    /// Run `age`, feeding `input`, and return its stdout. The process is killed when the host
    /// cancels the CTAP request being served.
    fn run(
        &self,
        mut command: Command,
        input: &[u8],
        action: &str,
        may_prompt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let _prompt = may_prompt.then(ctap_request::user_prompt);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                Error::Storage(format!(
                    "Failed to invoke {} for {action}: {error}",
                    self.binary.display()
                ))
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            // age exits early on a bad header or a missing identity; its stderr says why.
            match stdin.write_all(input) {
                Err(error) if error.kind() != ErrorKind::BrokenPipe => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Storage(format!(
                        "Failed to write to age for {action}: {error}"
                    )));
                }
                _ => {}
            }
        }
        let finished = wait_cancellable(&mut child)
            .map_err(|error| Error::Storage(format!("Failed to wait for age {action}: {error}")))?;
        let Some(Finished {
            status,
            stdout,
            stderr,
        }) = finished
        else {
            warn!("age {action} killed: the host cancelled the request");
            return Err(Error::Storage(format!(
                "age {action} cancelled by the host"
            )));
        };
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            debug!("age {action} failed: {}", stderr.trim());
            return Err(Error::Storage(format!(
                "age {action} failed ({}): {}",
                status,
                stderr.trim()
            )));
        }
        Ok(stdout)
    }
}

/// A process that exited, with its output.
struct Finished {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Vec<u8>,
}

/// Wait for `child` while collecting its output. `None`: the CTAP request was cancelled and the
/// process killed. Its output readers are then left to finish on their own: a process the child
/// started (a PIN prompt in an `age` wrapper) may still hold the pipes.
fn wait_cancellable(child: &mut Child) -> std::io::Result<Option<Finished>> {
    fn read_all(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buffer);
            }
            buffer
        })
    }
    let out = read_all(child.stdout.take());
    let err = read_all(child.stderr.take());
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(Finished {
                status,
                stdout: Zeroizing::new(out.join().unwrap_or_default()),
                stderr: err.join().unwrap_or_default(),
            }));
        }
        if ctap_request::cancelled() {
            let _ = child.kill();
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(CANCEL_POLL_INTERVAL);
    }
}

impl std::fmt::Display for AgeCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "age ({}, identities {})",
            self.binary.display(),
            self.identities_file.display()
        )
    }
}

/// passage's recipient overrides: `$PASSAGE_RECIPIENTS_FILE` wins over `$PASSAGE_RECIPIENTS`,
/// and empty values are ignored.
fn recipients_override(
    recipients_file: Option<OsString>,
    recipients: Option<OsString>,
) -> Option<AgeRecipients> {
    if let Some(file) = recipients_file.filter(|value| !value.is_empty()) {
        return Some(AgeRecipients::File(file.into()));
    }
    recipients.filter(|value| !value.is_empty()).map(|value| {
        AgeRecipients::List(
            value
                .to_string_lossy()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        )
    })
}

/// The nearest `.age-recipients` file from `start_dir` up to `store_root`, both included.
pub fn find_nearest_age_recipients(store_root: &Path, start_dir: &Path) -> Result<Option<PathBuf>> {
    if !start_dir.starts_with(store_root) {
        return Err(Error::Storage(format!(
            "Directory '{}' is not within store root '{}'",
            start_dir.display(),
            store_root.display()
        )));
    }
    let mut current = start_dir;
    loop {
        let candidate = current.join(AGE_RECIPIENTS_FILE);
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
        if current == store_root {
            return Ok(None);
        }
        // `start_dir` is beneath `store_root`, so the walk reaches it before running out.
        let Some(parent) = current.parent() else {
            return Ok(None);
        };
        current = parent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::CredentialStorage;
    use crate::storage::pass::{PassStorageAdapter, StoreCrypto};

    use std::fs;

    fn crypto(identities: &Path) -> AgeCrypto {
        AgeCrypto {
            binary: PathBuf::from("age"),
            identities_file: identities.to_path_buf(),
            recipients_override: None,
        }
    }

    #[test]
    fn the_nearest_age_recipients_file_applies() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path();
        let rp = store.join("fido2/example.com");
        fs::create_dir_all(&rp).unwrap();
        let target = rp.join("0a0b.age");
        let age = crypto(&store.join("identities"));

        // No .age-recipients anywhere: passage encrypts to its own identities.
        assert_eq!(
            age.recipients_for(store, &target).unwrap(),
            AgeRecipients::Identities(store.join("identities"))
        );

        fs::write(store.join(AGE_RECIPIENTS_FILE), "age1root\n").unwrap();
        assert_eq!(
            age.recipients_for(store, &target).unwrap(),
            AgeRecipients::File(store.join(AGE_RECIPIENTS_FILE))
        );

        fs::write(
            store.join("fido2").join(AGE_RECIPIENTS_FILE),
            "age1scoped\n",
        )
        .unwrap();
        assert_eq!(
            age.recipients_for(store, &target).unwrap(),
            AgeRecipients::File(store.join("fido2").join(AGE_RECIPIENTS_FILE))
        );

        fs::write(rp.join(AGE_RECIPIENTS_FILE), "age1rp\n").unwrap();
        assert_eq!(
            age.recipients_for(store, &target).unwrap(),
            AgeRecipients::File(rp.join(AGE_RECIPIENTS_FILE))
        );
    }

    #[test]
    fn a_directory_named_age_recipients_or_one_above_the_store_does_not_apply() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let rp = store.join("fido2/example.com");
        fs::create_dir_all(rp.join(AGE_RECIPIENTS_FILE)).unwrap();
        fs::write(dir.path().join(AGE_RECIPIENTS_FILE), "age1outside\n").unwrap();

        assert_eq!(find_nearest_age_recipients(&store, &rp).unwrap(), None);
    }

    #[test]
    fn a_target_outside_the_store_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let age = crypto(&dir.path().join("identities"));

        assert!(
            age.recipients_for(&store, &dir.path().join("elsewhere/x.age"))
                .is_err()
        );
    }

    #[test]
    fn environment_overrides_follow_passage_precedence() {
        assert_eq!(recipients_override(None, None), None);
        assert_eq!(
            recipients_override(Some("".into()), Some("".into())),
            None,
            "empty values are unset, as in passage's [[ -n ... ]]"
        );
        assert_eq!(
            recipients_override(None, Some(" age1a\tage1b\nage1c ".into())),
            Some(AgeRecipients::List(vec![
                "age1a".to_string(),
                "age1b".to_string(),
                "age1c".to_string(),
            ]))
        );
        assert_eq!(
            recipients_override(Some("/r.txt".into()), Some("age1a".into())),
            Some(AgeRecipients::File(PathBuf::from("/r.txt"))),
            "PASSAGE_RECIPIENTS_FILE wins over PASSAGE_RECIPIENTS"
        );
        assert_eq!(
            recipients_override(Some("".into()), Some("age1a".into())),
            Some(AgeRecipients::List(vec!["age1a".to_string()]))
        );
    }

    #[test]
    fn an_override_replaces_the_age_recipients_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(AGE_RECIPIENTS_FILE), "age1root\n").unwrap();
        let mut age = crypto(&store.join("identities"));
        age.recipients_override = Some(AgeRecipients::List(vec!["age1env".to_string()]));

        assert_eq!(
            age.recipients_for(store, &store.join("fido2/example.com/0a.age"))
                .unwrap(),
            AgeRecipients::List(vec!["age1env".to_string()])
        );
    }

    #[test]
    fn recipients_become_age_arguments() {
        let args = |recipients: AgeRecipients| {
            let mut command = Command::new("age");
            recipients.add_args(&mut command);
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            args(AgeRecipients::File("/s/.age-recipients".into())),
            ["-R", "/s/.age-recipients"]
        );
        assert_eq!(
            args(AgeRecipients::List(vec!["age1a".into(), "age1b".into()])),
            ["-r", "age1a", "-r", "age1b"]
        );
        assert_eq!(
            args(AgeRecipients::Identities("/ids".into())),
            ["-i", "/ids"]
        );
    }

    #[test]
    fn a_missing_identities_file_is_reported_like_passage() {
        let dir = tempfile::tempdir().unwrap();
        let error = crypto(&dir.path().join("identities"))
            .ensure_identities()
            .unwrap_err();
        assert!(error.to_string().contains("age-keygen -o"));
    }

    fn age_keygen(path: &Path) -> String {
        let output = Command::new("age-keygen")
            .arg("-o")
            .arg(path)
            .output()
            .expect("age-keygen must be on PATH");
        assert!(output.status.success());
        // age-keygen prints "Public key: age1..." to stderr.
        String::from_utf8(output.stderr)
            .unwrap()
            .trim()
            .strip_prefix("Public key: ")
            .unwrap()
            .to_string()
    }

    fn sample_credential() -> soft_fido2::Credential {
        soft_fido2::Credential {
            id: vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            rp: soft_fido2_ctap::types::RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: soft_fido2_ctap::types::User {
                id: vec![1, 2, 3],
                name: Some("alice@example.com".to_string()),
                display_name: Some("Alice".to_string()),
            },
            sign_count: 7,
            alg: -7,
            key: soft_fido2_ctap::CredentialKey::software(soft_fido2_ctap::SecBytes::new(vec![
                0x42;
                32
            ])),
            created: 1_700_000_000,
            discoverable: true,
            backup_state: soft_fido2::CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        }
    }

    fn credential_ref(credential: &soft_fido2::Credential) -> soft_fido2::CredentialRef<'_> {
        soft_fido2::CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp.id,
            rp_name: credential.rp.name.as_deref(),
            user_id: &credential.user.id,
            user_name: credential.user.name.as_deref(),
            user_display_name: credential.user.display_name.as_deref(),
            sign_count: &credential.sign_count,
            alg: &credential.alg,
            key: &credential.key,
            created: &credential.created,
            discoverable: &credential.discoverable,
            cred_protect: credential.extensions.cred_protect.as_ref(),
            backup_state: &credential.backup_state,
            cred_random: credential.extensions.cred_random.as_ref(),
        }
    }

    fn open(store: &Path, root: &str, crypto: AgeCrypto) -> PassStorageAdapter {
        PassStorageAdapter::new_with_options(
            store.to_path_buf(),
            PathBuf::from(root),
            StoreCrypto::Age(crypto),
            false,
        )
        .unwrap()
    }

    /// Passkeys written through the backend with the real `age` binary land in the site's folder
    /// next to its other passage entries (`www/example.com/passkey.age`, then
    /// `passkey-<8 hex>.age`), read back by credential ID, are plain age files that `age -d`
    /// decrypts to the CBOR payload, and are not readable with another identity.
    #[test]
    #[ignore = "requires the age and age-keygen binaries"]
    fn round_trip_with_the_age_binary() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let site = store.join("www/example.com");
        fs::create_dir_all(&site).unwrap();
        // The site's other entries: not age files, so decrypting one would fail the test.
        fs::write(site.join("user.age"), b"alice").unwrap();
        fs::write(site.join("pass.age"), b"hunter2").unwrap();
        let identities = dir.path().join("identities");
        let recipient = age_keygen(&identities);
        fs::write(store.join(AGE_RECIPIENTS_FILE), format!("{recipient}\n")).unwrap();

        let mut first = sample_credential();
        let mut second = sample_credential();
        second.id = vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        second.user.name = Some("bob@example.com".to_string());
        let mut adapter = open(&store, "www", crypto(&identities));
        adapter.write(credential_ref(&first)).unwrap();
        adapter.write(credential_ref(&second)).unwrap();
        // An update rewrites the passkey's own file.
        first.sign_count = 8;
        adapter.write(credential_ref(&first)).unwrap();

        let mut names: Vec<_> = fs::read_dir(&site)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "pass.age",
                "passkey-a1b2c3d4.age",
                "passkey.age",
                "user.age"
            ]
        );
        assert_eq!(fs::read(site.join("user.age")).unwrap(), b"alice");
        assert_eq!(fs::read(site.join("pass.age")).unwrap(), b"hunter2");
        let file = site.join("passkey.age");
        assert!(
            fs::read(&file)
                .unwrap()
                .starts_with(b"age-encryption.org/v1\n")
        );

        // A fresh adapter indexes the files without decrypting.
        let mut reopened = open(&store, "www", crypto(&identities));
        assert_eq!(reopened.count_credentials(), 2);
        assert_eq!(reopened.count_for_rp("example.com"), Some(2));
        assert!(reopened.cache.is_empty());
        // A lookup by ID during another site's request decrypts nothing and finds nothing.
        reopened.set_rp_hint(Some("other.example"));
        assert!(reopened.read(&second.id).is_err());
        assert!(reopened.cache.is_empty());
        // During the site's request, only its passkeys are decrypted.
        reopened.set_rp_hint(Some("example.com"));
        let read = reopened.read(&second.id).unwrap();
        assert_eq!(read.user.name.as_deref(), Some("bob@example.com"));
        let read = reopened.read(&first.id).unwrap();
        assert_eq!(read.rp.id, "example.com");
        assert_eq!(read.user.name.as_deref(), Some("alice@example.com"));
        assert_eq!(read.sign_count, 8);
        assert_eq!(read.key.material.as_slice(), &[0x42; 32]);

        // Deleting one account leaves the other's file.
        reopened.delete(&first.id).unwrap();
        assert!(!file.exists());
        assert!(site.join("passkey-a1b2c3d4.age").is_file());

        // passage-compatible: age itself decrypts it to the backend's CBOR payload.
        let output = Command::new("age")
            .arg("-d")
            .arg("-i")
            .arg(&identities)
            .arg(site.join("passkey-a1b2c3d4.age"))
            .output()
            .unwrap();
        assert!(output.status.success());
        let payload = crate::storage::credential::Credential::from_bytes(&output.stdout).unwrap();
        assert_eq!(payload.id.as_ref(), second.id.as_slice());
        assert_eq!(payload.rp.id, "example.com");

        // Another identity cannot read it, and the failure is a clean error.
        let other = dir.path().join("other-identities");
        age_keygen(&other);
        let mut wrong = open(&store, "www", crypto(&other));
        assert!(wrong.read(&second.id).is_err());
        let error = crypto(&other)
            .decrypt(&fs::read(site.join("passkey-a1b2c3d4.age")).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no identity matched"), "{error}");
    }

    /// An empty or `.` passkey root keeps the site folders directly in the store root.
    #[test]
    #[ignore = "requires the age and age-keygen binaries"]
    fn site_folders_can_sit_at_the_store_root() {
        for root in ["", "."] {
            let dir = tempfile::tempdir().unwrap();
            let identities = dir.path().join("identities");
            age_keygen(&identities);
            let credential = sample_credential();

            open(dir.path(), root, crypto(&identities))
                .write(credential_ref(&credential))
                .unwrap();

            assert!(
                dir.path().join("example.com/passkey.age").is_file(),
                "{root:?}"
            );
            let mut reopened = open(dir.path(), root, crypto(&identities));
            assert_eq!(reopened.count_credentials(), 1);
            assert_eq!(reopened.read(&credential.id).unwrap().rp.id, "example.com");
        }
    }

    /// Without any `.age-recipients`, entries are encrypted to the identities file, as passage does.
    #[test]
    #[ignore = "requires the age and age-keygen binaries"]
    fn without_age_recipients_entries_are_encrypted_to_the_identities() {
        let dir = tempfile::tempdir().unwrap();
        let identities = dir.path().join("identities");
        age_keygen(&identities);
        let age = crypto(&identities);
        let target = dir.path().join("fido2/example.com/01.age");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        age.encrypt_file(dir.path(), b"secret", &target).unwrap();

        assert_eq!(
            age.decrypt(&fs::read(&target).unwrap()).unwrap().as_slice(),
            b"secret"
        );
    }
}
