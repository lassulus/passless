//! Where credentials live in a store, and what is known about them without decrypting.
//!
//! pass: `<root>/<rp id>/<credential id hex>.gpg`, so the file name is the credential ID.
//!
//! passage: one folder per site, shared with the site's other entries (`user.age`, `pass.age`,
//! `otp.age`): `<root>/<rp id>/passkey.age`, and `passkey-<first 8 hex chars of the credential
//! ID>.age` for further accounts of the same site. Only those names are passkeys; nothing else in
//! the store is read. The credential ID is inside the ciphertext, so a passkey file's ID is
//! learned when it is decrypted, which is done per RP on demand (never for the whole store at
//! startup).

use super::StoreCrypto;
use crate::storage::index::{CredentialIndexes, load_credential_paths};
use crate::storage::rp_id::ValidatedRpId;
use crate::storage::{CredentialFilter, RelyingPartyMetadata};
use crate::util::{bytes_to_hex, create_secure_dir_all};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use log::warn;
use sha2::{Digest, Sha256};

const PASSKEY_FILE: &str = "passkey.age";

/// Whether `name` is a passage passkey file: `passkey.age` or `passkey-*.age`.
pub fn is_passkey_file_name(name: &str) -> bool {
    name == PASSKEY_FILE || (name.starts_with("passkey-") && name.ends_with(".age"))
}

/// The file name of a new passkey in an RP folder: `passkey.age`, or `passkey-<first 8 hex chars
/// of the credential ID>.age` when `passkey.age` is taken.
pub fn new_passkey_file_name(rp_dir: &Path, cred_id: &[u8]) -> String {
    if !rp_dir.join(PASSKEY_FILE).exists() {
        return PASSKEY_FILE.to_string();
    }
    let hex = bytes_to_hex(cred_id);
    format!("passkey-{}.age", &hex[..hex.len().min(8)])
}

/// Create the folder of an entry to be written. An existing passage folder belongs to the user's
/// store (passage creates it with umask 077, a Git clone with the user's umask, often 0755) and is
/// used as it is; a missing folder, and every pass folder, is created and checked private.
pub fn ensure_entry_dir(crypto: &StoreCrypto, dir: &Path) -> std::io::Result<()> {
    let existing_dir = std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir());
    if matches!(crypto, StoreCrypto::Age(_)) && existing_dir {
        return Ok(());
    }
    create_secure_dir_all(dir)
}

/// The credentials of a store, from file names alone.
#[derive(Default)]
pub struct StoreIndex {
    /// Credentials whose ID is known: from the file name (pass) or a decryption (passage).
    pub known: CredentialIndexes,
    /// passage passkey files not decrypted yet, by RP folder.
    unresolved: HashMap<String, Vec<PathBuf>>,
}

impl StoreIndex {
    /// Index the credentials under `root` without decrypting anything.
    pub fn load(root: &Path, crypto: &StoreCrypto) -> std::io::Result<Self> {
        match crypto {
            StoreCrypto::Gpg(_) => Ok(Self {
                known: load_credential_paths(root, "gpg")?,
                unresolved: HashMap::new(),
            }),
            StoreCrypto::Age(_) => Ok(Self {
                known: CredentialIndexes::default(),
                unresolved: scan_passkey_files(root),
            }),
        }
    }

    /// The RP folders whose passkey files must be decrypted before `filter` can be answered from
    /// [`Self::known`]. `rp_hint` is the RP of the current request: a credential looked up by ID
    /// is only searched there, otherwise in every RP.
    pub fn rps_to_resolve(&self, filter: &CredentialFilter, rp_hint: Option<&str>) -> Vec<String> {
        let rps = self.unresolved.keys();
        match filter {
            CredentialFilter::None => rps.cloned().collect(),
            CredentialFilter::ById(id) if self.known.id.contains_key(id) => Vec::new(),
            CredentialFilter::ById(_) => match rp_hint {
                Some(rp) => rps.filter(|dir| *dir == rp).cloned().collect(),
                None => rps.cloned().collect(),
            },
            CredentialFilter::ByRp(rp) => rps.filter(|dir| *dir == rp).cloned().collect(),
            CredentialFilter::ByHash(hash) => rps
                .filter(|dir| <[u8; 32]>::from(Sha256::digest(dir.as_bytes())) == *hash)
                .cloned()
                .collect(),
        }
    }

    /// Take the undecrypted passkey files of `rp`, to resolve them.
    pub fn take_unresolved(&mut self, rp: &str) -> (Option<ValidatedRpId>, Vec<PathBuf>) {
        let files = self.unresolved.remove(rp).unwrap_or_default();
        (ValidatedRpId::try_from(rp).ok(), files)
    }

    /// Put back a passkey file that could not be decrypted, so it still counts and is retried.
    pub fn keep_unresolved(&mut self, rp: &str, file: PathBuf) {
        self.unresolved
            .entry(rp.to_string())
            .or_default()
            .push(file);
    }

    pub fn count(&self) -> usize {
        self.known.id.len() + self.unresolved.values().map(Vec::len).sum::<usize>()
    }

    /// Credentials of `rp_id` (ASCII-case-insensitive, like [`CredentialIndexes::count_for_rp`]).
    pub fn count_for_rp(&self, rp_id: &str) -> usize {
        let rp_id = rp_id.trim();
        self.known.count_for_rp(rp_id)
            + self
                .unresolved
                .iter()
                .filter(|(dir, _)| dir.eq_ignore_ascii_case(rp_id))
                .map(|(_, files)| files.len())
                .sum::<usize>()
    }

    /// Every credential as `(RP ID, credential ID)`; `None` while a passkey's ID is unknown.
    pub fn credentials(&self) -> Option<Vec<(String, Vec<u8>)>> {
        self.unresolved.is_empty().then(|| self.known.credentials())
    }

    pub fn relying_parties(&self) -> Vec<RelyingPartyMetadata> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (rp, ids) in &self.known.rp {
            *counts.entry(rp).or_default() += ids.len();
        }
        for (rp, files) in &self.unresolved {
            *counts.entry(rp).or_default() += files.len();
        }
        let mut result: Vec<_> = counts
            .into_iter()
            .map(|(id, credential_count)| RelyingPartyMetadata {
                id: id.to_string(),
                // RP display name is encrypted credential data. Do not decrypt secrets
                // merely to provide an optional cosmetic field during discovery.
                name: None,
                credential_count,
            })
            .collect();
        result.sort_by(|left, right| left.id.cmp(&right.id));
        result
    }
}

/// The passkey files under `root`, by RP folder. Other entries are not looked at.
fn scan_passkey_files(root: &Path) -> HashMap<String, Vec<PathBuf>> {
    let mut files: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let Ok(rp_dirs) = std::fs::read_dir(root) else {
        return files;
    };
    for rp_dir in rp_dirs.flatten() {
        let rp = rp_dir.file_name();
        let Some(rp) = rp.to_str() else {
            continue;
        };
        if rp.starts_with('.') || !rp_dir.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(rp_dir.path()) else {
            continue;
        };
        let passkeys: Vec<PathBuf> = entries
            .flatten()
            .filter(|entry| entry.file_name().to_str().is_some_and(is_passkey_file_name))
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
            .map(|entry| entry.path())
            .collect();
        if passkeys.is_empty() {
            continue;
        }
        if let Err(e) = ValidatedRpId::try_from(rp) {
            warn!(
                "Skipping passkeys in {}: invalid RP ID folder name: {e}",
                rp_dir.path().display()
            );
            continue;
        }
        files.entry(rp.to_string()).or_default().extend(passkeys);
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn only_passkey_names_are_passkeys() {
        for name in ["passkey.age", "passkey-0a0b0c0d.age", "passkey-.age"] {
            assert!(is_passkey_file_name(name), "{name}");
        }
        for name in [
            "user.age",
            "pass.age",
            "otp.age",
            "passkey.gpg",
            "passkey",
            "passkeys.age",
            "my-passkey.age",
            ".tmp.1.passkey.age.new",
        ] {
            assert!(!is_passkey_file_name(name), "{name}");
        }
    }

    #[test]
    fn a_second_account_gets_the_credential_id_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let id = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        assert_eq!(new_passkey_file_name(dir.path(), &id), "passkey.age");
        fs::write(dir.path().join("passkey.age"), b"x").unwrap();
        assert_eq!(
            new_passkey_file_name(dir.path(), &id),
            "passkey-a1b2c3d4.age"
        );
        assert_eq!(
            new_passkey_file_name(dir.path(), &[0xab, 0x01]),
            "passkey-ab01.age"
        );
    }

    /// lass's layout: per-site folders hold user/pass/otp entries next to the passkeys.
    #[test]
    fn the_index_holds_passkey_files_only_and_counts_them_without_decrypting() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("www");
        for (path, contents) in [
            ("github.com/user.age", "not a passkey"),
            ("github.com/pass.age", "not a passkey"),
            ("github.com/otp.age", "not a passkey"),
            ("github.com/passkey.age", "x"),
            ("github.com/passkey-0a0b0c0d.age", "x"),
            ("example.org/pass.age", "not a passkey"),
            ("webauthn.io/passkey.age", "x"),
            (".git/passkey.age", "x"),
            ("passkey.age", "x"),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let age = StoreCrypto::Age(super::super::age::AgeCrypto::new(
            PathBuf::from("age"),
            dir.path().join("identities"),
        ));

        let index = StoreIndex::load(&root, &age).unwrap();

        assert_eq!(index.count(), 3);
        assert_eq!(index.count_for_rp("GitHub.com"), 2);
        assert_eq!(index.count_for_rp("example.org"), 0);
        assert_eq!(index.credentials(), None, "IDs are unknown until decrypted");
        let rps: Vec<_> = index
            .relying_parties()
            .into_iter()
            .map(|rp| (rp.id, rp.credential_count))
            .collect();
        assert_eq!(
            rps,
            [
                ("github.com".to_string(), 2),
                ("webauthn.io".to_string(), 1)
            ]
        );

        let mut by_rp = index.rps_to_resolve(&CredentialFilter::ByRp("github.com".into()), None);
        by_rp.sort();
        assert_eq!(by_rp, ["github.com"]);
        let hash: [u8; 32] = Sha256::digest(b"webauthn.io").into();
        assert_eq!(
            index.rps_to_resolve(&CredentialFilter::ByHash(hash), None),
            ["webauthn.io"]
        );
        assert_eq!(
            index.rps_to_resolve(&CredentialFilter::ById(vec![1]), Some("webauthn.io")),
            ["webauthn.io"],
            "an ID lookup is limited to the request's RP"
        );
        assert_eq!(
            index
                .rps_to_resolve(&CredentialFilter::ById(vec![1]), None)
                .len(),
            2
        );
    }
}
