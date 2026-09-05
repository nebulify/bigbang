//! The vault: PBKDF2 into AES-GCM, in the format the Kotlin CLI writes.
//!
//! Parity here is not a nicety. A vault this binary cannot read is a vault the deployment cannot
//! read, and the failure would arrive mid-deploy. Every parameter below is taken from
//! `CryptoUtil.kt` and must not be "improved":
//!
//! | | |
//! |---|---|
//! | KDF | PBKDF2WithHmacSHA256, 120_000 iterations, 256-bit output |
//! | Cipher | AES-256-GCM, 128-bit tag |
//! | IV | 12 bytes, random per encryption |
//! | Salt | 16 bytes, random per encryption |
//! | Encoding | base64 (standard alphabet, padded) for ciphertext, salt and IV |
//!
//! Java appends the GCM tag to the ciphertext, which is also what `aes-gcm` produces, so the
//! ciphertext bytes are directly interchangeable.
//!
//! On-disk layout, observed from a vault the Kotlin CLI wrote:
//!
//! ```text
//! <vault>/<account>/<project>/vault.rev                         pointer, a bare filename
//! <vault>/<account>/<project>/.vault-versions/<ts>-<n>-vault.json   pretty-printed array of items
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

const ITERATIONS: u32 = 120_000;
const KEY_LENGTH: usize = 32; // 256 bits
const IV_LENGTH: usize = 12;
const SALT_LENGTH: usize = 16;

/// The JSON stored in `VaultItem.encryptedContent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    #[serde(rename = "cipherText")]
    pub cipher_text: String,
    #[serde(rename = "saltB64")]
    pub salt_b64: String,
    #[serde(rename = "ivB64")]
    pub iv_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Holds an `EncryptedPayload` as a JSON *string*, not an object — the Kotlin code serialises
    /// the payload and assigns the text to this field.
    #[serde(rename = "encryptedContent")]
    pub encrypted_content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "projectCode")]
    pub project_code: String,
    /// Anything else the Kotlin model carries is preserved verbatim, so a round trip through this
    /// binary never drops a field it does not model.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, ITERATIONS, &mut key);
    key
}

pub fn decrypt(password: &str, payload: &EncryptedPayload) -> Result<String> {
    let salt = B64.decode(&payload.salt_b64).context("decoding salt")?;
    let iv = B64.decode(&payload.iv_b64).context("decoding iv")?;
    let cipher_text = B64.decode(&payload.cipher_text).context("decoding ciphertext")?;
    if iv.len() != IV_LENGTH {
        bail!("expected a {IV_LENGTH}-byte IV, got {}", iv.len());
    }
    let key = derive_key(password.as_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).context("building the cipher")?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &cipher_text, aad: b"" })
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password, or the item is corrupt"))?;
    String::from_utf8(plain).context("the decrypted value is not UTF-8")
}

pub fn encrypt(password: &str, plain_text: &str) -> Result<EncryptedPayload> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LENGTH];
    let mut iv = [0u8; IV_LENGTH];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let key = derive_key(password.as_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).context("building the cipher")?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plain_text.as_bytes(), aad: b"" })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    Ok(EncryptedPayload {
        cipher_text: B64.encode(encrypted),
        salt_b64: B64.encode(salt),
        iv_b64: B64.encode(iv),
    })
}

/// Where one project's items live.
pub struct Vault {
    pub root: PathBuf,
    pub account_id: String,
    pub project_code: String,
}

impl Vault {
    pub fn new(root: impl Into<PathBuf>, account_id: impl Into<String>, project_code: impl Into<String>) -> Self {
        Self { root: root.into(), account_id: account_id.into(), project_code: project_code.into() }
    }

    fn project_dir(&self) -> PathBuf {
        self.root.join(&self.account_id).join(&self.project_code)
    }

    fn versions_dir(&self) -> PathBuf {
        self.project_dir().join(".vault-versions")
    }

    pub fn read_items(&self) -> Result<Vec<VaultItem>> {
        let pointer = self.project_dir().join("vault.rev");
        if !pointer.exists() {
            return Ok(Vec::new());
        }
        // The vault pointer holds a bare filename, resolved under .vault-versions — unlike the
        // RepoDB pointer, which holds a path relative to the type directory.
        let name = fs::read_to_string(&pointer)
            .with_context(|| format!("reading {}", pointer.display()))?;
        let version_file = self.versions_dir().join(name.trim());
        let raw = fs::read_to_string(&version_file)
            .with_context(|| format!("reading {}", version_file.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", version_file.display()))
    }

    pub fn get(&self, item_name: &str, password: &str) -> Result<Option<String>> {
        let items = self.read_items()?;
        let Some(item) = items.iter().find(|i| i.name == item_name) else {
            return Ok(None);
        };
        let payload: EncryptedPayload = serde_json::from_str(&item.encrypted_content)
            .with_context(|| format!("parsing the encrypted payload of '{item_name}'"))?;
        Ok(Some(decrypt(password, &payload)?))
    }

    pub fn list(&self) -> Result<Vec<(String, String)>> {
        Ok(self.read_items()?.into_iter().map(|i| (i.name, i.type_)).collect())
    }

    pub fn path_of(root: &Path, account: &str, project: &str) -> PathBuf {
        root.join(account).join(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let payload = encrypt("pw", "hello").unwrap();
        assert_eq!(decrypt("pw", &payload).unwrap(), "hello");
    }

    #[test]
    fn a_wrong_password_fails_rather_than_returning_rubbish() {
        let payload = encrypt("pw", "hello").unwrap();
        assert!(decrypt("not-pw", &payload).is_err());
    }

    #[test]
    fn salt_and_iv_are_fresh_each_time() {
        let a = encrypt("pw", "hello").unwrap();
        let b = encrypt("pw", "hello").unwrap();
        assert_ne!(a.salt_b64, b.salt_b64);
        assert_ne!(a.iv_b64, b.iv_b64);
        assert_ne!(a.cipher_text, b.cipher_text);
    }
}

// ── writing ────────────────────────────────────────────────────────────────────

use chrono::Local;

impl Vault {
    /// Add an item, refusing to replace one that exists.
    ///
    /// The whole item list is rewritten as a new version and the pointer swapped, because that is
    /// what the Kotlin implementation does — versions are per-vault, not per-item. Reading the
    /// existing items first therefore matters: writing only the new one would silently drop every
    /// other secret in the project.
    pub fn add(&self, name: &str, type_: &str, description: Option<&str>, plain_text: &str, password: &str) -> Result<()> {
        let mut items = self.read_items()?;
        if items.iter().any(|i| i.name == name) {
            bail!("Vault item already exists: {name}");
        }

        let payload = encrypt(password, plain_text)?;
        let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let mut rest = serde_json::Map::new();
        rest.insert("createdAt".into(), serde_json::Value::String(now.clone()));
        rest.insert("updatedAt".into(), serde_json::Value::String(now));

        items.push(VaultItem {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            type_: type_.to_string(),
            description: description.map(str::to_string),
            encrypted_content: serde_json::to_string(&payload)?,
            username: None,
            account_id: self.account_id.clone(),
            project_code: self.project_code.clone(),
            rest,
        });

        self.write_items(&items)
    }

    fn write_items(&self, items: &[VaultItem]) -> Result<()> {
        let versions = self.versions_dir();
        fs::create_dir_all(&versions).with_context(|| format!("creating {}", versions.display()))?;

        // yyyyMMdd-HHmmss-<100..999>-vault.json, matching FileBasedVaultStorage.
        let stamp = Local::now().format("%Y%m%d-%H%M%S");
        let n: u16 = {
            use rand::Rng;
            rand::thread_rng().gen_range(100..1000)
        };
        let file_name = format!("{stamp}-{n}-vault.json");
        let version_file = versions.join(&file_name);

        // Pretty-printed, as writerWithDefaultPrettyPrinter produces.
        let encoded = serde_json::to_string_pretty(items)?;
        fs::write(&version_file, encoded.as_bytes())
            .with_context(|| format!("writing {}", version_file.display()))?;

        // Payload first, pointer second, and the pointer holds a bare filename here.
        let project = self.project_dir();
        let pointer = project.join("vault.rev");
        let tmp = project.join("vault.rev.tmp");
        fs::write(&tmp, file_name.as_bytes())?;
        fs::rename(&tmp, &pointer).with_context(|| format!("swapping {}", pointer.display()))?;
        Ok(())
    }
}
