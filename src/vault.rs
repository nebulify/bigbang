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

/// The alphabet generated secrets are drawn from.
///
/// Deliberately alphanumeric. A generated password ends up in a JDBC URL, a connection string, a
/// YAML value and a shell command, and `@`, `:`, `/` and `#` each break at least one of those —
/// usually far from where the password was chosen. Entropy comes from length instead, which is
/// free: 32 of these characters is about 190 bits, well beyond anything the length of a symbol
/// alphabet would buy.
const SECRET_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Special characters `--special` adds.
///
/// Every one of these is unreserved in RFC 3986 or safe as a literal in a quoted shell word. The
/// obvious candidates are missing on purpose: `@` `:` `/` end the userinfo or authority section of
/// a URL and break a JDBC connection string; `$` `` ` `` `\` `"` `'` are interpreted inside double
/// quotes; `!` is history expansion in an interactive shell; `%` collides with URL encoding. A
/// password containing those works until the day it is pasted somewhere that parses it.
pub const SAFE_SPECIALS: &str = "-_.~+=";

/// A random secret, drawn from the OS CSPRNG.
///
/// The point of generating rather than supplying is that the value never exists anywhere else: not
/// in a scratchpad file, not in a shell history, not in a terminal transcript. It goes from the
/// system's entropy source into the vault and stops there.
pub fn generate_secret(length: usize) -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut out = String::with_capacity(length);
    let mut buf = [0u8; 64];
    let n = SECRET_ALPHABET.len() as u8;
    // Rejection sampling: taking a raw byte modulo 62 would make the first few characters of the
    // alphabet slightly likelier than the rest. The bias is small and there is no reason to accept
    // it, so bytes landing in the incomplete final block are discarded.
    let limit = 256u16 - (256u16 % n as u16);
    while out.len() < length {
        OsRng.fill_bytes(&mut buf);
        for byte in buf.iter() {
            if (*byte as u16) < limit {
                out.push(SECRET_ALPHABET[(*byte % n) as usize] as char);
                if out.len() == length {
                    break;
                }
            }
        }
    }
    out
}

/// A secret of a length chosen uniformly in `[min, max]`, over the alphanumerics plus `extra`.
///
/// Two details that a naive version gets wrong:
///
/// * **The length is drawn uniformly too**, so a range is a range rather than a hint. `min == max`
///   gives a fixed length.
/// * **Requested specials are guaranteed to appear.** With six specials in a 68-character alphabet,
///   a 32-character password contains none about 6% of the time. A policy that asks for a symbol
///   and gets one 94% of the time is a policy that fails in production, on a Friday, for one
///   account.
pub fn generate_secret_in_range(min: usize, max: usize, extra: &str) -> Result<String> {
    if min == 0 || max == 0 {
        bail!("length must be positive");
    }
    if min > max {
        bail!("--min-length {min} is greater than --max-length {max}");
    }
    let mut alphabet: Vec<u8> = SECRET_ALPHABET.to_vec();
    for byte in extra.bytes() {
        if byte.is_ascii_whitespace() {
            bail!("whitespace cannot be part of a generated secret");
        }
        if !alphabet.contains(&byte) {
            alphabet.push(byte);
        }
    }

    let length = if min == max { min } else { min + uniform_below(max - min + 1) };
    let mut chars: Vec<u8> = (0..length).map(|_| alphabet[uniform_below(alphabet.len())]).collect();

    // Guarantee at least one of each requested special, placed at distinct random positions.
    let specials: Vec<u8> = extra.bytes().collect();
    if !specials.is_empty() {
        if length < specials.len() {
            bail!(
                "cannot guarantee {} special character(s) in a secret of length {length}",
                specials.len()
            );
        }
        let mut used: Vec<usize> = Vec::new();
        for special in &specials {
            // Reserve the position when a special is already there by chance. Merely skipping
            // meant a later special could be written over it, quietly undoing the guarantee for
            // the first one — which is what the test caught.
            if let Some(found) = chars
                .iter()
                .enumerate()
                .find(|(i, c)| *c == special && !used.contains(i))
                .map(|(i, _)| i)
            {
                used.push(found);
                continue;
            }
            let mut position = uniform_below(length);
            while used.contains(&position) {
                position = uniform_below(length);
            }
            chars[position] = *special;
            used.push(position);
        }
    }

    Ok(String::from_utf8(chars).expect("alphabet is ASCII"))
}

/// A uniform value in `0..n`, rejection-sampled for the same reason the alphabet is.
fn uniform_below(n: usize) -> usize {
    use rand::rngs::OsRng;
    use rand::RngCore;
    assert!(n > 0);
    if n == 1 {
        return 0;
    }
    let limit = u32::MAX - (u32::MAX % n as u32);
    loop {
        let value = OsRng.next_u32();
        if value < limit {
            return (value % n as u32) as usize;
        }
    }
}

/// An Ed25519 keypair: the private half for the vault, the public half for whoever needs it.
///
/// Ed25519 rather than RSA because OpenSSH, OVH and every cloud provider that matters accept it,
/// the keys are short, and there is no key size to get wrong.
///
/// Generated in memory. `ssh-keygen` would have been fewer lines and would have written the private
/// key to a file first, which is exactly the exposure this feature exists to remove.
pub fn generate_ssh_key(comment: &str) -> Result<(String, String)> {
    use ssh_key::{rand_core::OsRng as SshOsRng, Algorithm, LineEnding, PrivateKey};

    let mut key = PrivateKey::random(&mut SshOsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("generating an Ed25519 key: {e}"))?;
    key.set_comment(comment);

    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encoding the private key: {e}"))?
        .to_string();
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("encoding the public key: {e}"))?;
    Ok((private, public))
}
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

/// Which on-disk format a vault is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The Kotlin-compatible format: item list in the clear, each secret encrypted separately.
    V1,
    /// One authenticated envelope over everything.
    V2,
    /// Nothing on disk yet. New vaults are written as v2.
    New,
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

    /// Which format the vault on disk is in.
    pub fn format(&self) -> Result<Format> {
        match self.read_raw()? {
            None => Ok(Format::New),
            Some(raw) if crate::vault2::looks_like_v2(&raw) => Ok(Format::V2),
            Some(_) => Ok(Format::V1),
        }
    }

    fn read_raw(&self) -> Result<Option<String>> {
        let pointer = self.project_dir().join("vault.rev");
        if !pointer.exists() {
            return Ok(None);
        }
        let name = fs::read_to_string(&pointer)
            .with_context(|| format!("reading {}", pointer.display()))?;
        let version_file = self.versions_dir().join(name.trim());
        Ok(Some(fs::read_to_string(&version_file)
            .with_context(|| format!("reading {}", version_file.display()))?))
    }

    /// The v2 header, readable without a password. `None` for a v1 or absent vault.
    pub fn envelope(&self) -> Result<Option<crate::vault2::Envelope>> {
        match self.read_raw()? {
            Some(raw) if crate::vault2::looks_like_v2(&raw) => {
                Ok(Some(serde_json::from_str(&raw).context("parsing the vault envelope")?))
            }
            _ => Ok(None),
        }
    }

    /// The items, decrypting the envelope when the vault is v2.
    ///
    /// v1 leaves the item list in the clear and encrypts each secret separately, so it can be read
    /// without a password. v2 cannot, by design — the names and the policy are inside the envelope.
    pub fn read_items_with(&self, password: Option<&str>) -> Result<Vec<VaultItem>> {
        let Some(raw) = self.read_raw()? else { return Ok(Vec::new()) };
        if crate::vault2::looks_like_v2(&raw) {
            let envelope: crate::vault2::Envelope =
                serde_json::from_str(&raw).context("parsing the vault envelope")?;
            let Some(password) = password else {
                bail!(
                    "this vault is encrypted whole, so listing it needs the password — that is the \
                     point of the format. Unlock it once with: bigbang vault unlock"
                );
            };
            return crate::vault2::open(password, &envelope);
        }
        serde_json::from_str(&raw).context("parsing the vault items")
    }


    pub fn get(&self, item_name: &str, password: &str) -> Result<Option<String>> {
        let items = self.read_items_with(Some(password))?;
        let Some(item) = items.iter().find(|i| i.name == item_name) else {
            return Ok(None);
        };
        let payload: EncryptedPayload = serde_json::from_str(&item.encrypted_content)
            .with_context(|| format!("parsing the encrypted payload of '{item_name}'"))?;
        Ok(Some(decrypt(password, &payload)?))
    }

    /// Names and types, for a v1 vault only.
    ///
    /// v2 keeps names inside the envelope, so there is nothing to list without the password. The
    /// method is deliberately not a convenience wrapper over a password-less read: that wrapper
    /// existed, and four call sites used it against v2 vaults where it could only ever fail —
    /// `vault unlock`, `vault get`, `vault add` and the SSH key resolver. Removing it turned each
    /// of those from a runtime message into a compile error.
    pub fn list(&self) -> Result<Vec<(String, String)>> {
        Ok(self.read_items_with(None)?.into_iter().map(|i| (i.name, i.type_)).collect())
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
    fn a_generated_secret_has_the_requested_length_and_a_safe_alphabet() {
        for len in [16usize, 32, 64, 100] {
            let s = generate_secret(len);
            assert_eq!(s.chars().count(), len, "length {len}");
            assert!(
                s.chars().all(|c| c.is_ascii_alphanumeric()),
                "a generated secret ends up in JDBC URLs, YAML and shell commands: {s}"
            );
        }
    }

    #[test]
    fn generated_secrets_do_not_repeat() {
        let a = generate_secret(32);
        let b = generate_secret(32);
        assert_ne!(a, b);
        // A stuck source would produce one character repeated; catch that rather than trust it.
        assert!(a.chars().collect::<std::collections::BTreeSet<_>>().len() > 8, "{a}");
    }

    /// The rejection sampling exists to stop the first characters of the alphabet being likelier
    /// than the rest. 62 does not divide 256, so `byte % 62` would favour 'A'..'H' by about 8%.
    #[test]
    fn the_alphabet_is_drawn_uniformly() {
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        let sample = generate_secret(62 * 2000);
        for c in sample.chars() {
            *counts.entry(c).or_default() += 1;
        }
        assert_eq!(counts.len(), 62, "every character should appear at this sample size");
        let expected = (62 * 2000) as f64 / 62.0;
        let (min, max) = (
            *counts.values().min().unwrap() as f64,
            *counts.values().max().unwrap() as f64,
        );
        // The bounds come from the arithmetic, not from taste. 256 % 62 == 8, so without
        // rejection the bytes 248..=255 fold onto the first eight characters and make them 5/4 —
        // 21% — likelier than the rest. At this sample size one standard deviation is about 2.2%,
        // so a ±12% window is roughly 5 sigma of noise (a flake is vanishingly unlikely) while
        // still sitting well inside the 21% a biased implementation would produce.
        //
        // An earlier version of this test used ±30% and passed happily against exactly that bug.
        assert!(min > expected * 0.88, "under-represented character: {min} vs {expected}");
        assert!(max < expected * 1.12, "over-represented character: {max} vs {expected}");
    }

    #[test]
    fn a_length_range_produces_lengths_across_the_whole_range() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..400 {
            let s = generate_secret_in_range(16, 24, "").unwrap();
            assert!((16..=24).contains(&s.len()), "out of range: {}", s.len());
            seen.insert(s.len());
        }
        // A "range" that always returns the minimum would satisfy the bounds check above.
        assert!(seen.len() >= 8, "lengths seen: {seen:?}");
        assert!(seen.contains(&16) && seen.contains(&24), "endpoints unreachable: {seen:?}");

        // min == max is an exact length, not a range.
        assert_eq!(generate_secret_in_range(20, 20, "").unwrap().len(), 20);
    }

    /// Six specials in a 68-character alphabet means a 32-character secret contains none about 6%
    /// of the time. "Usually has a symbol" is not what a password policy means.
    #[test]
    fn every_requested_special_actually_appears() {
        for _ in 0..300 {
            let s = generate_secret_in_range(20, 20, SAFE_SPECIALS).unwrap();
            for special in SAFE_SPECIALS.chars() {
                assert!(s.contains(special), "{special:?} missing from {s}");
            }
            assert_eq!(s.len(), 20, "guaranteeing specials must not change the length");
        }
    }

    #[test]
    fn generation_refuses_what_it_cannot_deliver() {
        assert!(generate_secret_in_range(24, 16, "").is_err(), "min > max");
        assert!(generate_secret_in_range(0, 10, "").is_err(), "zero length");
        // Six specials cannot be guaranteed in four characters.
        assert!(generate_secret_in_range(4, 4, SAFE_SPECIALS).is_err());
        assert!(generate_secret_in_range(16, 16, "a b").is_err(), "whitespace");
    }

    #[test]
    fn the_safe_specials_are_safe_where_passwords_end_up() {
        // Each of these breaks a URL, a connection string or a quoted shell word.
        for bad in ['@', ':', '/', '$', '`', '\\', '"', '\'', '!', '%', '#', '?', '&'] {
            assert!(!SAFE_SPECIALS.contains(bad), "{bad:?} must not be in the default set");
        }
    }

    #[test]
    fn a_generated_ssh_key_is_a_usable_openssh_pair() {
        let (private, public) = generate_ssh_key("int@colistor").unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"), "{private:.40}");
        assert!(private.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(public.starts_with("ssh-ed25519 "), "{public}");
        assert!(public.trim_end().ends_with("int@colistor"), "comment missing: {public}");

        // The marker list resolve_ssh_key checks before handing a key to ssh.
        assert!(crate::infra::KEY_MARKERS.iter().any(|m| private.trim_start().starts_with(m)),
            "a generated key must be one resolve_ssh_key will accept");

        // Two calls must not produce the same key.
        let (_, other) = generate_ssh_key("int@colistor").unwrap();
        assert_ne!(public, other);
    }

    #[test]
    fn a_generated_ssh_key_survives_the_vault_round_trip() {
        let (private, _) = generate_ssh_key("round-trip").unwrap();
        let payload = encrypt("pw", &private).unwrap();
        assert_eq!(decrypt("pw", &payload).unwrap(), private);
    }

    #[test]
    fn a_generated_secret_survives_the_round_trip_it_will_actually_take() {
        let secret = generate_secret(32);
        let payload = encrypt("pw", &secret).unwrap();
        assert_eq!(decrypt("pw", &payload).unwrap(), secret);
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
    /// Returns the new item's id, so a caller storing it in a variable records the identity the
    /// vault actually assigned rather than echoing back the name it was given.
    pub fn add(&self, name: &str, type_: &str, description: Option<&str>, plain_text: &str, password: &str) -> Result<String> {
        self.add_with_metadata(name, type_, description, plain_text, password, None)
    }

    /// As `add`, with extra unencrypted fields stored beside the item.
    ///
    /// Used for the public half of a generated keypair. A public key is not a secret and is far
    /// more useful readable — it has to be handed to a cloud provider, and needing the vault
    /// password to read out something that is published by design would be theatre.
    pub fn add_with_metadata(
        &self,
        name: &str,
        type_: &str,
        description: Option<&str>,
        plain_text: &str,
        password: &str,
        metadata: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<String> {
        let mut items = self.read_items_with(Some(password))?;
        if items.iter().any(|i| i.name == name) {
            bail!("Vault item already exists: {name}");
        }

        let payload = encrypt(password, plain_text)?;
        let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let mut rest = serde_json::Map::new();
        rest.insert("createdAt".into(), serde_json::Value::String(now.clone()));
        rest.insert("updatedAt".into(), serde_json::Value::String(now));
        if let Some(extra) = metadata {
            for (k, v) in extra {
                rest.insert(k, v);
            }
        }

        let id = uuid::Uuid::new_v4().to_string();
        items.push(VaultItem {
            id: id.clone(),
            name: name.to_string(),
            type_: type_.to_string(),
            description: description.map(str::to_string),
            encrypted_content: serde_json::to_string(&payload)?,
            username: None,
            account_id: self.account_id.clone(),
            project_code: self.project_code.clone(),
            rest,
        });

        self.write_items_in_format(&items, password)?;
        Ok(id)
    }

    /// Write the item list in whichever format this vault already uses.
    ///
    /// A vault does not silently change format: a v1 vault stays v1 until `vault migrate` says
    /// otherwise, and only a vault that does not exist yet is created as v2. Rewriting someone's
    /// vault into a format their other tools cannot read, as a side effect of adding an item, is
    /// not a thing a credential store should do.
    fn write_items_in_format(&self, items: &[VaultItem], password: &str) -> Result<()> {
        match self.format()? {
            Format::V1 => self.write_items(items),
            Format::V2 | Format::New => self.write_envelope(items, password),
        }
    }

    /// Seal the whole list, carrying the sequence forward and hoisting public keys into the header.
    pub fn write_envelope(&self, items: &[VaultItem], password: &str) -> Result<()> {
        let sequence = self.envelope()?.map(|e| e.header.sequence + 1).unwrap_or(1);

        // Public keys are published by design; keeping a copy in the header is what lets one be
        // read — and handed to a provider — without the password. It is covered by the AAD, so it
        // can be read freely and not altered freely.
        let mut public = std::collections::BTreeMap::new();
        for item in items {
            if let Some(key) = item.rest.get("publicKey") {
                public.insert(item.name.clone(), key.clone());
            }
        }

        let envelope = crate::vault2::seal(password, items, sequence, public)?;
        let encoded = serde_json::to_string_pretty(&envelope)?;
        self.write_version(&encoded)
    }

    fn write_items(&self, items: &[VaultItem]) -> Result<()> {
        let encoded = serde_json::to_string_pretty(items)?;
        self.write_version(&encoded)
    }

    fn write_version(&self, encoded: &str) -> Result<()> {
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

// ── restriction tiers ──────────────────────────────────────────────────────────

/// How much an unlocked item may be used for.
///
/// The tiers exist because credentials are not equally dangerous. An int database password whose
/// blast radius is a throwaway VPS does not need the ceremony that a credential with no test
/// equivalent does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Restriction {
    /// The credential as data: readable, fetchable, substitutable into any command.
    #[default]
    None,
    /// The credential as a capability. Never substituted into a command the caller composed, never
    /// printed by `vault get`; usable only through the prepared commands stored beside it.
    Prepared,
    /// No delegation. The agent will not hold it, so every use costs a password prompt.
    Always,
}

impl Restriction {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Ok(Restriction::None),
            "prepared" => Ok(Restriction::Prepared),
            "always" => Ok(Restriction::Always),
            other => bail!("unknown restriction '{other}' — expected none, prepared or always"),
        }
    }
}

/// A command whose *structure* comes from the vault and whose values come from the caller.
///
/// The prepared-statement property: the caller supplies parameters, never syntax. `{{self}}` is the
/// item's own secret and `{{param:name}}` a declared parameter; nothing else is substituted, and
/// the result is never rescanned, so a parameter cannot introduce a placeholder of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCommand {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// argv, as discrete elements. There is no shell, so a parameter cannot become syntax.
    pub argv: Vec<String>,
    /// Written to the child's stdin. `{{self}}` here is how a secret reaches a tool without
    /// touching argv or the environment — `docker login --password-stdin` is the shape.
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub env: BTreeMapString,
    /// Parameters the caller may supply. Anything else is refused.
    #[serde(default)]
    pub params: Vec<String>,
    /// Whether the child's output comes back at all. Some tools echo what they were given.
    #[serde(rename = "returnsOutput", default = "default_true")]
    pub returns_output: bool,
}

type BTreeMapString = std::collections::BTreeMap<String, String>;

fn default_true() -> bool {
    true
}

impl VaultItem {
    pub fn restriction(&self) -> Restriction {
        self.rest
            .get("restriction")
            .and_then(|v| v.as_str())
            .and_then(|s| Restriction::parse(s).ok())
            .unwrap_or_default()
    }

    pub fn prepared_commands(&self) -> Vec<PreparedCommand> {
        self.rest
            .get("preparedCommands")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }
}
