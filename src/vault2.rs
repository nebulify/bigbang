//! The authenticated vault format.
//!
//! v1 exists to be byte-compatible with the Kotlin CLI, and that constraint is gone: Kotlin is
//! retired. This format is what the constraint was preventing.
//!
//! ## What v1 got wrong, and it is not the cipher
//!
//! v1 encrypts each secret and leaves everything else in the clear — names, descriptions, and,
//! since the restriction tiers landed, `restriction` and `preparedCommands`. So the security policy
//! itself is a plaintext field anyone with write access can edit: change `prepared` to `none` and
//! the tier evaporates. Per-item encryption would not fix that either, because a policy outside the
//! ciphertext stays malleable and whole items can still be added, removed or swapped.
//!
//! v2 puts the entire item list inside one authenticated envelope. Any edit — a downgraded tier, a
//! renamed item, a deleted one, a reordered list — breaks the tag.
//!
//! ## The four changes, and why each
//!
//! | | v1 | v2 | because |
//! |---|---|---|---|
//! | KDF | PBKDF2-HMAC-SHA256, 120k | Argon2id, 64 MiB, t=3, p=4 | PBKDF2 is cheap to parallelise on GPUs; Argon2id is memory-hard, so an attacker pays in RAM |
//! | Cipher | AES-256-GCM, 96-bit nonce | XChaCha20-Poly1305, 192-bit nonce | a 192-bit nonce is safe to choose at random forever, with no reuse cliff to reason about |
//! | Scope | one secret per ciphertext | the whole item list | names and policy become tamper-evident rather than editable |
//! | Binding | none | header as AAD, plus key commitment | see below |
//!
//! **The header is additional authenticated data.** Rewriting it — weakening the Argon2 parameters,
//! swapping a stored public key, editing the sequence — makes the ciphertext fail to authenticate.
//! Without this an attacker could lower the KDF cost for the *next* write.
//!
//! **The key is committed.** AEADs are not key-committing: a ciphertext can, in principle, decrypt
//! successfully under more than one key, which is what partitioning-oracle attacks against
//! password-based encryption exploit to test many passwords per query. Argon2 emits 64 bytes here;
//! the first 32 are the cipher key and the second 32 are stored in the header and checked first. A
//! wrong password fails on the commitment, and every candidate password costs a full Argon2
//! evaluation.
//!
//! ## What it still does not stop
//!
//! **Rollback.** The store keeps every version, and repointing `vault.rev` at an older file yields
//! a perfectly valid, correctly authenticated vault — one where an item may have been unrestricted.
//! `sequence` increments on every write and a decrease is reported, which catches accidents and
//! casual tampering; it is not proof against someone who can also edit whatever remembers the last
//! sequence. Real protection needs state outside the file: the agent, or a TPM.
//!
//! **Anyone holding the password.** Encryption constrains who can read, never what a legitimate
//! holder may do.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::vault::VaultItem;

pub const FORMAT: &str = "bigbang-vault-2";

/// 64 MiB, three passes, four lanes.
///
/// Above the OWASP floor (19 MiB, t=2) because this is a laptop tool whose unlock happens once per
/// session behind the agent: a few hundred milliseconds is invisible to the person and expensive to
/// anyone testing passwords in bulk. Stored in the header so they can be raised later without
/// stranding existing vaults.
pub const ARGON_MEMORY_KIB: u32 = 65_536;
pub const ARGON_PASSES: u32 = 3;
pub const ARGON_LANES: u32 = 4;

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24; // XChaCha20
const KEY_LENGTH: usize = 32;
const COMMITMENT_LENGTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Kdf {
    pub algorithm: String,
    #[serde(rename = "memoryKiB")]
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub salt: String,
}

/// Everything except the ciphertext. Serialized verbatim as the AEAD's associated data, so none of
/// it can be changed without the ciphertext failing to authenticate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub format: String,
    pub kdf: Kdf,
    pub cipher: String,
    pub nonce: String,
    /// The second half of the KDF output. Checked before any decryption is attempted.
    pub commitment: String,
    /// Increments on every write. A decrease means an older vault has been put back.
    pub sequence: u64,
    /// Data that is published by design — SSH public keys — readable without the password. It is
    /// covered by the AAD, so it can be read freely and not altered freely.
    #[serde(default)]
    pub public: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(flatten)]
    pub header: Header,
    pub ciphertext: String,
}

/// Is this file a v2 envelope? v1 is a bare JSON array, so the two never collide.
pub fn looks_like_v2(raw: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("format").and_then(|f| f.as_str()).map(|s| s == FORMAT))
        .unwrap_or(false)
}

fn derive(password: &str, salt: &[u8], kdf: &Kdf) -> Result<([u8; KEY_LENGTH], [u8; COMMITMENT_LENGTH])> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if kdf.algorithm != "argon2id" {
        bail!("unsupported KDF '{}'", kdf.algorithm);
    }
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(KEY_LENGTH + COMMITMENT_LENGTH))
        .map_err(|e| anyhow::anyhow!("Argon2 parameters rejected: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; KEY_LENGTH + COMMITMENT_LENGTH];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("deriving the vault key: {e}"))?;

    let mut key = [0u8; KEY_LENGTH];
    let mut commitment = [0u8; COMMITMENT_LENGTH];
    key.copy_from_slice(&out[..KEY_LENGTH]);
    commitment.copy_from_slice(&out[KEY_LENGTH..]);
    Ok((key, commitment))
}

/// Encrypt the whole item list under a fresh salt and nonce.
pub fn seal(
    password: &str,
    items: &[VaultItem],
    sequence: u64,
    public: BTreeMap<String, serde_json::Value>,
) -> Result<Envelope> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let kdf = Kdf {
        algorithm: "argon2id".into(),
        memory_kib: ARGON_MEMORY_KIB,
        passes: ARGON_PASSES,
        lanes: ARGON_LANES,
        salt: B64.encode(salt),
    };
    let (key, commitment) = derive(password, &salt, &kdf)?;

    let header = Header {
        format: FORMAT.into(),
        kdf,
        cipher: "xchacha20poly1305".into(),
        nonce: B64.encode(nonce_bytes),
        commitment: B64.encode(commitment),
        sequence,
        public,
    };
    let aad = serde_json::to_vec(&header).context("serialising the header")?;
    let plaintext = serde_json::to_vec(items).context("serialising the vault items")?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("key rejected: {e}"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| anyhow::anyhow!("encrypting the vault"))?;

    Ok(Envelope { header, ciphertext: B64.encode(ciphertext) })
}

/// Decrypt, checking the key commitment before spending effort on the ciphertext.
pub fn open(password: &str, envelope: &Envelope) -> Result<Vec<VaultItem>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    if envelope.header.format != FORMAT {
        bail!("not a {FORMAT} vault: '{}'", envelope.header.format);
    }
    if envelope.header.cipher != "xchacha20poly1305" {
        bail!("unsupported cipher '{}'", envelope.header.cipher);
    }
    let salt = B64.decode(&envelope.header.kdf.salt).context("decoding the salt")?;
    let (key, commitment) = derive(password, &salt, &envelope.header.kdf)?;

    let expected = B64.decode(&envelope.header.commitment).context("decoding the commitment")?;
    // Constant-time: a timing difference here would leak how much of a guess was right.
    if expected.len() != commitment.len() || !constant_time_eq(&expected, &commitment) {
        bail!("wrong password for this vault");
    }

    let nonce = B64.decode(&envelope.header.nonce).context("decoding the nonce")?;
    if nonce.len() != NONCE_LENGTH {
        bail!("nonce is {} bytes, expected {NONCE_LENGTH}", nonce.len());
    }
    let ciphertext = B64.decode(&envelope.ciphertext).context("decoding the ciphertext")?;
    let aad = serde_json::to_vec(&envelope.header).context("serialising the header")?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("key rejected: {e}"))?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad })
        .map_err(|_| {
            anyhow::anyhow!(
                "the vault failed to authenticate — the file has been modified since it was written"
            )
        })?;

    serde_json::from_slice(&plaintext).context("parsing the decrypted vault items")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str) -> VaultItem {
        let mut rest = serde_json::Map::new();
        rest.insert("restriction".into(), serde_json::Value::String("prepared".into()));
        VaultItem {
            id: format!("id-{name}"),
            name: name.into(),
            type_: "SECRET".into(),
            description: Some("a secret".into()),
            encrypted_content: "{}".into(),
            username: None,
            account_id: "colistor".into(),
            project_code: "colistor-int".into(),
            rest,
        }
    }

    fn sealed() -> Envelope {
        seal("correct horse", &[item("a"), item("b")], 1, BTreeMap::new()).unwrap()
    }

    #[test]
    fn a_vault_round_trips() {
        let items = open("correct horse", &sealed()).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "a");
        assert_eq!(items[0].restriction(), crate::vault::Restriction::Prepared);
    }

    #[test]
    fn the_wrong_password_is_refused_by_the_commitment() {
        let err = open("wrong horse", &sealed()).unwrap_err();
        assert!(format!("{err:#}").contains("wrong password"), "{err:#}");
    }

    /// Names and descriptions are inside the envelope, unlike v1 where they were an open index of
    /// which services an organisation uses.
    #[test]
    fn item_names_do_not_appear_in_the_file() {
        let envelope = seal("pw-for-the-test", &[item("stripe_secret_key")], 1, BTreeMap::new()).unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(!encoded.contains("stripe_secret_key"), "the name leaked into the file");
        assert!(!encoded.contains("prepared"), "the policy leaked into the file");
    }

    /// The reason for the format: a policy that can be edited is not a policy.
    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let mut envelope = sealed();
        let mut raw = B64.decode(&envelope.ciphertext).unwrap();
        raw[10] ^= 0x01;
        envelope.ciphertext = B64.encode(raw);
        let err = open("correct horse", &envelope).unwrap_err();
        assert!(format!("{err:#}").contains("authenticate"), "{err:#}");
    }

    #[test]
    fn tampering_with_the_header_is_detected() {
        // The sequence: putting an older vault back and renumbering it.
        let mut envelope = sealed();
        envelope.header.sequence = 99;
        assert!(open("correct horse", &envelope).is_err(), "sequence was not bound");

        // The public section: a swapped SSH public key would send the wrong one to a provider.
        let mut envelope = sealed();
        envelope
            .header
            .public
            .insert("k".into(), serde_json::Value::String("ssh-ed25519 AAAA-attacker".into()));
        assert!(open("correct horse", &envelope).is_err(), "public section was not bound");

        // The KDF cost: weakening it for a later write.
        let mut envelope = sealed();
        envelope.header.kdf.memory_kib = 8;
        assert!(open("correct horse", &envelope).is_err(), "KDF parameters were not bound");
    }

    #[test]
    fn every_write_uses_a_fresh_salt_and_nonce() {
        let a = sealed();
        let b = sealed();
        assert_ne!(a.header.kdf.salt, b.header.kdf.salt);
        assert_ne!(a.header.nonce, b.header.nonce);
        assert_ne!(a.ciphertext, b.ciphertext, "identical content must not produce identical files");
    }

    #[test]
    fn the_public_section_is_readable_without_the_password() {
        let mut public = BTreeMap::new();
        public.insert("int-key".into(), serde_json::json!({"publicKey": "ssh-ed25519 AAAA"}));
        let envelope = seal("pw-for-the-test", &[item("a")], 1, public).unwrap();
        // Parsed straight from the file, no password involved.
        let encoded = serde_json::to_string(&envelope).unwrap();
        let parsed: Envelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            parsed.header.public["int-key"]["publicKey"],
            serde_json::json!("ssh-ed25519 AAAA")
        );
    }

    #[test]
    fn a_v1_file_is_not_mistaken_for_a_v2_one() {
        assert!(!looks_like_v2("[]"));
        assert!(!looks_like_v2(r#"[{"id":"x","name":"y"}]"#));
        assert!(looks_like_v2(&serde_json::to_string(&sealed()).unwrap()));
    }

    #[test]
    fn the_argon_parameters_are_at_least_the_owasp_floor() {
        // 19 MiB and two passes is the published minimum for Argon2id; going below it later would
        // be a silent downgrade, so it is asserted rather than trusted to review.
        assert!(ARGON_MEMORY_KIB >= 19 * 1024, "memory below the OWASP floor");
        assert!(ARGON_PASSES >= 2, "too few passes");
        assert!(ARGON_LANES >= 1);
    }
}
