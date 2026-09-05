//! The on-disk object store, as the Kotlin implementation writes it.
//!
//! Layout, verified against a store produced by the Kotlin CLI rather than read off its source:
//!
//! ```text
//! <base>/<account>/<db>/<type>/<name>.rev
//! <base>/<account>/<db>/<type>/<name>/20260905-213315-644-t0-<name>.json
//! ```
//!
//! The `.rev` file holds one line: the payload's path relative to the type directory. Reading the
//! latest version therefore means reading the pointer and following it — never listing the
//! directory and sorting, which would pick a different file the moment two versions share a
//! timestamp.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const TYPE_RECIPE: &str = "recipe";

/// Where a store lives, and under which account and database.
#[derive(Debug, Clone)]
pub struct RepoDb {
    pub base_path: PathBuf,
    pub account_code: String,
    pub database_name: String,
}

impl RepoDb {
    pub fn new(base_path: impl Into<PathBuf>, account_code: impl Into<String>, database_name: impl Into<String>) -> Self {
        Self { base_path: base_path.into(), account_code: account_code.into(), database_name: database_name.into() }
    }

    pub fn root(&self) -> PathBuf {
        self.base_path.join(&self.account_code).join(&self.database_name)
    }

    pub fn type_dir(&self, object_type: &str) -> PathBuf {
        self.root().join(object_type)
    }

    /// `<type>/<name>.rev`
    pub fn pointer_path(&self, object_type: &str, name: &str) -> PathBuf {
        self.type_dir(object_type).join(format!("{}.rev", safe_name(name)))
    }

    /// Every object of a type, by name, sorted — one entry per pointer file.
    pub fn list_names(&self, object_type: &str) -> Result<Vec<String>> {
        let dir = self.type_dir(object_type);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) == Some("rev") {
                    path.file_stem().and_then(|s| s.to_str()).map(str::to_owned)
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// The newest payload for one object, followed through its pointer.
    pub fn read_latest(&self, object_type: &str, name: &str) -> Result<Option<serde_json::Value>> {
        let pointer = self.pointer_path(object_type, name);
        if !pointer.exists() {
            return Ok(None);
        }
        let target = fs::read_to_string(&pointer)
            .with_context(|| format!("reading pointer {}", pointer.display()))?;
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("pointer {} is empty", pointer.display());
        }
        let payload_path = self.type_dir(object_type).join(target);
        let raw = fs::read_to_string(&payload_path)
            .with_context(|| format!("pointer {} names {}, which is missing", pointer.display(), payload_path.display()))?;
        let value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", payload_path.display()))?;
        Ok(Some(value))
    }

    pub fn exists(&self, object_type: &str, name: &str) -> bool {
        self.pointer_path(object_type, name).exists()
    }
}

/// Kotlin: `s.replace(Regex("[^a-zA-Z0-9._-]"), "-")`. Reproduced exactly — a name that sanitises
/// differently would address a different file and quietly split one object into two.
pub fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '-' })
        .collect()
}

/// Path helper used by callers that need the type directory without constructing a `RepoDb`.
pub fn type_dir_of(root: &Path, object_type: &str) -> PathBuf {
    root.join(object_type)
}

#[cfg(test)]
mod tests {
    use super::safe_name;

    #[test]
    fn sanitising_matches_the_kotlin_regex() {
        assert_eq!(safe_name("create-colistor-schema-recipe"), "create-colistor-schema-recipe");
        assert_eq!(safe_name("a.b_c-d"), "a.b_c-d");
        assert_eq!(safe_name("with space"), "with-space");
        assert_eq!(safe_name("slash/and:colon"), "slash-and-colon");
        // Kotlin's Regex replaces per char, not per byte, so one non-ASCII char is one dash.
        assert_eq!(safe_name("café"), "caf-");
    }
}

// ── writing ────────────────────────────────────────────────────────────────────

use chrono::Local;
use rand::Rng;

impl RepoDb {
    /// Store a new version and point at it.
    ///
    /// Order matters and is not incidental: the payload is written and flushed first, then the
    /// pointer is swapped by an atomic rename. A crash between the two leaves an unreferenced
    /// payload, which is inert; the reverse order would leave a pointer naming a file that does
    /// not exist, which is a store that fails to read.
    pub fn write(&self, object_type: &str, name: &str, data: &serde_json::Value) -> Result<PathBuf> {
        let safe = safe_name(name);
        let object_dir = self.type_dir(object_type).join(&safe);
        fs::create_dir_all(&object_dir)
            .with_context(|| format!("creating {}", object_dir.display()))?;

        let file_name = version_file_name(&safe);
        let payload_path = object_dir.join(&file_name);

        // Compact, matching Jackson's default writer — the Kotlin store holds one line per object.
        let encoded = serde_json::to_string(data)?;
        fs::write(&payload_path, encoded.as_bytes())
            .with_context(|| format!("writing {}", payload_path.display()))?;

        let relative = format!("{safe}/{file_name}");
        self.write_pointer(object_type, &safe, &relative)?;
        Ok(payload_path)
    }

    /// temp + atomic rename, so a reader never observes a half-written pointer.
    fn write_pointer(&self, object_type: &str, safe: &str, relative: &str) -> Result<()> {
        let dir = self.type_dir(object_type);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let pointer = dir.join(format!("{safe}.rev"));
        let tmp = dir.join(format!("{safe}.rev.tmp"));
        fs::write(&tmp, relative.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &pointer)
            .with_context(|| format!("swapping {}", pointer.display()))?;
        Ok(())
    }
}

/// `yyyyMMdd-HHmmss-SSS-<2 base36 chars>-<name>.json`, local time, matching RepoDbPath.
///
/// The two random characters exist because the millisecond stamp alone collides when a directory
/// of recipes installs in one pass — several of them land in the same millisecond.
fn version_file_name(safe: &str) -> String {
    let ts = Local::now().format("%Y%m%d-%H%M%S-%3f");
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let rand: String = (0..2)
        .map(|_| ALPHABET[rng.gen_range(0..36)] as char)
        .collect();
    format!("{ts}-{rand}-{safe}.json")
}

#[cfg(test)]
mod write_tests {
    use super::*;

    #[test]
    fn version_names_match_the_kotlin_shape() {
        let name = version_file_name("my-recipe");
        // 20260905-213315-643-t0-my-recipe.json
        let re_ok = name.len() > "20260905-213315-643-t0-".len()
            && name.ends_with("-my-recipe.json")
            && name.chars().take(8).all(|c| c.is_ascii_digit())
            && name.as_bytes()[8] == b'-';
        assert!(re_ok, "unexpected version file name: {name}");
    }

    #[test]
    fn write_then_read_round_trips_through_the_pointer() {
        let dir = std::env::temp_dir().join(format!("bigbang-rs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = RepoDb::new(&dir, "acct", "db");
        let value = serde_json::json!({"id": "x", "name": "x"});
        store.write(TYPE_RECIPE, "x", &value).expect("write");
        let read = store.read_latest(TYPE_RECIPE, "x").expect("read").expect("present");
        assert_eq!(read, value);
        assert_eq!(store.list_names(TYPE_RECIPE).unwrap(), vec!["x".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }
}
