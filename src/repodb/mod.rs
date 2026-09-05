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
