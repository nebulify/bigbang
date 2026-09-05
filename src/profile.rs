//! Profiles: which store, which account, which vault.
//!
//! Mirrors `blaster:profile`, validated against the same JSON schema the Kotlin CLI ships so a
//! profile written by either binary is accepted by both.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const PROFILE_TYPE: &str = "blaster:profile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "bigbangPath")]
    pub bigbang_path: String,
    #[serde(rename = "accountCode")]
    pub account_code: String,
    #[serde(rename = "databaseName")]
    pub database_name: String,
    #[serde(rename = "libraryPath")]
    pub library_path: String,
    #[serde(rename = "vaultPath")]
    pub vault_path: String,
    #[serde(rename = "defaultVaultName")]
    pub default_vault_name: String,
}

/// Where a bare profile name is looked up. Overridable so a test, or a second set of
/// environments, does not have to live in the home directory.
pub fn profiles_dir() -> PathBuf {
    match std::env::var("BIGBANG_PROFILES_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(Profile::expand(&dir)),
        _ => PathBuf::from(Profile::expand("~/.bigbang/profiles")),
    }
}

impl Profile {
    /// Accepts either a name or a path.
    ///
    /// `colistor` means `~/.bigbang/profiles/colistor.json`; anything containing a separator, or
    /// ending in `.json`, is taken as a path and used as written. Typing the full path for the one
    /// profile you use every day is friction with no purpose, and the two forms are unambiguous:
    /// a profile name is a bare word, and a path is not.
    pub fn resolve(name_or_path: &str) -> PathBuf {
        let trimmed = name_or_path.trim();
        let looks_like_path = trimmed.contains('/')
            || trimmed.starts_with('~')
            || trimmed.ends_with(".json");
        if looks_like_path {
            return PathBuf::from(Self::expand(trimmed));
        }
        profiles_dir().join(format!("{trimmed}.json"))
    }

    /// Every profile name available for the bare-name form.
    pub fn available() -> Vec<String> {
        let dir = profiles_dir();
        let Ok(entries) = fs::read_dir(&dir) else { return Vec::new() };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    /// Resolve then load, with an error that lists the alternatives when a name does not exist —
    /// a bare name is a guess at a filename, so "not found" alone leaves the user guessing twice.
    pub fn open(name_or_path: &str) -> Result<Self> {
        let path = Self::resolve(name_or_path);
        if !path.exists() {
            let available = Self::available();
            if available.is_empty() {
                bail!("no profile at {} (and {} holds none)", path.display(), profiles_dir().display());
            }
            bail!(
                "no profile at {}. Available: {}",
                path.display(),
                available.join(", ")
            );
        }
        Self::load(path)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        let profile: Profile = serde_json::from_str(&raw)
            .with_context(|| format!("parsing profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// The same invariants the Kotlin `init` block enforces, so an invalid profile fails the same
    /// way in either binary rather than only in one.
    pub fn validate(&self) -> Result<()> {
        if self.type_ != PROFILE_TYPE {
            bail!("Invalid profile type: expected '{PROFILE_TYPE}', got '{}'", self.type_);
        }
        if self.name.trim().is_empty() || self.name.len() > 100 {
            bail!("Profile name must be non-blank and at most 100 characters");
        }
        if self.description.trim().is_empty() || self.description.len() > 500 {
            bail!("Profile description must be non-blank and at most 500 characters");
        }
        for (field, value) in [
            ("bigbangPath", &self.bigbang_path),
            ("accountCode", &self.account_code),
            ("databaseName", &self.database_name),
            ("libraryPath", &self.library_path),
            ("vaultPath", &self.vault_path),
            ("defaultVaultName", &self.default_vault_name),
        ] {
            if value.trim().is_empty() {
                bail!("Profile field '{field}' must not be blank");
            }
        }
        Ok(())
    }

    /// `~/…` is expanded the way the Kotlin `expandPath` does — only a leading `~/`, nothing else.
    pub fn expand(path: &str) -> String {
        let trimmed = path.trim();
        match trimmed.strip_prefix("~/") {
            Some(rest) => match std::env::var("HOME") {
                Ok(home) => format!("{home}/{rest}"),
                Err(_) => trimmed.to_string(),
            },
            None => trimmed.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn a_bare_word_resolves_into_the_profiles_directory() {
        std::env::set_var("BIGBANG_PROFILES_DIR", "/profiles");
        assert_eq!(Profile::resolve("colistor"), std::path::PathBuf::from("/profiles/colistor.json"));
        std::env::remove_var("BIGBANG_PROFILES_DIR");
    }

    #[test]
    fn anything_path_shaped_is_used_as_written() {
        std::env::set_var("BIGBANG_PROFILES_DIR", "/profiles");
        for given in ["./colistor.json", "/etc/bigbang/p.json", "sub/dir/p.json", "colistor.json"] {
            let resolved = Profile::resolve(given);
            assert_ne!(resolved, std::path::PathBuf::from("/profiles").join(format!("{given}.json")),
                       "{given} should be treated as a path");
        }
        std::env::remove_var("BIGBANG_PROFILES_DIR");
    }

    #[test]
    fn expand_only_touches_a_leading_tilde_slash() {
        std::env::set_var("HOME", "/home/test");
        assert_eq!(Profile::expand("~/x"), "/home/test/x");
        assert_eq!(Profile::expand("/absolute/~/x"), "/absolute/~/x");
        assert_eq!(Profile::expand("  /trimmed  "), "/trimmed");
    }
}
