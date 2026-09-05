//! Profiles: which store, which account, which vault.
//!
//! Mirrors `blaster:profile`, validated against the same JSON schema the Kotlin CLI ships so a
//! profile written by either binary is accepted by both.

use std::fs;
use std::path::Path;

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

impl Profile {
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
    fn expand_only_touches_a_leading_tilde_slash() {
        std::env::set_var("HOME", "/home/test");
        assert_eq!(Profile::expand("~/x"), "/home/test/x");
        assert_eq!(Profile::expand("/absolute/~/x"), "/absolute/~/x");
        assert_eq!(Profile::expand("  /trimmed  "), "/trimmed");
    }
}
