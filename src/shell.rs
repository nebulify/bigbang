//! Interactive mode: one profile loaded, one password typed, many commands.
//!
//! The value is entirely in the session state. Outside the shell every command needs
//! `--profile <path>` and every vault read needs the password again; inside, both are held once.
//! Which also means the shell holds a decrypted secret in memory for as long as it runs — hence
//! [`CachedPassword`], which wipes itself on drop and refuses to print itself.

use std::collections::HashMap;

use anyhow::Result;
use zeroize::Zeroize;

use crate::profile::Profile;

/// A vault password held for the life of a session.
///
/// `Debug` is implemented by hand: the derived one would print the password into any log line that
/// formatted the session, which is exactly the accident worth designing out rather than
/// remembering to avoid.
pub struct CachedPassword(String);

impl CachedPassword {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for CachedPassword {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for CachedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedPassword(<redacted>)")
    }
}

#[derive(Debug, Default)]
pub struct Session {
    pub profile: Option<Profile>,
    pub profile_path: Option<String>,
    passwords: HashMap<String, CachedPassword>,
}

impl Session {
    /// Takes a profile name or a path — the same resolution the command line uses, so the two
    /// never disagree about what `colistor` means.
    pub fn load_profile(&mut self, name_or_path: &str) -> Result<()> {
        let profile = Profile::open(name_or_path)?;
        println!("✓ Profile '{}' loaded", profile.name);
        self.profile = Some(profile);
        self.profile_path = Some(name_or_path.to_string());
        Ok(())
    }

    pub fn cached_password(&self, vault_path: &str) -> Option<&str> {
        self.passwords.get(vault_path).map(CachedPassword::as_str)
    }

    pub fn cache_password(&mut self, vault_path: &str, password: String) {
        self.passwords.insert(vault_path.to_string(), CachedPassword::new(password));
    }

    pub fn clear_passwords(&mut self) {
        self.passwords.clear();
    }

    /// Shows which environment the next command will touch — worth the space, because the same
    /// words target a scratch project or production depending on this one value.
    pub fn prompt(&self) -> String {
        match &self.profile {
            Some(p) => format!("bigbang[{}]> ", p.name),
            None => "bigbang> ".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_names_the_loaded_profile() {
        let mut session = Session::default();
        assert_eq!(session.prompt(), "bigbang> ");
        session.profile = Some(Profile {
            type_: "blaster:profile".into(),
            name: "production".into(),
            description: "d".into(),
            bigbang_path: "/b".into(),
            account_code: "a".into(),
            database_name: "db".into(),
            library_path: "/l".into(),
            vault_path: "/v".into(),
            default_vault_name: "v".into(),
        });
        assert_eq!(session.prompt(), "bigbang[production]> ");
    }

    #[test]
    fn a_cached_password_is_returned_for_its_own_vault_only() {
        let mut session = Session::default();
        session.cache_password("/vault/a", "pw".into());
        assert_eq!(session.cached_password("/vault/a"), Some("pw"));
        assert_eq!(session.cached_password("/vault/b"), None);
        session.clear_passwords();
        assert_eq!(session.cached_password("/vault/a"), None);
    }

    #[test]
    fn a_password_never_appears_in_debug_output() {
        // A derived Debug would put the secret into any log line that formatted the session.
        let cached = CachedPassword::new("hunter2".into());
        let rendered = format!("{cached:?}");
        assert!(!rendered.contains("hunter2"), "password leaked into Debug: {rendered}");
        let session = Session { passwords: HashMap::from([("v".into(), CachedPassword::new("hunter2".into()))]), ..Default::default() };
        assert!(!format!("{session:?}").contains("hunter2"));
    }
}
