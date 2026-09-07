//! Installing recipes: read a file or a directory, validate, store.
//!
//! Mirrors the Kotlin command's outcome model, because CI depends on the exit codes it produces:
//! an error fails, and so does installing nothing at all. The second case is not pedantry — eight
//! of this repository's ten recipes once lacked a `type` field, were counted as "ignored", and the
//! command exited 0 while installing two.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::repodb::{RepoDb, TYPE_RECIPE};

pub const RECIPE_TYPE: &str = "blaster:recipe";

/// The schema ships in the binary — same file the Kotlin CLI loads from its resources.
const RECIPE_SCHEMA: &str = include_str!("recipe-schema.json");

#[derive(Debug, Default, PartialEq, Eq)]
pub struct InstallOutcome {
    pub installed: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<(String, String)>,
    pub missing_type: usize,
}

impl InstallOutcome {
    /// An install that installed nothing is a failed install, whatever the reason.
    pub fn failed(&self) -> bool {
        let problems = self.errors.len() + self.skipped.len() + self.missing_type;
        !self.errors.is_empty() || (self.installed.is_empty() && problems > 0)
    }
}

/// Whether this process may block on a human. Mirrors CliIo in the Kotlin CLI: a prompt reached
/// from CI must fail rather than read EOF and quietly take the default.
pub fn interactive() -> bool {
    if std::env::var("BIGBANG_NON_INTERACTIVE").map(|v| !v.is_empty()).unwrap_or(false) {
        return false;
    }
    std::io::stdin().is_terminal()
}

pub fn install(store: &RepoDb, source: &Path, recursive: bool, force: bool) -> Result<InstallOutcome> {
    let mut outcome = InstallOutcome::default();

    let files = if source.is_dir() {
        collect_json_files(source, recursive)?
    } else if source.extension().and_then(|s| s.to_str()) == Some("json") {
        vec![source.to_path_buf()]
    } else {
        anyhow::bail!("Source must be a .json file or a directory");
    };

    if files.is_empty() {
        println!("⚠️  No JSON files found in {}", source.display());
        outcome.errors.push((source.display().to_string(), "no JSON files".into()));
        return Ok(outcome);
    }

    for file in files {
        let label = file.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        match install_one(store, &file, force, &mut outcome) {
            Ok(()) => {}
            Err(err) => outcome.errors.push((label, format!("{err:#}"))),
        }
    }
    Ok(outcome)
}

fn install_one(store: &RepoDb, file: &Path, force: bool, outcome: &mut InstallOutcome) -> Result<()> {
    let label = file.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
    let raw = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let value: Value = serde_json::from_str(&raw).with_context(|| format!("parsing {}", file.display()))?;

    match value.get("type").and_then(Value::as_str) {
        None => {
            outcome.missing_type += 1;
            return Ok(());
        }
        Some(t) if t != RECIPE_TYPE => {
            outcome.skipped.push(format!("{label} (not a recipe, type: {t})"));
            return Ok(());
        }
        Some(_) => {}
    }

    let id = match value.get("id").and_then(Value::as_str) {
        Some(id) if !id.trim().is_empty() => id.to_string(),
        _ => {
            outcome.skipped.push(format!("{label} (missing 'id' field)"));
            return Ok(());
        }
    };

    validate(&value).with_context(|| format!("{label} does not conform to the recipe schema"))?;

    if store.exists(TYPE_RECIPE, &id) && !force {
        if !interactive() {
            eprintln!();
            eprintln!("❌ Needs an answer, and this session cannot ask: Overwrite {id}?");
            eprintln!("   Pass --force to overwrite without asking (what CI should do).");
            std::process::exit(crate::EXIT_NEEDS_INPUT as i32);
        }
        println!("⚠️  Recipe already exists: {id}");
        outcome.skipped.push(format!("{id} (already exists)"));
        return Ok(());
    }

    store.write(TYPE_RECIPE, &id, &value)?;
    outcome.installed.push(id);
    Ok(())
}

fn validate(value: &Value) -> Result<()> {
    let schema: Value = serde_json::from_str(RECIPE_SCHEMA).context("parsing the bundled recipe schema")?;
    let validator = jsonschema::validator_for(&schema).context("compiling the recipe schema")?;
    if let Err(err) = validator.validate(value) {
        anyhow::bail!("{}", err);
    }
    Ok(())
}

fn collect_json_files(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                out.extend(collect_json_files(&path, true)?);
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

// ── the recipe model, for execution ────────────────────────────────────────────

use std::collections::BTreeMap;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Recipe {
    pub id: String,
    #[serde(rename = "projectId", default)]
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub variables: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub roles: Vec<Role>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Role {
    pub name: String,
    #[serde(default)]
    pub selectors: Option<Vec<String>>,
    #[serde(rename = "infrastructureIds", default)]
    pub infrastructure_ids: Option<Vec<String>>,
    #[serde(default)]
    pub variables: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub items: Vec<RoleItem>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoleItem {
    /// `group/name/version`, resolved against the library.
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub order: Option<i64>,
    #[serde(rename = "continueOnError", default)]
    pub continue_on_error: bool,
}

/// Resolve one variable value.
///
/// | form | source |
/// |---|---|
/// | `vault:account/project/id` | the encrypted vault — a laptop with the passphrase |
/// | `env:NAME` | the process environment — CI, where GitHub holds the secret |
/// | `file:/path` | a file on disk |
/// | anything else | used as written |
///
/// `env:` exists so the same recipe runs in both places: a laptop resolves `vault:` references
/// against a local vault, and CI supplies the same values from GitHub Environment secrets without
/// the vault ever being committed. See [`resolve_all`] for the override that lets one recipe do
/// both without being edited.
///
/// A reference that cannot be resolved is an error, never an empty string — an unresolved password
/// silently becoming `""` is a command that runs with the wrong credentials rather than failing.
pub fn resolve_value(
    value: &serde_json::Value,
    vault_root: &str,
    password: &dyn Fn() -> anyhow::Result<String>,
) -> Result<String> {
    resolve_value_in(value, vault_root, None, password)
}

/// As `resolve_value`, with the profile's own vault identity for the short reference form.
///
/// `vault:account/project/name` names a specific vault. `vault:name` means "this profile's vault",
/// which is what makes a task portable: setup-pgbackrest hardcoded
/// `vault:colistor/colistor/backup_s3_access_key`, so running it under the int profile looked in a
/// project int's vault does not have. A task that names an environment is a task that belongs to
/// one, which defeats the point of having environments at all.
///
/// The short form is also what 15 references in update-colistor-credentials already use; the
/// resolver rejected them, so that recipe could not run at all.
pub fn resolve_value_in(
    value: &serde_json::Value,
    vault_root: &str,
    profile_vault: Option<(&str, &str)>,
    password: &dyn Fn() -> anyhow::Result<String>,
) -> Result<String> {
    let raw = match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string().trim_matches('"').to_string(),
    };

    if let Some(reference) = raw.strip_prefix("vault:") {
        let parts: Vec<&str> = reference.split('/').collect();
        let (account, project, key) = if parts.len() >= 3 {
            (parts[0].to_string(), parts[1].to_string(), parts[2..].join("/"))
        } else if parts.len() == 1 {
            let Some((account, project)) = profile_vault else {
                anyhow::bail!(
                    "'vault:{reference}' is the short form, which resolves against the profile's \
                     own vault — and this call site has none. Use vault:account/project/name here."
                );
            };
            (account.to_string(), project.to_string(), parts[0].to_string())
        } else {
            anyhow::bail!(
                "vault reference must be 'name' or 'account/project/name', got '{reference}'"
            );
        };
        let pw = password()?;
        let vault = crate::vault::Vault::new(
            crate::profile::Profile::expand(vault_root),
            &account,
            &project,
        );
        return vault
            .get(&key, &pw)?
            .with_context(|| format!("Vault item not found: {key} in {account}/{project}"));
    }

    if let Some(name) = raw.strip_prefix("env:") {
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("env reference has no variable name");
        }
        return match std::env::var(name) {
            Ok(value) if !value.is_empty() => Ok(value),
            _ => anyhow::bail!(
                "environment variable '{name}' is not set (or is empty) — it is referenced as 'env:{name}'"
            ),
        };
    }

    if let Some(path) = raw.strip_prefix("file:") {
        let expanded = crate::profile::Profile::expand(path);
        return fs::read_to_string(&expanded)
            .with_context(|| format!("reading file reference {expanded}"));
    }

    Ok(raw)
}

/// The environment variable that overrides a declared variable: `db_password` becomes
/// `BIGBANG_VAR_DB_PASSWORD`.
pub fn override_env_name(key: &str) -> String {
    format!("BIGBANG_VAR_{}", key.to_uppercase().replace('-', "_"))
}

/// Resolve every variable, honouring overrides.
///
/// Precedence, highest first:
///
/// 1. `overrides` — what `--var name=value` supplied
/// 2. `BIGBANG_VAR_<NAME>` in the environment
/// 3. the value the recipe declares, itself possibly `vault:`, `env:` or `file:`
///
/// The point of 1 and 2 is that a recipe written with `vault:` references — the right thing on a
/// laptop — runs unchanged in CI, where no vault exists and GitHub holds the secret. One recipe,
/// no branching inside it on where it thinks it is running, and the vault never leaves the laptop.
/// Resolved variables, and which of them are secret.
///
/// Only values that came from somewhere secret are masked in output: a `vault:` or `env:`
/// reference, or a BIGBANG_VAR_ override, which is how CI supplies a secret. A literal written in
/// the recipe, or passed with `--var`, is not masked — `--var` is visible in `ps` anyway, so
/// treating it as secret buys nothing and costs a great deal of legibility. Masking everything
/// turned "REFUSING: expected colistor-prod" into "REFUSING: expected ***", which is exactly the
/// line an operator needs to read.
#[derive(Debug, Default)]
pub struct Resolved {
    pub values: BTreeMap<String, String>,
    pub secrets: Vec<String>,
}

pub fn resolve_all(
    variables: &BTreeMap<String, serde_json::Value>,
    vault_root: &str,
    password: &dyn Fn() -> anyhow::Result<String>,
    overrides: &BTreeMap<String, String>,
) -> Result<Resolved> {
    resolve_all_in(variables, vault_root, None, password, overrides)
}

pub fn resolve_all_in(
    variables: &BTreeMap<String, serde_json::Value>,
    vault_root: &str,
    profile_vault: Option<(&str, &str)>,
    password: &dyn Fn() -> anyhow::Result<String>,
    overrides: &BTreeMap<String, String>,
) -> Result<Resolved> {
    let mut out = Resolved::default();
    for (key, value) in variables {
        if let Some(supplied) = overrides.get(key) {
            out.values.insert(key.clone(), supplied.clone());
            continue;
        }
        if let Ok(from_env) = std::env::var(override_env_name(key)) {
            if !from_env.is_empty() {
                out.secrets.push(from_env.clone());
                out.values.insert(key.clone(), from_env);
                continue;
            }
        }
        let declared = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let resolved = resolve_value_in(value, vault_root, profile_vault, password)
            .with_context(|| format!("resolving variable '{key}'"))?;
        if declared.starts_with("vault:") || declared.starts_with("env:") {
            out.secrets.push(resolved.clone());
        }
        out.values.insert(key.clone(), resolved);
    }
    // A --var naming something the recipe does not declare still applies.
    //
    // It used to be dropped: the loop above only ever consulted overrides for keys already in the
    // map, so `--var db_host=...` against a recipe with no db_host default did nothing at all and
    // the run proceeded with the placeholder unsubstituted. That is the shape of bug this
    // repository keeps finding — an instruction accepted, ignored, and reported as success — and
    // it appeared the moment a dangerous default was removed, which is exactly when someone would
    // be supplying the value by hand.
    for (key, supplied) in overrides {
        out.values.entry(key.clone()).or_insert_with(|| supplied.clone());
    }
    Ok(out)
}

#[cfg(test)]
mod value_tests {
    use super::*;

    fn no_password() -> anyhow::Result<String> {
        anyhow::bail!("should not be asked")
    }

    /// `vault:name` means "this profile's vault". Without it a task must name an account and
    /// project, which ties it to one environment — setup-pgbackrest said
    /// `vault:colistor/colistor/...` and so could only ever run against production.
    #[test]
    fn the_short_vault_form_needs_a_profile_to_resolve_against() {
        let value = serde_json::Value::String("vault:backup_s3_access_key".into());
        let err = resolve_value(&value, "/nonexistent", &no_password).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("short form"), "{text}");

        // Given one, it looks in that profile's vault rather than a hardcoded pair.
        let err = resolve_value_in(&value, "/nonexistent", Some(("colistor", "colistor-int")), &no_password)
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(
            !text.contains("short form"),
            "with a profile it should attempt a lookup, not refuse: {text}"
        );
    }

    #[test]
    fn a_two_part_reference_is_still_refused() {
        let value = serde_json::Value::String("vault:colistor/backup_key".into());
        let err = resolve_value_in(&value, "/nonexistent", Some(("a", "b")), &no_password).unwrap_err();
        assert!(format!("{err:#}").contains("must be"), "{err:#}");
    }

    /// `--var` must be able to introduce a variable, not only replace a declared one. Removing a
    /// dangerous default is precisely when a value is supplied by hand, and dropping it silently
    /// left the placeholder unsubstituted in the command.
    #[test]
    fn an_override_applies_even_when_the_recipe_declares_nothing() {
        let declared = BTreeMap::new();
        let mut overrides = BTreeMap::new();
        overrides.insert("db_host".to_string(), "10.0.0.9".to_string());

        let resolved = resolve_all(&declared, "/nonexistent", &no_password, &overrides).unwrap();
        assert_eq!(resolved.values.get("db_host").map(String::as_str), Some("10.0.0.9"));
    }

    #[test]
    fn a_declared_variable_loses_to_an_override_and_survives_without_one() {
        let mut declared = BTreeMap::new();
        declared.insert("db_name".to_string(), serde_json::Value::String("from_recipe".into()));

        let resolved = resolve_all(&declared, "/nonexistent", &no_password, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.values["db_name"], "from_recipe");

        let mut overrides = BTreeMap::new();
        overrides.insert("db_name".to_string(), "from_flag".to_string());
        let resolved = resolve_all(&declared, "/nonexistent", &no_password, &overrides).unwrap();
        assert_eq!(resolved.values["db_name"], "from_flag", "--var must beat the recipe");
    }

    #[test]
    fn a_plain_value_passes_through() {
        let v = serde_json::json!("appdb");
        assert_eq!(resolve_value(&v, "/vault", &no_password).unwrap(), "appdb");
    }

    #[test]
    fn a_number_is_rendered_as_written() {
        let v = serde_json::json!(5432);
        assert_eq!(resolve_value(&v, "/vault", &no_password).unwrap(), "5432");
    }

    #[test]
    fn a_malformed_vault_reference_is_an_error_not_an_empty_string() {
        let v = serde_json::json!("vault:too/short");
        assert!(resolve_value(&v, "/vault", &no_password).is_err());
    }

    #[test]
    fn an_env_reference_reads_the_environment() {
        std::env::set_var("BIGBANG_TEST_SECRET", "from-the-environment");
        let v = serde_json::json!("env:BIGBANG_TEST_SECRET");
        assert_eq!(resolve_value(&v, "/vault", &no_password).unwrap(), "from-the-environment");
        std::env::remove_var("BIGBANG_TEST_SECRET");
    }

    #[test]
    fn an_unset_env_reference_fails_rather_than_resolving_to_nothing() {
        let v = serde_json::json!("env:BIGBANG_DEFINITELY_UNSET");
        let err = resolve_value(&v, "/vault", &no_password).unwrap_err();
        assert!(format!("{err:#}").contains("not set"));
    }

    #[test]
    fn an_override_replaces_a_vault_reference_without_touching_the_vault() {
        // This is what lets one recipe run on a laptop and in CI: the vault reference is never
        // resolved, so no vault and no passphrase are needed.
        let mut vars = BTreeMap::new();
        vars.insert("db_password".to_string(), serde_json::json!("vault:a/b/c"));
        let mut overrides = BTreeMap::new();
        overrides.insert("db_password".to_string(), "supplied".to_string());
        let out = resolve_all(&vars, "/nonexistent", &no_password, &overrides).unwrap();
        assert_eq!(out.values["db_password"], "supplied");
        assert!(out.secrets.is_empty(), "--var is not a secret channel: it is visible in ps");
    }

    #[test]
    fn the_env_override_follows_the_variable_name() {
        assert_eq!(override_env_name("db_password"), "BIGBANG_VAR_DB_PASSWORD");
        assert_eq!(override_env_name("image-tag"), "BIGBANG_VAR_IMAGE_TAG");

        let mut vars = BTreeMap::new();
        vars.insert("db_password".to_string(), serde_json::json!("vault:a/b/c"));
        std::env::set_var("BIGBANG_VAR_DB_PASSWORD", "from-ci");
        let out = resolve_all(&vars, "/nonexistent", &no_password, &BTreeMap::new()).unwrap();
        assert_eq!(out.values["db_password"], "from-ci");
        assert_eq!(out.secrets, vec!["from-ci".to_string()], "an env override is a secret and must be masked");
        std::env::remove_var("BIGBANG_VAR_DB_PASSWORD");
    }

    #[test]
    fn an_explicit_var_beats_the_environment() {
        let mut vars = BTreeMap::new();
        vars.insert("x".to_string(), serde_json::json!("declared"));
        std::env::set_var("BIGBANG_VAR_X", "from-env");
        let mut overrides = BTreeMap::new();
        overrides.insert("x".to_string(), "from-flag".to_string());
        let out = resolve_all(&vars, "/v", &no_password, &overrides).unwrap();
        assert_eq!(out.values["x"], "from-flag");
        std::env::remove_var("BIGBANG_VAR_X");
    }
}
