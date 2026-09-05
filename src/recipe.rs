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

/// Resolve one variable value: `vault:account/project/id` decrypts, `file:path` reads, anything
/// else is used as written.
///
/// A reference that cannot be resolved is an error, never an empty string — an unresolved password
/// silently becoming `""` is a command that runs with the wrong credentials rather than failing.
pub fn resolve_value(
    value: &serde_json::Value,
    vault_root: &str,
    password: &dyn Fn() -> anyhow::Result<String>,
) -> Result<String> {
    let raw = match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string().trim_matches('"').to_string(),
    };

    if let Some(reference) = raw.strip_prefix("vault:") {
        let parts: Vec<&str> = reference.split('/').collect();
        if parts.len() < 3 {
            anyhow::bail!("vault reference must be account/project/id, got '{reference}'");
        }
        let pw = password()?;
        let vault = crate::vault::Vault::new(
            crate::profile::Profile::expand(vault_root),
            parts[0],
            parts[1],
        );
        let key = parts[2..].join("/");
        return vault
            .get(&key, &pw)?
            .with_context(|| format!("Vault item not found: {key} in {}/{}", parts[0], parts[1]));
    }

    if let Some(path) = raw.strip_prefix("file:") {
        let expanded = crate::profile::Profile::expand(path);
        return fs::read_to_string(&expanded)
            .with_context(|| format!("reading file reference {expanded}"));
    }

    Ok(raw)
}

pub fn resolve_all(
    variables: &BTreeMap<String, serde_json::Value>,
    vault_root: &str,
    password: &dyn Fn() -> anyhow::Result<String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (key, value) in variables {
        let resolved = resolve_value(value, vault_root, password)
            .with_context(|| format!("resolving variable '{key}'"))?;
        out.insert(key.clone(), resolved);
    }
    Ok(out)
}

#[cfg(test)]
mod value_tests {
    use super::*;

    fn no_password() -> anyhow::Result<String> {
        anyhow::bail!("should not be asked")
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
}
