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
