//! The BigBang CLI.
//!
//! Exit codes match the Kotlin CLI's contract, because pipelines already depend on them:
//!   0  the operation succeeded
//!   1  the operation was attempted and failed
//!   2  input was required and this session could not ask for it

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use bigbang::profile::Profile;
use bigbang::recipe;
use bigbang::repodb::{RepoDb, TYPE_RECIPE};
use bigbang::EXIT_FAILURE;

#[derive(Parser)]
#[command(name = "bigbang", version, about = "Colistor deployment CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage deployment recipes
    Recipe {
        #[command(subcommand)]
        operation: RecipeOp,
    },
}

#[derive(Subcommand)]
enum RecipeOp {
    /// List every recipe in the store
    List {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Show one recipe as stored
    Show {
        #[arg(long)]
        id: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Install recipe files into the store
    Install {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        /// Recurse into sub-directories
        #[arg(long, short = 'r')]
        recursive: bool,
        /// Overwrite existing recipes without asking. What CI should pass.
        #[arg(long, short = 'f')]
        force: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("❌ {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Recipe { operation } => match operation {
            RecipeOp::List { profile } => recipe_list(&profile),
            RecipeOp::Show { id, profile } => recipe_show(&id, &profile),
            RecipeOp::Install { source, profile, recursive, force } => {
                recipe_install(&source, &profile, recursive, force)
            }
        },
    }
}

fn open_store(profile_path: &PathBuf) -> Result<(Profile, RepoDb)> {
    let profile = Profile::load(profile_path)?;
    let base = Profile::expand(&profile.bigbang_path);
    let store = RepoDb::new(base, &profile.account_code, &profile.database_name);
    Ok((profile, store))
}

fn recipe_list(profile_path: &PathBuf) -> Result<()> {
    let (profile, store) = open_store(profile_path)?;
    println!("✓ Profile '{}' loaded", profile.name);
    let names = store.list_names(TYPE_RECIPE)?;
    if names.is_empty() {
        println!("No recipes found");
        return Ok(());
    }
    println!("Recipes: {}", names.len());
    for name in &names {
        let value = store
            .read_latest(TYPE_RECIPE, name)?
            .with_context(|| format!("{name} has a pointer but no payload"))?;
        let description = value.get("description").and_then(|d| d.as_str()).unwrap_or("");
        println!("  ✓ {name}");
        if !description.is_empty() {
            println!("      {description}");
        }
    }
    Ok(())
}

fn recipe_show(id: &str, profile_path: &PathBuf) -> Result<()> {
    let (_, store) = open_store(profile_path)?;
    match store.read_latest(TYPE_RECIPE, id)? {
        Some(value) => {
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        None => anyhow::bail!("Recipe not found: {id}"),
    }
}

fn recipe_install(source: &PathBuf, profile_path: &PathBuf, recursive: bool, force: bool) -> Result<()> {
    let (_, store) = open_store(profile_path)?;
    println!("📂 Target: {}", store.type_dir(TYPE_RECIPE).display());
    let outcome = recipe::install(&store, source, recursive, force)?;

    println!("{}", "=".repeat(80));
    println!("📊 Installation Summary:");
    println!("{}", "-".repeat(80));
    println!("  ✓ Installed: {}", outcome.installed.len());
    if !outcome.skipped.is_empty() {
        println!("  ⊘ Skipped:   {}", outcome.skipped.len());
    }
    if !outcome.errors.is_empty() {
        println!("  ✗ Errors:    {}", outcome.errors.len());
    }
    if outcome.missing_type > 0 {
        println!("  ⓘ Ignored:   {} JSON file(s) without 'type' attribute", outcome.missing_type);
    }
    for id in &outcome.installed {
        println!("  ✓ {id}");
    }
    for item in &outcome.skipped {
        println!("  ⊘ {item}");
    }
    for (file, err) in &outcome.errors {
        println!("  ✗ {file}: {err}");
    }

    if outcome.failed() {
        if outcome.errors.is_empty() {
            anyhow::bail!("Nothing was installed");
        }
        anyhow::bail!("{} recipe(s) failed to install", outcome.errors.len());
    }
    Ok(())
}
