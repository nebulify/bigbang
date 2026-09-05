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
use bigbang::vault::Vault;
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
    /// Read encrypted credentials
    Vault {
        #[command(subcommand)]
        operation: VaultOp,
    },
    /// Manage the task and package library
    Library {
        #[command(subcommand)]
        operation: LibraryOp,
    },
    /// Inspect profiles
    Profile {
        #[command(subcommand)]
        operation: ProfileOp,
    },
    /// Start the interactive shell
    Shell,
}

#[derive(Subcommand)]
enum LibraryOp {
    /// Install task or package definitions
    Install {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, short = 'r')]
        recursive: bool,
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// List everything in the library
    List {
        #[arg(long)]
        profile: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProfileOp {
    /// Check a profile file is valid
    Validate {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Print a profile
    Show {
        #[arg(long)]
        profile: PathBuf,
    },
}

#[derive(Subcommand)]
enum VaultOp {
    /// List item names and types, without decrypting
    List {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Decrypt and print one item
    Get {
        #[arg(long = "item-id")]
        item_id: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Add an item to the vault
    Add {
        #[arg(long = "item-id")]
        item_id: String,
        #[arg(long)]
        data: String,
        #[arg(long = "type", default_value = "PASSWORD")]
        type_: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        profile: PathBuf,
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
    /// Execute a recipe against the machines its roles select
    Execute {
        #[arg(long)]
        id: String,
        #[arg(long)]
        profile: PathBuf,
        /// Resolve and print the plan without running anything
        #[arg(long)]
        dry_run: bool,
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
    dispatch(Cli::parse())
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Recipe { operation } => match operation {
            RecipeOp::List { profile } => recipe_list(&profile),
            RecipeOp::Show { id, profile } => recipe_show(&id, &profile),
            RecipeOp::Execute { id, profile, dry_run } => recipe_execute(&id, &profile, dry_run),
            RecipeOp::Install { source, profile, recursive, force } => {
                recipe_install(&source, &profile, recursive, force)
            }
        },
        Command::Shell => shell_loop(),
        Command::Library { operation } => match operation {
            LibraryOp::Install { source, profile, recursive, force } => {
                library_install(&source, &profile, recursive, force)
            }
            LibraryOp::List { profile } => library_list(&profile),
        },
        Command::Profile { operation } => match operation {
            ProfileOp::Validate { profile } => {
                let p = Profile::load(&profile)?;
                println!("✓ Profile '{}' is valid", p.name);
                Ok(())
            }
            ProfileOp::Show { profile } => {
                let p = Profile::load(&profile)?;
                println!("{}", serde_json::to_string_pretty(&p)?);
                Ok(())
            }
        },
        Command::Vault { operation } => match operation {
            VaultOp::List { profile } => vault_list(&profile),
            VaultOp::Get { item_id, profile } => vault_get(&item_id, &profile),
            VaultOp::Add { item_id, data, type_, description, profile } => {
                vault_add(&item_id, &data, &type_, description.as_deref(), &profile)
            }
        },
    }
}

fn open_vault(profile_path: &PathBuf) -> Result<Vault> {
    let profile = Profile::load(profile_path)?;
    Ok(Vault::new(
        Profile::expand(&profile.vault_path),
        &profile.account_code,
        &profile.default_vault_name,
    ))
}

/// Same variables the Kotlin CLI honours, in the same order, so a pipeline that sets one keeps
/// working across the migration. Refuses rather than prompting with no terminal.
fn vault_password() -> Result<String> {
    for var in ["COLISTOR_MASTER_PASSWORD", "BIGBANG_VAULT_PASSWORD", "VAULT_PASSWORD"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    if !bigbang::recipe::interactive() {
        eprintln!("❌ Needs input, and this session cannot ask: Vault password");
        eprintln!("   Set BIGBANG_VAULT_PASSWORD (or COLISTOR_MASTER_PASSWORD).");
        std::process::exit(bigbang::EXIT_NEEDS_INPUT as i32);
    }
    print!("Vault password: ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn vault_list(profile_path: &PathBuf) -> Result<()> {
    let vault = open_vault(profile_path)?;
    let items = vault.list()?;
    if items.is_empty() {
        println!("No vault items found");
        return Ok(());
    }
    println!("Vault items: {}", items.len());
    for (name, type_) in items {
        println!("  ✓ {name} ({type_})");
    }
    Ok(())
}

fn vault_get(item_id: &str, profile_path: &PathBuf) -> Result<()> {
    let vault = open_vault(profile_path)?;
    let password = vault_password()?;
    match vault.get(item_id, &password)? {
        Some(value) => {
            println!("{value}");
            Ok(())
        }
        None => anyhow::bail!("Vault item not found: {item_id}"),
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

fn vault_add(item_id: &str, data: &str, type_: &str, description: Option<&str>, profile_path: &PathBuf) -> Result<()> {
    let vault = open_vault(profile_path)?;
    let password = vault_password()?;
    vault.add(item_id, type_, description, data, &password)?;
    println!("✓ Added vault item: {item_id}");
    Ok(())
}

fn recipe_execute(id: &str, profile_path: &PathBuf, dry_run: bool) -> Result<()> {
    use bigbang::exec::{run_definition, SshExecutor};
    use bigbang::infra::{load_instances, resolve_role_targets, resolve_ssh_key, ssh_target_for};
    use bigbang::recipe::{resolve_all, Recipe};
    use bigbang::task::TaskDefinition;

    let profile = Profile::load(profile_path)?;
    let store = RepoDb::new(
        Profile::expand(&profile.bigbang_path),
        &profile.account_code,
        &profile.database_name,
    );

    let raw = store
        .read_latest(TYPE_RECIPE, id)?
        .with_context(|| format!("Recipe not found: {id}"))?;
    let recipe: Recipe = serde_json::from_value(raw).context("parsing the recipe")?;

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Recipe Execution: {}", recipe.name);
    println!("╚════════════════════════════════════════════════════════════╝");

    let vault_root = Profile::expand(&profile.vault_path);
    let password = || vault_password();
    let recipe_vars = resolve_all(&recipe.variables, &vault_root, &password)?;
    let instances = load_instances(&store)?;
    let library_root = PathBuf::from(Profile::expand(&profile.library_path));

    let mut failures = 0usize;
    let mut targeted = 0usize;
    for role in &recipe.roles {
        let targets = resolve_role_targets(
            &instances,
            &recipe.project_id,
            role.infrastructure_ids.as_ref(),
            role.selectors.as_ref(),
        );
        println!();
        println!("── role '{}' → {} instance(s)", role.name, targets.len());
        targeted += targets.len();
        if targets.is_empty() {
            println!("   (no instance matches; nothing to do)");
            continue;
        }

        let role_vars = resolve_all(&role.variables, &vault_root, &password)?;
        let mut merged = recipe_vars.clone();
        merged.extend(role_vars);

        let mut items: Vec<_> = role.items.iter().collect();
        items.sort_by_key(|i| i.order.unwrap_or(0));

        for instance in &targets {
            println!("   ▸ {} ({})", instance.name, instance.address()?);
            for item in &items {
                let Some(coordinate) = item.package.as_ref().or(item.task.as_ref()) else {
                    println!("     ⚠️  item has neither 'package' nor 'task'; skipped");
                    continue;
                };
                let definition = TaskDefinition::load_from_library(&library_root, coordinate)
                    .with_context(|| format!("loading {coordinate}"))?;

                if dry_run {
                    let count: usize = definition.tasks.iter().map(|t| t.commands.len()).sum();
                    println!("     · {coordinate}: {} task(s), {count} command(s)", definition.tasks.len());
                    continue;
                }

                let key_id = instance.ssh_key_id.as_deref()
                    .with_context(|| format!("no sshKeyId on instance {}", instance.name))?;
                let key = resolve_ssh_key(key_id, &vault_root, &password()?)?;
                let target = ssh_target_for(instance, &instances, &key.path.to_string_lossy(), None)?;
                let mut executor = SshExecutor { target, echo: true };

                let outcomes = run_definition(&definition, &merged, &mut executor)?;
                for outcome in &outcomes {
                    if let Some(failure) = &outcome.failed {
                        println!("     ✗ {}: {failure}", outcome.task_name);
                        failures += 1;
                    } else {
                        println!("     ✓ {} ({} ran, {} skipped)", outcome.task_name, outcome.ran.len(), outcome.skipped.len());
                    }
                }
                if failures > 0 && !item.continue_on_error {
                    anyhow::bail!("Recipe execution failed in role '{}'", role.name);
                }
            }
        }
    }

    if failures > 0 {
        anyhow::bail!("Recipe execution failed: {failures} task(s)");
    }
    // A recipe that reached no machine did nothing, and saying "completed" for that is how a
    // deployment appears to succeed while changing nothing at all.
    if targeted == 0 {
        anyhow::bail!(
            "Recipe '{}' matched no infrastructure — check the roles' selectors and infrastructureIds \
             against the instances in this store",
            recipe.name
        );
    }
    println!();
    println!("✓ Recipe '{}' completed", recipe.name);
    Ok(())
}

fn open_library(profile_path: &PathBuf) -> Result<bigbang::library::Library> {
    let profile = Profile::load(profile_path)?;
    Ok(bigbang::library::Library::new(Profile::expand(&profile.library_path)))
}

fn library_install(source: &PathBuf, profile_path: &PathBuf, recursive: bool, force: bool) -> Result<()> {
    let library = open_library(profile_path)?;
    let mut files = Vec::new();
    if source.is_dir() {
        collect_json(source, recursive, &mut files)?;
    } else {
        files.push(source.clone());
    }
    let (mut installed, mut failed) = (0usize, 0usize);
    for file in files {
        match library.install_file(&file, force) {
            Ok(item) => {
                println!("  ✓ {} ({})", item.coordinate(), item.item_type.folder_name());
                installed += 1;
            }
            Err(err) => {
                println!("  ✗ {}: {err:#}", file.display());
                failed += 1;
            }
        }
    }
    println!("Installed: {installed}");
    if failed > 0 {
        anyhow::bail!("{failed} item(s) failed to install");
    }
    if installed == 0 {
        anyhow::bail!("Nothing was installed");
    }
    Ok(())
}

fn collect_json(dir: &PathBuf, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)?.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_json(&path, true, out)?;
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(())
}

fn library_list(profile_path: &PathBuf) -> Result<()> {
    let items = open_library(profile_path)?.list()?;
    if items.is_empty() {
        println!("Library is empty");
        return Ok(());
    }
    println!("Library items: {}", items.len());
    for item in items {
        println!("  ✓ {} ({})", item.coordinate(), item.item_type.folder_name());
    }
    Ok(())
}

/// The interactive loop. Commands are parsed by the same clap definition as the command line, so
/// there is one grammar rather than two that drift apart — the Kotlin shell re-parses arguments in
/// a separate code path, which is how a flag comes to work in one mode and not the other.
fn shell_loop() -> Result<()> {
    use bigbang::shell::Session;
    use rustyline::error::ReadlineError;

    let mut session = Session::default();
    let mut editor = rustyline::DefaultEditor::new()?;
    let history = std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".bigbang_history"));
    if let Some(path) = &history {
        let _ = editor.load_history(path);
    }

    println!("BigBang shell. 'help' for commands, 'exit' to leave.");
    loop {
        match editor.readline(&session.prompt()) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line.as_str());
                match line.as_str() {
                    "exit" | "quit" | "q" => break,
                    "help" | "?" => {
                        println!("  profile load <path>   load a profile for this session");
                        println!("  profile show          show the loaded profile");
                        println!("  forget                clear cached vault passwords");
                        println!("  <any bigbang command> e.g. recipe list");
                        println!("  exit                  leave");
                        continue;
                    }
                    "forget" => {
                        session.clear_passwords();
                        println!("✓ Cached passwords cleared");
                        continue;
                    }
                    _ => {}
                }

                let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
                if words[0] == "profile" && words.get(1).map(String::as_str) == Some("load") {
                    match words.get(2) {
                        Some(path) => {
                            if let Err(err) = session.load_profile(path) {
                                eprintln!("❌ {err:#}");
                            }
                        }
                        None => eprintln!("❌ usage: profile load <path>"),
                    }
                    continue;
                }
                if words[0] == "profile" && words.get(1).map(String::as_str) == Some("show") {
                    match &session.profile {
                        Some(p) => println!("{}", serde_json::to_string_pretty(p)?),
                        None => println!("No profile loaded"),
                    }
                    continue;
                }

                // A loaded profile fills in --profile so it need not be typed every time.
                let mut argv: Vec<String> = vec!["bigbang".to_string()];
                argv.extend(words.clone());
                if !words.iter().any(|w| w == "--profile") {
                    if let Some(path) = &session.profile_path {
                        argv.push("--profile".into());
                        argv.push(path.clone());
                    }
                }

                match Cli::try_parse_from(&argv) {
                    Ok(cli) => {
                        if let Err(err) = dispatch(cli) {
                            eprintln!("❌ {err:#}");
                        }
                    }
                    Err(err) => println!("{err}"),
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("❌ {err}");
                break;
            }
        }
    }
    if let Some(path) = &history {
        let _ = editor.save_history(path);
    }
    println!("bye");
    Ok(())
}
