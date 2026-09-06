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
    /// Manage the machine inventory
    Infra {
        #[command(subcommand)]
        operation: InfraOp,
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
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
        #[arg(long, short = 'r')]
        recursive: bool,
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// List everything in the library
    List {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
}

#[derive(Subcommand)]
enum ProfileOp {
    /// Check a profile file is valid
    Validate {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Print a profile
    Show {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
}

#[derive(Subcommand)]
enum InfraOp {
    /// List the machines in the inventory
    List {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Import machine definitions from a file or a directory
    Import {
        /// A .json instance definition, or a directory of them
        source: PathBuf,
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
        /// Replace an instance that is already in the store
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum VaultOp {
    /// List item names and types, without decrypting
    List {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Decrypt and print one item
    Get {
        #[arg(long = "item-id")]
        item_id: String,
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
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
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
}

#[derive(Subcommand)]
enum RecipeOp {
    /// List every recipe in the store
    List {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Show one recipe as stored
    Show {
        #[arg(long)]
        id: String,
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Execute a recipe against the machines its roles select
    Execute {
        #[arg(long)]
        id: String,
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
        /// Resolve and print the plan without running anything
        #[arg(long)]
        dry_run: bool,
        /// Supply a variable directly: --var name=value. Beats the recipe and the environment.
        #[arg(long = "var", value_name = "NAME=VALUE")]
        vars: Vec<String>,
    },
    /// Install recipe files into the store
    Install {
        #[arg(long)]
        source: PathBuf,
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
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
            RecipeOp::Execute { id, profile, dry_run, vars } => {
                recipe_execute(&id, &profile, dry_run, &vars)
            }
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
                let p = Profile::open(&profile)?;
                println!("✓ Profile '{}' is valid", p.name);
                Ok(())
            }
            ProfileOp::Show { profile } => {
                let p = Profile::open(&profile)?;
                println!("{}", serde_json::to_string_pretty(&p)?);
                Ok(())
            }
        },
        Command::Infra { operation } => match operation {
            InfraOp::List { profile } => infra_list(&profile),
            InfraOp::Import { source, profile, force } => infra_import(&source, &profile, force),
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

fn open_vault(profile_ref: &str) -> Result<Vault> {
    let profile = Profile::open(profile_ref)?;
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

fn vault_list(profile_ref: &str) -> Result<()> {
    let vault = open_vault(profile_ref)?;
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

fn vault_get(item_id: &str, profile_ref: &str) -> Result<()> {
    let vault = open_vault(profile_ref)?;
    let password = vault_password()?;
    match vault.get(item_id, &password)? {
        Some(value) => {
            println!("{value}");
            Ok(())
        }
        None => anyhow::bail!("Vault item not found: {item_id}"),
    }
}

fn open_store(profile_ref: &str) -> Result<(Profile, RepoDb)> {
    let profile = Profile::open(profile_ref)?;
    let base = Profile::expand(&profile.bigbang_path);
    let store = RepoDb::new(base, &profile.account_code, &profile.database_name);
    Ok((profile, store))
}

fn infra_list(profile_ref: &str) -> Result<()> {
    let (profile, store) = open_store(profile_ref)?;
    println!("✓ Profile '{}' loaded", profile.name);
    let instances = bigbang::infra::load_instances(&store)?;
    if instances.is_empty() {
        println!("No machines in the inventory");
        return Ok(());
    }
    println!("Machines: {}", instances.len());
    for i in &instances {
        let address = i.address().unwrap_or_else(|_| "—".to_string());
        let via = i.jump_host_id.as_deref().map(|j| format!(" via {j}")).unwrap_or_default();
        let selectors = i.selectors.clone().unwrap_or_default().join(", ");
        println!(
            "  {:<20} {:<16}{}  {}@{}  [{}]",
            i.name,
            address,
            via,
            i.ssh_username.as_deref().unwrap_or("—"),
            i.project_id,
            selectors
        );
    }
    Ok(())
}

fn infra_import(source: &PathBuf, profile_ref: &str, force: bool) -> Result<()> {
    let (profile, store) = open_store(profile_ref)?;
    println!("✓ Profile '{}' loaded", profile.name);
    println!("📂 Target: {}", store.type_dir(bigbang::infra::TYPE_INFRASTRUCTURE).display());
    let outcome = bigbang::infra::import(&store, source, force)?;

    for name in &outcome.imported {
        println!("  ✓ {name}");
    }
    for item in &outcome.skipped {
        println!("  ⊘ {item}");
    }
    for (file, err) in &outcome.errors {
        println!("  ✗ {file}: {err}");
    }
    println!(
        "📊 Imported: {}  Skipped: {}  Errors: {}",
        outcome.imported.len(),
        outcome.skipped.len(),
        outcome.errors.len()
    );

    // A partial import is a failure: the inventory is now neither what it was nor what was asked
    // for, and exiting 0 would let a pipeline carry on against machines that were never written.
    if !outcome.errors.is_empty() {
        anyhow::bail!("{} definition(s) could not be imported", outcome.errors.len());
    }
    if outcome.imported.is_empty() && outcome.skipped.is_empty() {
        anyhow::bail!("Nothing was imported — no .json definitions found in {}", source.display());
    }
    Ok(())
}

fn recipe_list(profile_ref: &str) -> Result<()> {
    let (profile, store) = open_store(profile_ref)?;
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

fn recipe_show(id: &str, profile_ref: &str) -> Result<()> {
    let (_, store) = open_store(profile_ref)?;
    match store.read_latest(TYPE_RECIPE, id)? {
        Some(value) => {
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        None => anyhow::bail!("Recipe not found: {id}"),
    }
}

fn recipe_install(source: &PathBuf, profile_ref: &str, recursive: bool, force: bool) -> Result<()> {
    let (_, store) = open_store(profile_ref)?;
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

fn vault_add(item_id: &str, data: &str, type_: &str, description: Option<&str>, profile_ref: &str) -> Result<()> {
    let vault = open_vault(profile_ref)?;
    let password = vault_password()?;
    vault.add(item_id, type_, description, data, &password)?;
    println!("✓ Added vault item: {item_id}");
    Ok(())
}

fn recipe_execute(id: &str, profile_ref: &str, dry_run: bool, vars: &[String]) -> Result<()> {
    use bigbang::exec::{run_definition, CommandExecutor, LocalExecutor, SshExecutor};
    use bigbang::infra::{load_instances, resolve_role_targets, resolve_ssh_key, ssh_target_for};
    use bigbang::recipe::{resolve_all, Recipe};
    use bigbang::task::TaskDefinition;

    let profile = Profile::open(profile_ref)?;
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

    let mut overrides = std::collections::BTreeMap::new();
    for pair in vars {
        let (name, value) = pair
            .split_once('=')
            .with_context(|| format!("--var expects NAME=VALUE, got '{pair}'"))?;
        overrides.insert(name.to_string(), value.to_string());
    }

    let vault_root = Profile::expand(&profile.vault_path);
    let password = || vault_password();
    let resolved = resolve_all(&recipe.variables, &vault_root, &password, &overrides)?;
    let recipe_vars = resolved.values;
    let mut secret_values = resolved.secrets;
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

        let role_resolved = resolve_all(&role.variables, &vault_root, &password, &overrides)?;
        secret_values.extend(role_resolved.secrets.clone());
        let mut merged = recipe_vars.clone();
        merged.extend(role_resolved.values);

        let mut items: Vec<_> = role.items.iter().collect();
        items.sort_by_key(|i| i.order.unwrap_or(0));

        for instance in &targets {
            if instance.is_local() {
                println!("   ▸ {} (local)", instance.name);
            } else {
                println!("   ▸ {} ({})", instance.name, instance.address()?);
            }
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

                // Only genuinely secret values are masked — see recipe::Resolved. Masking every
                // variable made refusal messages unreadable, which is worse than useless when the
                // message exists to tell an operator what went wrong.
                let secrets: Vec<String> = secret_values.clone();

                // A LOCAL host runs here; anything else needs a key and a route.
                let _key_guard;
                let mut executor: Box<dyn CommandExecutor> = if instance.is_local() {
                    Box::new(LocalExecutor { echo: true, secrets })
                } else {
                    let key_id = instance.ssh_key_id.as_deref()
                        .with_context(|| format!("no sshKeyId on instance {}", instance.name))?;
                    let key = resolve_ssh_key(key_id, &vault_root, &password)?;
                    let target = ssh_target_for(instance, &instances, &key.path.to_string_lossy(), None)?;
                    _key_guard = key; // keep the temporary key file alive for the whole run
                    Box::new(SshExecutor { target, echo: true, secrets })
                };

                let outcomes = run_definition(&definition, &merged, executor.as_mut())?;
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

fn open_library(profile_ref: &str) -> Result<bigbang::library::Library> {
    let profile = Profile::open(profile_ref)?;
    Ok(bigbang::library::Library::new(Profile::expand(&profile.library_path)))
}

fn library_install(source: &PathBuf, profile_ref: &str, recursive: bool, force: bool) -> Result<()> {
    let library = open_library(profile_ref)?;
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

fn library_list(profile_ref: &str) -> Result<()> {
    let items = open_library(profile_ref)?.list()?;
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
                        println!("  profile load <name>   load a profile (from ~/.bigbang/profiles)");
                        println!("  profile load --path F load one from an explicit file");
                        println!("  profile list          names available to load");
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
                    // `profile load colistor` or `profile load --path /somewhere/p.json`
                    let target = if words.get(2).map(String::as_str) == Some("--path") {
                        words.get(3).cloned()
                    } else {
                        words.get(2).cloned()
                    };
                    match target {
                        Some(name) => {
                            if let Err(err) = session.load_profile(&name) {
                                eprintln!("❌ {err:#}");
                            }
                        }
                        None => {
                            eprintln!("❌ usage: profile load <name> | profile load --path <file>");
                            let names = Profile::available();
                            if !names.is_empty() {
                                eprintln!("   available: {}", names.join(", "));
                            }
                        }
                    }
                    continue;
                }
                if words[0] == "profile" && words.get(1).map(String::as_str) == Some("list") {
                    let names = Profile::available();
                    if names.is_empty() {
                        println!("No profiles in {}", bigbang::profile::profiles_dir().display());
                    } else {
                        for n in names {
                            println!("  {n}");
                        }
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
