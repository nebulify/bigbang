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
use bigbang::recipe::resolve_all_in;
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
    /// Hold the vault open in a background agent, so the password is typed once
    Unlock {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
        /// Only these items are unlocked. Without it, every item in the vault is.
        #[arg(long = "item", value_name = "NAME")]
        items: Vec<String>,
        /// How long before the agent exits on its own.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Append every request to this file. Commands and item names, never values.
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Run in the foreground instead of detaching.
        #[arg(long)]
        foreground: bool,
    },
    /// Re-write a v1 vault as one authenticated envelope
    Migrate {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop the agent for a profile
    Lock {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Whether an agent is holding this profile open
    Status {
        /// Profile name (looked up in ~/.bigbang/profiles) or a path to a profile file
        #[arg(long)]
        profile: String,
    },
    /// Ask the operator to store an item, in a terminal this process cannot read.
    ///
    /// Writes a request that bgconsole picks up and opens a prompt for. Nothing comes back
    /// here: the outcome is discovered by looking at the vault afterwards, because a reply
    /// channel would be a way for the secret to return.
    Request {
        #[arg(long = "item-id")]
        item_id: String,
        #[arg(long = "type", default_value = "PASSWORD")]
        type_: String,
        #[arg(long)]
        description: Option<String>,
        /// How long to wait for the operator, in seconds.
        #[arg(long, default_value_t = 180)]
        timeout: u64,
        #[arg(long)]
        profile: String,
    },
    /// Add an item to the vault
    Add {
        #[arg(long = "item-id")]
        item_id: String,
        /// The value itself. Visible in `ps` for the life of the process — prefer --data-file or
        /// --stdin for anything that is actually secret.
        #[arg(long, conflicts_with_all = ["data_file", "stdin"])]
        data: Option<String>,
        /// Read the value from a file, so it never appears in a process listing.
        #[arg(long = "data-file", conflicts_with_all = ["data", "stdin"])]
        data_file: Option<PathBuf>,
        /// Rotate an item that already exists, keeping its id.
        #[arg(long)]
        replace: bool,
        /// Read the value from standard input.
        #[arg(long, conflicts_with_all = ["data", "data_file", "prompt"])]
        stdin: bool,
        /// Ask for the value on this terminal, without echoing it. Meant for a terminal the
        /// operator owns — see `vault request`, which opens one.
        #[arg(long, conflicts_with_all = ["data", "data_file", "stdin", "generate"])]
        prompt: bool,
        /// Read the prompted value as a block ending at Ctrl-D, for a private key or a
        /// certificate. Without it a prompt takes one line.
        #[arg(long, requires = "prompt")]
        multiline: bool,
        /// Generate a random value and store it without ever displaying it.
        #[arg(long, conflicts_with_all = ["data", "data_file", "stdin"])]
        generate: bool,
        /// Characters to generate. 32 alphanumerics is roughly 190 bits.
        #[arg(long, default_value_t = 32, requires = "generate")]
        length: usize,
        /// Shortest acceptable length; with --max-length the length is drawn from the range.
        #[arg(long = "min-length", requires = "generate")]
        min_length: Option<usize>,
        /// Longest acceptable length.
        #[arg(long = "max-length", requires = "generate")]
        max_length: Option<usize>,
        /// Include special characters that are safe in URLs, connection strings and shells.
        #[arg(long, requires = "generate", conflicts_with = "charset")]
        special: bool,
        /// Exactly which extra characters to allow, when --special is not the set you want.
        #[arg(long, requires = "generate")]
        charset: Option<String>,
        /// Comment to embed in a generated SSH key. Defaults to the item id.
        #[arg(long, requires = "generate")]
        comment: Option<String>,
        /// none (default), prepared (usable only through its prepared commands), or always
        /// (never held by the agent).
        #[arg(long, default_value = "none")]
        restriction: String,
        /// A JSON array of prepared commands, required by --restriction prepared.
        #[arg(long = "prepared-file")]
        prepared_file: Option<PathBuf>,
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
        /// A directory of resources for this run, searched before the library's.
        ///
        /// For files this project built — an archive, a rendered config. They are not in the
        /// shared library and a build has no business putting them there. Repeatable.
        #[arg(long = "resources", value_name = "DIR")]
        resources: Vec<PathBuf>,
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
            RecipeOp::Execute { id, profile, dry_run, vars, resources } => {
                recipe_execute(&id, &profile, dry_run, &vars, &resources)
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
            VaultOp::Unlock { profile, items, ttl, audit, foreground } => {
                vault_unlock(&profile, &items, ttl, audit, foreground)
            }
            VaultOp::Migrate { profile, dry_run } => vault_migrate(&profile, dry_run),
            VaultOp::Lock { profile } => vault_lock(&profile),
            VaultOp::Status { profile } => vault_status(&profile),
            VaultOp::List { profile } => vault_list(&profile),
            VaultOp::Get { item_id, profile } => vault_get(&item_id, &profile),
            VaultOp::Request { item_id, type_, description, timeout, profile } =>
                vault_request(&item_id, &type_, description.as_deref(), timeout, &profile),
            VaultOp::Add {
                item_id, data, data_file, stdin, prompt, multiline, replace, generate, length, min_length,
                max_length, special, charset, comment, restriction, prepared_file, type_,
                description, profile,
            } => vault_add(
                &item_id, data.as_deref(), data_file.as_deref(), stdin, prompt, multiline, replace,
                GenerateOptions { generate, length, min_length, max_length, special,
                                  charset: charset.clone(), comment: comment.clone() },
                &restriction, prepared_file.as_deref(),
                &type_, description.as_deref(), &profile,
            ),
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
/// The vault password: from the environment, otherwise from the terminal.
///
/// Read from `/dev/tty` with echo disabled, not from stdin, for two reasons that both bit in
/// practice. Reading stdin meant `printf '%s' secret | bigbang vault add --stdin` could not work at
/// all — the value had consumed stdin, so the prompt found nothing and the command refused. And a
/// line read from stdin is echoed, so the password appeared on screen and stayed in the scrollback
/// of whoever typed it.
fn vault_password() -> Result<String> {
    for var in ["COLISTOR_MASTER_PASSWORD", "BIGBANG_VAULT_PASSWORD", "VAULT_PASSWORD"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    match rpassword::prompt_password("Vault password: ") {
        Ok(value) => Ok(value),
        Err(_) => {
            // No terminal to ask on. Distinct from a failure, so a pipeline can tell "nobody could
            // answer" from "the thing went wrong".
            eprintln!("❌ Needs input, and this session cannot ask: Vault password");
            eprintln!("   Set BIGBANG_VAULT_PASSWORD, or run this where there is a terminal.");
            std::process::exit(bigbang::EXIT_NEEDS_INPUT as i32);
        }
    }
}

/// The vault password, asking a running agent before asking the person.
///
/// This is what makes unlocking worth anything for deployments: without it `recipe execute` would
/// prompt for every run while an unlocked agent sat there, and the agent would be useful for
/// everything except the tool it ships with.
fn vault_password_for(profile_ref: &str) -> Result<String> {
    for var in ["COLISTOR_MASTER_PASSWORD", "BIGBANG_VAULT_PASSWORD", "VAULT_PASSWORD"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    if let Ok(profile) = Profile::open(profile_ref) {
        let socket = bigbang::agent::socket_path(&profile.name);
        if bigbang::agent::is_running(&socket) {
            let request = bigbang::agent::AgentRequest {
                argv: vec![],
                env: std::collections::BTreeMap::new(),
                cwd: None,
                run_prepared: None,
                request_password: true,
            };
            if let Ok(response) = bigbang::agent::send(&socket, &request) {
                if let Some(password) = response.password {
                    return Ok(password);
                }
            }
        }
    }
    vault_password()
}

/// The password for a vault that does not exist yet, asked twice.
///
/// The first write establishes the password, because it is what derives the key. There is nothing
/// to check a typo against — the vault would simply be encrypted under a password nobody knows, and
/// that is discovered later, by which time it holds something.
fn new_vault_password() -> Result<String> {
    for var in ["COLISTOR_MASTER_PASSWORD", "BIGBANG_VAULT_PASSWORD", "VAULT_PASSWORD"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    println!("This vault does not exist yet: the password you choose now is the password.");
    let first = match rpassword::prompt_password("Choose a vault password: ") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("❌ Needs input, and this session cannot ask: Vault password");
            std::process::exit(bigbang::EXIT_NEEDS_INPUT as i32);
        }
    };
    if first.trim().is_empty() {
        anyhow::bail!("an empty vault password is not accepted");
    }
    let again = rpassword::prompt_password("Type it again: ").unwrap_or_default();
    if first != again {
        anyhow::bail!("the two entries differ; nothing was written");
    }
    Ok(first)
}

fn vault_list(profile_ref: &str) -> Result<()> {
    use bigbang::vault::Format;
    let vault = open_vault(profile_ref)?;
    // A v1 vault lists without a password because its names are in the clear. A v2 vault asks,
    // which is not an inconvenience to route around — it is the property being paid for.
    let items = match vault.format()? {
        Format::V2 => {
            let password = vault_password_for(profile_ref)?;
            vault.read_items_with(Some(&password))?
        }
        _ => vault.read_items_with(None)?,
    };
    if items.is_empty() {
        println!("No vault items found");
        return Ok(());
    }
    println!("Vault items: {}", items.len());
    for item in &items {
        let restriction = match item.restriction() {
            bigbang::vault::Restriction::None => String::new(),
            other => format!("  [{}]", serde_json::to_value(other).map(|v| v.as_str().unwrap_or("?").to_string()).unwrap_or_default()),
        };
        println!("  ✓ {} ({}){restriction}", item.name, item.type_);
    }
    Ok(())
}

fn vault_get(item_id: &str, profile_ref: &str) -> Result<()> {
    let vault = open_vault(profile_ref)?;
    let password = vault_password_for(profile_ref)?;
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

/// The value comes from exactly one of: --data, --data-file, or stdin.
///
/// A private key passed as --data sits in the process's argv, where anything else on the machine
/// can read it out of `ps` for as long as the command runs. A file or stdin costs nothing and
/// closes that, which matters because the natural first use of this command is storing an SSH key.
fn vault_unlock(
    profile_ref: &str,
    wanted: &[String],
    ttl_secs: u64,
    audit: Option<PathBuf>,
    foreground: bool,
) -> Result<()> {
    use bigbang::agent;
    let profile = Profile::open(profile_ref)?;
    let socket = agent::socket_path(&profile.name);
    if agent::is_running(&socket) {
        anyhow::bail!("'{}' is already unlocked. Stop it with: bigbang vault lock --profile {profile_ref}", profile.name);
    }

    let vault = open_vault(profile_ref)?;
    let password = vault_password()?;
    let (items, withheld) = bigbang::agent::load_items(&vault, &password, wanted)?;
    if items.is_empty() {
        anyhow::bail!("nothing to unlock — no item matched");
    }
    for name in wanted {
        if !items.contains_key(name) {
            anyhow::bail!("'{name}' is not in this vault; nothing was unlocked");
        }
    }

    println!("🔓 {} unlocked: {} item(s), {} minutes", profile.name, items.len(), ttl_secs / 60);
    for (name, item) in &items {
        match item.restriction {
            bigbang::vault::Restriction::Prepared => println!(
                "   {name}  [prepared only: {}]",
                if item.prepared.is_empty() {
                    "no commands defined, so unusable".to_string()
                } else {
                    item.prepared.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", ")
                }
            ),
            _ => println!("   {name}"),
        }
    }
    for name in &withheld {
        println!("   {name}  [always: not delegated, asks for the password each time]");
    }
    println!("   socket {}", socket.display());
    println!("   use it with: bb -- <command with {{{{item-name}}}}>");

    if foreground {
        let source = agent::VaultSource {
            root: Profile::expand(&profile.vault_path),
            account: profile.account_code.clone(),
            project: profile.default_vault_name.clone(),
            wanted: wanted.to_vec(),
        };
        return agent::serve(
            &socket, items, password, Some(source),
            std::time::Duration::from_secs(ttl_secs), audit,
        );
    }

    // Detach by re-executing ourselves in the foreground with the password in the child's
    // environment. The password is not on the command line, so it is not in `ps`.
    let exe = std::env::current_exe().context("finding this executable")?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("vault").arg("unlock")
        .arg("--profile").arg(profile_ref)
        .arg("--ttl").arg(ttl_secs.to_string())
        .arg("--foreground")
        .env("BIGBANG_VAULT_PASSWORD", &password)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for name in wanted {
        command.arg("--item").arg(name);
    }
    if let Some(path) = &audit {
        command.arg("--audit").arg(path);
    }
    command.spawn().context("starting the agent")?;

    for _ in 0..100 {
        if agent::is_running(&socket) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    anyhow::bail!("the agent did not come up on {}", socket.display());
}

/// Re-wrap a v1 vault as v2, verifying every item survives before the pointer moves.
///
/// The items themselves are unchanged: each secret keeps its own encrypted payload, so this is a
/// re-wrap rather than a re-encryption, and every item can be compared byte for byte afterwards.
/// The old version file stays in .vault-versions, so the migration is reversible by pointing back
/// at it.
fn vault_migrate(profile_ref: &str, dry_run: bool) -> Result<()> {
    use bigbang::vault::Format;
    let vault = open_vault(profile_ref)?;
    match vault.format()? {
        Format::V2 => {
            println!("Already a {} vault; nothing to do.", bigbang::vault2::FORMAT);
            return Ok(());
        }
        Format::New => anyhow::bail!("there is no vault here yet"),
        Format::V1 => {}
    }

    let password = vault_password_for(profile_ref)?;
    let before = vault.read_items_with(Some(&password))?;
    println!("{} item(s) to migrate", before.len());
    // A wrong password must not be discovered halfway through: v1 leaves the item list readable, so
    // decrypt one secret first and stop here if it fails.
    if let Some(first) = before.first() {
        vault
            .get(&first.name, &password)
            .context("the password does not open this vault; nothing was written")?;
    }

    if dry_run {
        println!("--dry-run: would write a {} envelope with {} item(s)", bigbang::vault2::FORMAT, before.len());
        return Ok(());
    }

    vault.write_envelope(&before, &password)?;

    // Read it back through the same path a normal run uses, and compare.
    let after = vault.read_items_with(Some(&password))?;
    if after.len() != before.len() {
        anyhow::bail!(
            "migration wrote {} item(s) but {} came back — the previous version is still in \
             .vault-versions and the pointer can be moved back to it",
            before.len(), after.len()
        );
    }
    for (a, b) in before.iter().zip(after.iter()) {
        if a.name != b.name || a.encrypted_content != b.encrypted_content || a.rest != b.rest {
            anyhow::bail!("item '{}' did not survive the migration intact", a.name);
        }
    }
    // And prove a secret still decrypts, not merely that the bytes match.
    if let Some(first) = after.first() {
        vault.get(&first.name, &password).context("a migrated secret failed to decrypt")?;
    }

    println!("✓ migrated to {} — {} item(s) verified", bigbang::vault2::FORMAT, after.len());
    println!("  names, descriptions and restrictions are now inside the envelope");
    println!("  the previous version remains in .vault-versions");
    Ok(())
}

fn vault_lock(profile_ref: &str) -> Result<()> {
    use bigbang::agent;
    let profile = Profile::open(profile_ref)?;
    let socket = agent::socket_path(&profile.name);
    if !socket.exists() {
        println!("'{}' is not unlocked", profile.name);
        return Ok(());
    }
    std::fs::remove_file(&socket).with_context(|| format!("removing {}", socket.display()))?;
    println!("🔒 {} locked", profile.name);
    Ok(())
}

fn vault_status(profile_ref: &str) -> Result<()> {
    use bigbang::agent;
    let profile = Profile::open(profile_ref)?;
    let socket = agent::socket_path(&profile.name);
    if agent::is_running(&socket) {
        println!("🔓 {} is unlocked ({})", profile.name, socket.display());
    } else {
        println!("🔒 {} is locked", profile.name);
    }
    Ok(())
}

/// Everything the --generate family carries.
struct GenerateOptions {
    generate: bool,
    length: usize,
    min_length: Option<usize>,
    max_length: Option<usize>,
    special: bool,
    charset: Option<String>,
    comment: Option<String>,
}

/// The value comes from exactly one of: --data, --data-file, stdin, or --generate.
///
/// A private key passed as --data sits in the process's argv, where anything else on the machine
/// can read it out of `ps` for as long as the command runs. A file, stdin or generation costs
/// nothing and closes that.
/// Ask the operator for an item, then wait for the vault to receive it.
///
/// The waiting is the interesting part, and it is deliberately blunt. Nothing is written
/// back to this process, so the only evidence the operator finished is the vault changing
/// on disk. A v2 vault will not list its contents without the password — which is the
/// property being paid for, not an obstacle to route around — so this watches the file
/// rather than its contents. It learns that *something* was stored, never what.
///
/// The precise check is used where it is honestly available: a vault that does not exist
/// yet, or a v1 vault whose names are in the clear.
fn vault_request(
    item_id: &str,
    type_: &str,
    description: Option<&str>,
    timeout_secs: u64,
    profile_ref: &str,
) -> Result<()> {
    use bigbang::request;

    let profile = Profile::open(profile_ref)?;
    let vault_root = std::path::PathBuf::from(Profile::expand(&profile.vault_path));

    // Already present is a success, not an error: this is meant to be safe to call from a
    // recipe that runs more than once.
    if vault_holds(profile_ref, item_id) == Some(true) {
        println!("✓ {item_id} is already in the vault");
        return Ok(());
    }

    if !request::receiver_present() {
        anyhow::bail!(
            "no bgconsole is listening at {} — start bgconsole, or add the item directly with\n    bigbang vault add --prompt --profile {profile_ref} --item-id {item_id}",
            request::request_dir().display()
        );
    }

    let before = vault_fingerprint(&vault_root);
    let path = request::ask_for_item(profile_ref, item_id, type_, description)?;
    println!("→ asked for {item_id} in a terminal this process cannot read");

    let found = request::wait_for(std::time::Duration::from_secs(timeout_secs), || {
        match vault_holds(profile_ref, item_id) {
            Some(present) => present,
            // Encrypted listing: the change on disk is all this process may know.
            None => vault_fingerprint(&vault_root) != before,
        }
    })?;

    request::withdraw(&path);

    if !found {
        anyhow::bail!("{item_id} was not stored within {timeout_secs}s");
    }
    match vault_holds(profile_ref, item_id) {
        Some(true) => println!("✓ {item_id} is in the vault"),
        _ => println!(
            "✓ the vault was written. Its contents are encrypted, so this process cannot \
             confirm the item by name — the next command that uses it will."
        ),
    }
    Ok(())
}

/// Whether the vault holds an item — `None` when that cannot be answered without the
/// password, which is not a failure but the encryption working.
fn vault_holds(profile_ref: &str, item_id: &str) -> Option<bool> {
    use bigbang::vault::Format;
    let vault = open_vault(profile_ref).ok()?;
    match vault.format() {
        Ok(Format::V2) => None,
        Ok(_) => Some(
            vault
                .read_items_with(None)
                .map(|items| items.iter().any(|i| i.name == item_id))
                .unwrap_or(false),
        ),
        // No vault yet: nothing is in it.
        Err(_) => Some(false),
    }
}

/// A cheap signature of the vault on disk: how many files, their total size, and the newest
/// modification time. Enough to notice that the operator stored something, and nothing more.
fn vault_fingerprint(root: &std::path::Path) -> (usize, u64, u64) {
    fn walk(dir: &std::path::Path, acc: &mut (usize, u64, u64)) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                walk(&entry.path(), acc);
            } else {
                acc.0 += 1;
                acc.1 += meta.len();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                acc.2 = acc.2.max(mtime);
            }
        }
    }
    let mut acc = (0usize, 0u64, 0u64);
    walk(root, &mut acc);
    acc
}

/// Read a multi-line value from the terminal with echo off.
///
/// Reads `/dev/tty` rather than standard input, so this keeps working when the process was
/// started with its stdin redirected — which is the normal case for a command bgconsole
/// typed into a shell. Echo is disabled around the read and restored afterwards, including
/// on the error paths, because a terminal left with echo off looks broken and the operator
/// has no way to know why.
fn read_hidden_block(prompt: &str) -> Result<String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::io::AsRawFd;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening /dev/tty — a prompt needs a terminal")?;
    let fd = tty.as_raw_fd();

    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
        anyhow::bail!("reading the terminal settings");
    }
    let restore = term;
    term.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        anyhow::bail!("turning the echo off — refusing to read a value that would be shown");
    }

    let mut out = std::io::stderr();
    let _ = writeln!(out, "{prompt}");
    let mut text = String::new();
    let mut reader = BufReader::new(&tty);
    let mut line = String::new();
    let result = loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break Ok(()),
            Ok(_) => text.push_str(&line),
            Err(e) => break Err(e),
        }
    };

    // Restored whichever way the loop ended.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &restore) };
    let _ = writeln!(out);
    result.context("reading the value")?;
    Ok(text)
}

fn vault_add(
    item_id: &str,
    data: Option<&str>,
    data_file: Option<&std::path::Path>,
    stdin: bool,
    prompt: bool,
    multiline: bool,
    replace: bool,
    gen: GenerateOptions,
    restriction: &str,
    prepared_file: Option<&std::path::Path>,
    type_: &str,
    description: Option<&str>,
    profile_ref: &str,
) -> Result<()> {
    let restriction = bigbang::vault::Restriction::parse(restriction)?;
    let prepared: Vec<bigbang::vault::PreparedCommand> = match prepared_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing prepared commands from {}", path.display()))?
        }
        None => Vec::new(),
    };
    // A prepared item with no commands is unreachable: nothing may substitute it and there is
    // nothing to invoke. Storing it would look like protection and be a dead credential.
    for command in &prepared {
        command.validate()?;
    }
    if restriction == bigbang::vault::Restriction::Prepared && prepared.is_empty() {
        anyhow::bail!(
            "--restriction prepared needs --prepared-file: without a command the item cannot be \
             used at all, which is a dead credential rather than a protected one"
        );
    }
    if !prepared.is_empty() && restriction != bigbang::vault::Restriction::Prepared {
        anyhow::bail!("--prepared-file only means something with --restriction prepared");
    }
    let mut public_key: Option<String> = None;

    // Asked for on the terminal, never echoed, and typed twice. The confirmation is not
    // ceremony: a mistyped secret stores cleanly and fails later against whatever it was
    // meant to authenticate to, with nothing pointing back here.
    let prompted = if prompt {
        if multiline {
            // A private key cannot be typed on one line, and pasting one through a file
            // would put it on the disk of the very machine the prompt exists to keep it off.
            // So: read until end-of-input, echoing nothing, and confirm by shape rather than
            // by asking for the whole thing twice — nobody re-pastes a 3 kB key correctly,
            // and a confirmation people work around is worse than none.
            let text = read_hidden_block(&format!(
                "Paste the value for {item_id}, then press Ctrl-D on a blank line:"
            ))?;
            if text.trim().is_empty() {
                anyhow::bail!("refusing to store an empty value");
            }
            println!(
                "  read {} bytes over {} lines",
                text.len(),
                text.lines().count()
            );
            Some(text)
        } else {
            let first = rpassword::prompt_password(format!("Value for {item_id}: "))
                .context("reading the value")?;
            if first.is_empty() {
                anyhow::bail!("refusing to store an empty value");
            }
            let again = rpassword::prompt_password("Type it again: ").unwrap_or_default();
            if first != again {
                anyhow::bail!("the two values did not match — nothing was stored");
            }
            Some(first)
        }
    } else {
        None
    };

    let value = match (prompted.as_deref().or(data), data_file, stdin, gen.generate) {
        (Some(d), _, _, _) => d.to_string(),
        (_, Some(path), _, _) => std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?,
        (_, _, true, _) => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).context("reading the value from stdin")?;
            buf
        }
        (_, _, _, true) => {
            // The type decides what "generate" means. An SSH_KEY item wants a keypair, not a
            // random string that happens to be stored under the same name.
            if type_.eq_ignore_ascii_case("SSH_KEY") {
                let comment = gen.comment.clone().unwrap_or_else(|| item_id.to_string());
                let (private, public) = bigbang::vault::generate_ssh_key(&comment)?;
                public_key = Some(public);
                private
            } else {
                let extra = match (&gen.charset, gen.special) {
                    (Some(chars), _) => chars.clone(),
                    (None, true) => bigbang::vault::SAFE_SPECIALS.to_string(),
                    (None, false) => String::new(),
                };
                let (min, max) = match (gen.min_length, gen.max_length) {
                    (None, None) => (gen.length, gen.length),
                    (Some(a), None) => (a, a.max(gen.length)),
                    (None, Some(b)) => (gen.length.min(b), b),
                    (Some(a), Some(b)) => (a, b),
                };
                if min < 16 {
                    anyhow::bail!("{min} is too short to generate; 16 is the floor, 32 the default");
                }
                bigbang::vault::generate_secret_in_range(min, max, &extra)?
            }
        }
        _ => anyhow::bail!(
            "supply the value with --data, --data-file <path>, --stdin, or --generate"
        ),
    };
    if value.trim().is_empty() {
        anyhow::bail!("refusing to store an empty value as '{item_id}'");
    }

    let vault = open_vault(profile_ref)?;
    let password = if vault.format()? == bigbang::vault::Format::New {
        new_vault_password()?
    } else {
        vault_password_for(profile_ref)?
    };
    // The public half of a keypair is not a secret, and is stored unencrypted beside the item so
    // it can be read back — and handed to a cloud provider — without the vault password at all.
    let mut meta = serde_json::Map::new();
    if let Some(pk) = &public_key {
        meta.insert("publicKey".to_string(), serde_json::Value::String(pk.clone()));
    }
    if restriction != bigbang::vault::Restriction::None {
        meta.insert("restriction".to_string(), serde_json::to_value(restriction)?);
    }
    if !prepared.is_empty() {
        meta.insert("preparedCommands".to_string(), serde_json::to_value(&prepared)?);
    }
    let metadata = if meta.is_empty() { None } else { Some(meta) };
    vault.add_or_replace(item_id, type_, description, &value, &password, metadata, replace)?;

    // Deliberately reports the length rather than any part of the value.
    println!("✓ Added vault item: {item_id} ({} bytes, {type_})", value.len());
    if gen.generate {
        println!("  generated and stored; it has not been displayed and is not recoverable from this output");
    }
    match restriction {
        bigbang::vault::Restriction::Prepared => println!(
            "  restricted: usable only through {} prepared command(s): {}",
            prepared.len(),
            prepared.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", ")
        ),
        bigbang::vault::Restriction::Always => {
            println!("  restricted: never held by the agent; every use asks for the password")
        }
        bigbang::vault::Restriction::None => {}
    }
    if let Some(pk) = public_key {
        println!();
        println!("Public key — not a secret, give this to the provider:");
        println!("{pk}");
    }
    Ok(())
}

/// Where the ssh control sockets live for one run of one recipe.
///
/// Only created when the recipe asks for `singleSession`. The directory is
/// removed when this value drops, which also removes the sockets — an ssh
/// master whose socket is gone exits on its own, so an abandoned run does not
/// leave a connection open.
///
/// Kept short (`/tmp/bb-<pid>`) on purpose: a unix socket path has about a
/// hundred bytes to work with, and a long one fails at connect time rather than
/// anywhere informative.
struct Sessions {
    dir: Option<PathBuf>,
}

impl Sessions {
    fn new(enabled: bool) -> Self {
        if !enabled {
            return Sessions { dir: None };
        }
        let dir = std::env::temp_dir().join(format!("bb-{}", std::process::id()));
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Sessions { dir: Some(dir) },
            Err(e) => {
                // Not fatal: without a socket every command opens its own
                // connection, which is what it did before this existed.
                eprintln!("bigbang: no shared ssh session ({e}); connecting per command");
                Sessions { dir: None }
            }
        }
    }

    fn path_for(&self, host: &str) -> Option<String> {
        let dir = self.dir.as_ref()?;
        // One socket per host, named by a hash so the length is bounded
        // whatever the instance is called.
        let mut h: u64 = 1469598103934665603;
        for b in host.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        Some(dir.join(format!("{h:x}")).to_string_lossy().into_owned())
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn recipe_execute(
    id: &str,
    profile_ref: &str,
    dry_run: bool,
    vars: &[String],
    resources: &[PathBuf],
) -> Result<()> {
    use bigbang::exec::{run_definition_with, CommandExecutor, LocalExecutor, SshExecutor};
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
    let password = || vault_password_for(profile_ref);
    let profile_vault = Some((profile.account_code.as_str(), profile.default_vault_name.as_str()));
    let resolved = resolve_all_in(&recipe.variables, &vault_root, profile_vault, &password, &overrides)?;
    let recipe_vars = resolved.values;
    let mut secret_values = resolved.secrets;
    let instances = load_instances(&store)?;
    let library_root = PathBuf::from(Profile::expand(&profile.library_path));

    // A directory that is not there resolves nothing, and the run would fail later at the
    // upload naming the file rather than the flag. Refuse now, while the message can still
    // be about the argument that was wrong.
    let mut resource_roots = Vec::new();
    for dir in resources {
        let expanded = PathBuf::from(Profile::expand(&dir.to_string_lossy()));
        let canonical = expanded.canonicalize().with_context(|| {
            format!("--resources {}: no such directory", expanded.display())
        })?;
        if !canonical.is_dir() {
            anyhow::bail!("--resources {}: not a directory", canonical.display());
        }
        resource_roots.push(canonical);
    }

    // Resolve every role first, and refuse before running anything.
    //
    // Two separate refusals, both of which used to be silent. A role declaring
    // something this code does not implement is a promise that reads as kept.
    // A role matching no machine used to print a line and let the recipe report
    // success — and because a single host tagged with every role makes every
    // selector correct, that only bites once the topology splits.
    let mut plan: Vec<(&bigbang::recipe::Role, Vec<_>)> = Vec::new();
    let mut complaints: Vec<String> = Vec::new();
    let unhonoured = bigbang::recipe::unhonoured_recipe_fields(&recipe);
    if !unhonoured.is_empty() {
        complaints.push(format!(
            "this recipe declares {} — nothing here implements that",
            unhonoured.join(", ")
        ));
    }
    for role in &recipe.roles {
        let unhonoured = bigbang::recipe::unhonoured_role_fields(role);
        if !unhonoured.is_empty() {
            complaints.push(format!(
                "role '{}' declares {} this version does not implement",
                role.name,
                unhonoured.join(", ")
            ));
        }
        let targets = resolve_role_targets(
            &instances,
            &recipe.project_id,
            role.infrastructure_ids.as_ref(),
            role.selectors.as_ref(),
        );
        if let Some(why) = bigbang::recipe::role_shortfall(role, targets.len()) {
            let how = match (&role.infrastructure_ids, &role.selectors) {
                (Some(ids), _) if !ids.is_empty() => format!("ids {}", ids.join(", ")),
                (_, Some(sel)) if !sel.is_empty() => format!("selectors {}", sel.join(", ")),
                _ => "no selector at all".to_string(),
            };
            complaints.push(format!("role '{}' {why} — matching on {how}", role.name));
        }
        plan.push((role, targets));
    }

    println!();
    println!("Plan:");
    for (role, targets) in &plan {
        let want = match role.count {
            Some(n) => format!("expects {n}"),
            None => "expects ≥1".to_string(),
        };
        println!(
            "  role '{}' → {} instance(s) ({want})",
            role.name,
            targets.len()
        );
        for t in targets.iter() {
            println!("      {}", t.name);
        }
    }

    // Every package a role runs declares what a host must have — memory, disk, OS —
    // and until now nothing read it. Those requirements become prerequisites here, so
    // the component that needs the memory is the one that says so and a recipe
    // composed of three packages inherits all three sets without copying anything.
    let mut package_checks: Vec<bigbang::recipe::Prerequisite> = Vec::new();
    for (_, targets) in &plan {
        if targets.is_empty() {
            continue;
        }
        for role in recipe.roles.iter() {
            for item in &role.items {
                let Some(coordinate) = item.package.as_deref() else { continue };
                let Some((name, req)) =
                    bigbang::task::PackageDefinition::requirements_of(&library_root, coordinate)
                else {
                    continue;
                };
                for (check, command, why) in req.checks(&name) {
                    if package_checks.iter().any(|p| p.check == check) {
                        continue;
                    }
                    package_checks.push(bigbang::recipe::Prerequisite {
                        check,
                        command,
                        failure_message: Some(why),
                    });
                }
            }
        }
        break;
    }
    let all_prerequisites: Vec<&bigbang::recipe::Prerequisite> =
        recipe.prerequisites.iter().chain(package_checks.iter()).collect();

    // Prerequisites are checked on every machine the recipe targets, before any
    // of them is touched. Checking them per host as its turn came would mean
    // the first host is already changed when the second fails its check, which
    // is the half-deployed state the checks exist to avoid.
    let sessions = Sessions::new(recipe.single_session);
    if dry_run && !all_prerequisites.is_empty() {
        // A prerequisite is an arbitrary command from the recipe. Running it
        // would make --dry-run something that executes, which is the one thing
        // it promises not to be. Say they were skipped rather than let a clean
        // dry run imply they passed.
        println!();
        println!(
            "Prerequisites: {} not checked — a dry run does not execute them",
            all_prerequisites.len()
        );
        for p in &all_prerequisites {
            println!("  ⊘ {}", p.check);
        }
    }
    if !all_prerequisites.is_empty() && complaints.is_empty() && !dry_run {
        let mut seen: Vec<String> = Vec::new();
        println!();
        println!("Prerequisites:");
        for (_, targets) in &plan {
            for instance in targets {
                if seen.contains(&instance.name) {
                    continue;
                }
                seen.push(instance.name.clone());
                // Declared out here so the temporary key file lives as long as the
                // executor that names it. Bound inside the branch, it would be
                // deleted the moment the branch ended and every check would fail
                // to authenticate.
                let _key_guard;
                let mut probe: Box<dyn CommandExecutor> = if instance.is_local() {
                    Box::new(LocalExecutor { echo: false, secrets: Vec::new() })
                } else {
                    let key_id = instance.ssh_key_id.as_deref().with_context(|| {
                        format!("no sshKeyId on instance {}", instance.name)
                    })?;
                    let key = resolve_ssh_key(key_id, &vault_root, &password)?;
                    let target =
                        ssh_target_for(instance, &instances, &key.path.to_string_lossy(), None)?;
                    let ex = SshExecutor {
                        target,
                        echo: false,
                        secrets: Vec::new(),
                        control_path: sessions.path_for(&instance.name),
                    };
                    _key_guard = key;
                    Box::new(ex)
                };
                for p in &all_prerequisites {
                    // Up to 3 attempts, 2s apart. Safe to retry blindly here in a way it would
                    // not be for a task command: a prerequisite is always a read-only shell test
                    // (free, df, grep) with no side effect to double up on, never a mutation --
                    // unlike the retry that once turned one bad photo upload into a permanent
                    // loop, there is nothing here for a retry to repeat that matters.
                    //
                    // Added after finding a real, unexplained intermittent failure: one specific
                    // CI environment's ssh process closing its own connection to a jump host
                    // mid-authentication, consistently, on a host independently proven reachable
                    // and correctly configured moments apart from the same environment. Neither a
                    // jump-hop identity bug nor the jump host's own connection-flood defenses
                    // explained it (both investigated and ruled out or fixed on their own
                    // merits) -- this does not fix the root cause, it works around it the way any
                    // unexplained transient network failure gets worked around.
                    const ATTEMPTS: u32 = 3;
                    let mut result = probe.run(&p.command, 60)?;
                    let mut attempt = 1;
                    while result.exit_code != 0 && attempt < ATTEMPTS {
                        attempt += 1;
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        result = probe.run(&p.command, 60)?;
                    }
                    let ok = result.exit_code == 0;
                    println!(
                        "  {} {} — {}{}",
                        if ok { "✓" } else { "✗" },
                        instance.name,
                        p.check,
                        if attempt > 1 { format!(" (attempt {attempt}/{ATTEMPTS})") } else { String::new() }
                    );
                    if !ok {
                        // Found live: a prerequisite failing here looked identical whether the
                        // check genuinely evaluated false (real host state) or ssh itself never
                        // connected at all (auth failure, timeout, network) -- exit_code alone
                        // does not distinguish "1" from "255", and the actual ssh output (which
                        // would say which one) was captured and then silently thrown away. Three
                        // unrelated checks (memory, disk, OS) all failing at once on a host
                        // already proven reachable was the exact shape this produced -- an
                        // operator staring at "needs 512 MB" for a host with 4 GB, unable to tell
                        // that ssh, not the host, was the actual problem.
                        if !result.output.trim().is_empty() {
                            let shown = bigbang::exec::mask(result.output.trim(), probe.secrets());
                            println!("      {}", shown.replace('\n', "\n      "));
                        }
                        complaints.push(p.complaint(&instance.name));
                    }
                }
            }
        }
    }

    if !complaints.is_empty() {
        println!();
        for c in &complaints {
            println!("  ✗ {c}");
        }
        anyhow::bail!(
            "this recipe cannot run here — nothing was run.\n    A role matching the wrong number of machines means the inventory is missing\n    something or a selector is wrong; a role that may genuinely be absent should\n    say so with \"count\": 0.\n    A failed prerequisite means the machine is not ready, and the recipe said so\n    rather than finding out halfway."
        );
    }

    let mut failures = 0usize;
    let mut targeted = 0usize;
    for (role, targets) in plan {
        println!();
        println!("── role '{}' → {} instance(s)", role.name, targets.len());
        targeted += targets.len();
        if targets.is_empty() {
            continue;
        }

        let role_resolved = resolve_all_in(&role.variables, &vault_root, profile_vault, &password, &overrides)?;
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

                // A task's own variables may hold `vault:` references too, and until now nothing
                // resolved them: only recipe and role variables went through resolve_all, so
                // setup-pgbackrest wrote the literal text `vault:backup_s3_access_key` into
                // pgbackrest.conf. Resolved here, at lower precedence than the recipe's, which is
                // the order run_definition already applies.
                //
                // This runs BEFORE the executor is built, and the order is the whole point. The
                // executor takes a snapshot of the secret list, so resolving task variables after
                // it was constructed left every task-level secret substituted into commands but
                // absent from the mask — and the echoed command printed it in clear. That is how
                // an S3 access key and secret reached a terminal during a test-data run.
                let task_resolved = resolve_all_in(
                    &definition
                        .variables
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect(),
                    &vault_root,
                    profile_vault,
                    &password,
                    &overrides,
                )?;
                secret_values.extend(task_resolved.secrets.clone());
                let mut definition = definition.clone();
                definition.variables = task_resolved.values;

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
                    Box::new(SshExecutor {
                        target,
                        echo: true,
                        secrets,
                        control_path: sessions.path_for(&instance.name),
                    })
                };

                // Functions need more than a shell: where templates live, and a vault to write to.
                let function_vault = open_vault(profile_ref).ok();
                let ctx = bigbang::functions::FunctionContext {
                    resources_root: library_root.join("resources"),
                    extra_resource_roots: resource_roots.clone(),
                    vault: function_vault.as_ref(),
                    vault_password: &password,
                    // Provisioning registers what it created, into the same store the recipe was
                    // resolved from.
                    store: Some(&store),
                    echo: true,
                };
                let outcomes =
                    run_definition_with(&definition, &merged, executor.as_mut(), Some(&ctx))?;
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

/// Copy a directory tree, returning how many files landed.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> Result<usize> {
    let mut count = 0usize;
    std::fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    for entry in std::fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            count += copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)
                .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
            count += 1;
        }
    }
    Ok(count)
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
    // Templates travel with the definitions that reference them. Installing the JSON and leaving
    // the resources behind gives a task that parses, runs, and fails at the upload — the failure
    // arriving on the host rather than here.
    if source.is_dir() {
        let resources = source.join("resources");
        if resources.is_dir() {
            let copied = copy_tree(&resources, &library.root().join("resources"))?;
            println!("Resources: {copied} file(s)");
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
            // `resources` holds the files tasks upload, not definitions. A library whose
            // resources include a .json — a docker daemon.json, a kubernetes manifest —
            // otherwise had that file installed as a task, which fails with "has no
            // 'group' field" and makes the whole install exit non-zero. Nothing in there
            // is ever a definition, so nothing in there is ever a candidate.
            if recursive && path.file_name().is_some_and(|n| n != "resources") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_resource_is_not_mistaken_for_a_definition() {
        // `library install --source tasks -r` walks the tree. `resources/` holds the files
        // tasks upload; a docker daemon.json or a kubernetes manifest in there was installed
        // as a task, failed with "has no 'group' field", and took the whole install's exit
        // code with it — a library carrying one could never install cleanly.
        let root = std::env::temp_dir().join(format!("bb-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("resources/deploy-test-static-site")).unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("install-haproxy.json"), "{}").unwrap();
        std::fs::write(root.join("nested/setup-nginx.json"), "{}").unwrap();
        std::fs::write(root.join("resources/deploy-test-static-site/daemon.json"), "{}").unwrap();

        let mut found = Vec::new();
        collect_json(&root, true, &mut found).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"install-haproxy.json".to_string()));
        assert!(names.contains(&"setup-nginx.json".to_string()), "other directories are still walked");
        assert!(!names.contains(&"daemon.json".to_string()), "nothing under resources/ is a definition");

        let _ = std::fs::remove_dir_all(&root);
    }
}
