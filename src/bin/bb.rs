//! `bb` — run a command with secrets from an unlocked vault, without ever holding them.
//!
//! ```text
//! bb --profile int -- psql -h db -U colistor_int          # nothing injected
//! bb --profile int --env PGPASSWORD={{int-db-password}} -- psql -h db -U colistor_int
//! bb --profile int -- curl -H 'Authorization: Bearer {{api-token}}' https://…
//! ```
//!
//! The request goes to the agent, which substitutes, runs the command and returns the output with
//! the injected values redacted. This process never sees a secret — which is the point, since it is
//! the process whose command line an operator (or an assistant) composes.
//!
//! `--env` is the better form wherever the tool accepts it: a value substituted into an argument is
//! visible in `ps` for the life of the child, and one passed in the environment is not.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;

use anyhow::{Context, Result};

use bigbang::agent::{self, AgentRequest};
use bigbang::profile::Profile;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("❌ {err:#}");
            ExitCode::from(1u8)
        }
    }
}

fn usage() -> ! {
    eprintln!("bb — run a command with secrets from an unlocked vault");
    eprintln!();
    eprintln!("  bb --profile <name> [--env NAME={{{{item}}}}]... -- <command> [args]");
    eprintln!();
    eprintln!("  {{{{item-name}}}} in any argument or --env value is replaced by the agent.");
    eprintln!("  Prefer --env: a value in an argument is visible in `ps`.");
    eprintln!();
    eprintln!("  Unlock first:  bigbang vault unlock --profile <name>");
    std::process::exit(2)
}

fn run() -> Result<u8> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        usage();
    }

    let mut profile_ref: Option<String> = None;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--profile" => {
                profile_ref = args.get(index + 1).cloned();
                index += 2;
            }
            "--env" => {
                let pair = args.get(index + 1).context("--env needs NAME=VALUE")?;
                let (name, value) = pair
                    .split_once('=')
                    .with_context(|| format!("--env expects NAME=VALUE, got '{pair}'"))?;
                env.insert(name.to_string(), value.to_string());
                index += 2;
            }
            other if other.starts_with('-') => {
                anyhow::bail!("unknown option '{other}' — put the command after --");
            }
            _ => break,
        }
    }

    let argv: Vec<String> = args[index..].to_vec();
    if argv.is_empty() {
        usage();
    }

    // A profile is required rather than guessed: silently picking one would run a command against
    // whichever environment happened to be unlocked.
    let profile_ref = profile_ref.context("--profile is required")?;
    let profile = Profile::open(&profile_ref)?;
    let socket = agent::socket_path(&profile.name);

    // Warn where a value would land in argv, since ps shows that to everything on the machine.
    if argv.iter().any(|a| a.contains("{{")) {
        eprintln!(
            "⚠️  a value substituted into an argument is visible in `ps` while the command runs; \
             use --env NAME={{{{item}}}} where the tool allows it"
        );
    }

    let response = agent::send(
        &socket,
        &AgentRequest {
            argv,
            env,
            cwd: std::env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()),
        },
    )?;

    if let Some(error) = response.error {
        anyhow::bail!(error);
    }
    print!("{}", response.stdout);
    std::io::stdout().flush().ok();
    eprint!("{}", response.stderr);
    std::io::stderr().flush().ok();

    // The child's exit code is the point of running it; clamp only because a process exit status is
    // a byte.
    Ok(response.exit_code.clamp(0, 255) as u8)
}
