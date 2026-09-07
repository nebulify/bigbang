//! An unlocked vault, held by a process, reachable over a Unix socket.
//!
//! The problem it solves is ergonomic first: without it the vault password is typed for every
//! operation, which is unusable when a session performs dozens. `ssh-agent` and `gpg-agent` exist
//! for the same reason.
//!
//! ## Why the agent runs the command
//!
//! The obvious design has the client ask for a value and substitute it. That hands the plaintext to
//! the client, which defeats the purpose: the point is that whoever composes the command never
//! holds the secret. So the request travels *to* the agent, the agent substitutes, execs the child
//! and streams back output with the injected values redacted. The client is a pipe.
//!
//! This is also what makes the next step possible. Running the agent under its own UID — a systemd
//! service, socket group-readable — turns a convention into a boundary the client cannot cross,
//! and nothing about the protocol has to change. Socket-first from the start, so that move is a
//! unit file rather than a rewrite.
//!
//! ## What it does not do
//!
//! It does not contain a determined caller. `bb -- sh -c 'echo {{secret}} | base64'` transforms the
//! value inside the child, and redaction only sees the encoded result. What it reliably prevents is
//! the realistic failure: secrets in terminal scrollback, transcripts, CI logs and `ps` — all of
//! which persist and get shared. Combined with an allowlist of which items are unlocked at all, a
//! mistake with the wrong credential becomes impossible rather than unlikely.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// What the agent holds for one item.
#[derive(Debug, Clone)]
pub struct UnlockedItem {
    pub value: String,
    pub restriction: crate::vault::Restriction,
    pub prepared: Vec<crate::vault::PreparedCommand>,
}

/// Where the agent can re-read the vault from when it is asked for something it does not hold.
#[derive(Debug, Clone)]
pub struct VaultSource {
    pub root: String,
    pub account: String,
    pub project: String,
    /// The allowlist given at unlock. Re-reading must not quietly widen it.
    pub wanted: Vec<String>,
}

/// Decrypt a vault into the map the agent serves.
///
/// Shared by `vault unlock` and by the agent's own reload, so the allowlist and the handling of the
/// `always` tier cannot drift between the two.
pub fn load_items(
    vault: &crate::vault::Vault,
    password: &str,
    wanted: &[String],
) -> Result<(BTreeMap<String, UnlockedItem>, Vec<String>)> {
    let mut items = BTreeMap::new();
    let mut withheld = Vec::new();
    for item in vault.read_items_with(Some(password))? {
        let name = item.name.clone();
        if !wanted.is_empty() && !wanted.iter().any(|w| w == &name) {
            continue;
        }
        let restriction = item.restriction();
        if restriction == crate::vault::Restriction::Always {
            withheld.push(name);
            continue;
        }
        if let Some(value) = vault.get(&name, password)? {
            items.insert(name, UnlockedItem { value, restriction, prepared: item.prepared_commands() });
        }
    }
    Ok((items, withheld))
}

/// Invoking a capability rather than composing a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPrepared {
    pub item: String,
    pub command: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    /// The command and its arguments. `{{name}}` in any element is replaced by the agent.
    pub argv: Vec<String>,
    /// Environment for the child. Values may contain `{{name}}`; this is the form that keeps a
    /// secret out of `ps`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// When set, `argv` and `env` are ignored: the structure comes from the vault instead.
    #[serde(default)]
    pub run_prepared: Option<RunPrepared>,
    /// Ask the agent for the vault password, so `bigbang` can resolve its own `vault:` references
    /// without prompting for every recipe run.
    ///
    /// This hands the password to the caller, which the rest of the protocol exists to avoid — but
    /// the caller here is bigbang resolving a reference it would otherwise have prompted for, and
    /// refusing would mean the agent helps with everything except deployments, which is the reason
    /// it exists. It is a separate field so the audit log records exactly when it happened.
    #[serde(default)]
    pub request_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    /// Only set in reply to `request_password`.
    #[serde(default)]
    pub password: Option<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Set when the agent refused before running anything.
    #[serde(default)]
    pub error: Option<String>,
}

/// Where a profile's socket lives.
///
/// `$XDG_RUNTIME_DIR` is per-user and cleared at logout, which is the right lifetime for an
/// unlocked vault. Falling back to /tmp keeps it working on systems without one, at the cost of
/// surviving a logout — the directory is still 0700.
pub fn socket_dir() -> PathBuf {
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir).join("bigbang"),
        _ => std::env::temp_dir().join(format!("bigbang-{}", current_uid())),
    }
}

fn current_uid() -> u32 {
    // Read from /proc rather than taking a libc dependency for one number.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|uid| uid.parse().ok())
        .unwrap_or(0)
}

pub fn socket_path(profile_name: &str) -> PathBuf {
    let safe: String = profile_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    socket_dir().join(format!("{safe}.sock"))
}

/// Replace `{{name}}` from the unlocked items, reporting which values were used.
///
/// A placeholder naming something that is not unlocked is an error rather than being left as
/// written. In a command the literal text `{{db_password}}` would reach the far side and be used as
/// a password, which fails in a way that looks like the wrong credential rather than a missing one.
pub fn substitute(
    input: &str,
    items: &BTreeMap<String, String>,
    used: &mut Vec<String>,
) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        let Some(end) = rest[start..].find("}}") else { break };
        let name = rest[start + 2..start + end].trim().to_string();
        out.push_str(&rest[..start]);
        let Some(value) = items.get(&name) else {
            bail!(
                "'{name}' is not unlocked in this agent. Unlocked: {}",
                if items.is_empty() {
                    "(nothing)".to_string()
                } else {
                    items.keys().cloned().collect::<Vec<_>>().join(", ")
                }
            );
        };
        out.push_str(value);
        if !used.contains(value) {
            used.push(value.clone());
        }
        rest = &rest[start + end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Every `{{name}}` in a string.
fn placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let Some(end) = rest[start..].find("}}") else { break };
        out.push(rest[start + 2..start + end].trim().to_string());
        rest = &rest[start + end + 2..];
    }
    out
}

/// Remove every injected value from text the caller will see.
pub fn redact(text: &str, values: &[String]) -> String {
    let mut out = text.to_string();
    for value in values {
        // Below six characters, replacing would shred unrelated output for no gain.
        if value.len() >= 6 {
            out = out.replace(value.as_str(), "«redacted»");
        }
    }
    out
}

fn refuse(message: String) -> AgentResponse {
    AgentResponse { password: None, exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some(message) }
}

/// Only unrestricted items may be substituted into a command the caller composed.
///
/// This is where the prepared tier is actually enforced: a `prepared` item is simply not in the map
/// that `{{name}}` is resolved against, so there is no command anyone can write that reaches it.
fn substitutable(items: &BTreeMap<String, UnlockedItem>) -> BTreeMap<String, String> {
    items
        .iter()
        .filter(|(_, item)| item.restriction == crate::vault::Restriction::None)
        .map(|(name, item)| (name.clone(), item.value.clone()))
        .collect()
}

/// Run one request: substitute, exec, redact.
pub fn handle(
    request: &AgentRequest,
    items: &BTreeMap<String, UnlockedItem>,
    password: &str,
) -> AgentResponse {
    if request.request_password {
        return AgentResponse {
            password: Some(password.to_string()),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        };
    }
    if let Some(invocation) = &request.run_prepared {
        return run_prepared(invocation, items);
    }
    // A restricted item that is asked for by name deserves a better answer than "not unlocked":
    // it *is* unlocked, and saying so — along with how to reach it — costs nothing, since the name
    // was supplied by the caller and the value is what stays out of reach.
    for text in request.argv.iter().chain(request.env.values()) {
        for name in placeholders(text) {
            if let Some(item) = items.get(&name) {
                if item.restriction != crate::vault::Restriction::None {
                    return refuse(format!(
                        "'{name}' is restricted and cannot be substituted into a command. Reach it \
                         with: bb --run {name}/<command>{}",
                        if item.prepared.is_empty() {
                            String::new()
                        } else {
                            format!(" — available: {}",
                                item.prepared.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", "))
                        }
                    ));
                }
            }
        }
    }

    let mut used: Vec<String> = Vec::new();
    let plain = substitutable(items);
    let items = &plain;

    let argv: Result<Vec<String>> = request
        .argv
        .iter()
        .map(|a| substitute(a, items, &mut used))
        .collect();
    let argv = match argv {
        Ok(a) => a,
        Err(err) => {
            return AgentResponse { password: None, exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some(format!("{err:#}")) }
        }
    };
    if argv.is_empty() {
        return AgentResponse { password: None, exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some("no command given".into()) };
    }

    let mut env = BTreeMap::new();
    for (key, value) in &request.env {
        match substitute(value, items, &mut used) {
            Ok(v) => {
                env.insert(key.clone(), v);
            }
            Err(err) => {
                return AgentResponse { password: None, exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some(format!("{err:#}")) }
            }
        }
    }

    // No shell. The command is exec'd with its arguments as discrete elements, so a value
    // containing a semicolon or a backtick is data and cannot become syntax.
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    for (key, value) in &env {
        command.env(key, value);
    }
    if let Some(dir) = &request.cwd {
        command.current_dir(dir);
    }

    match command.output() {
        Ok(out) => AgentResponse {
            password: None,
            exit_code: out.status.code().unwrap_or(-1),
            stdout: redact(&String::from_utf8_lossy(&out.stdout), &used),
            stderr: redact(&String::from_utf8_lossy(&out.stderr), &used),
            error: None,
        },
        Err(err) => AgentResponse {
            password: None,
            exit_code: 127,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(format!("running {}: {err}", argv[0])),
        },
    }
}

/// Invoke a capability: the vault supplies the structure, the caller supplies parameters.
fn run_prepared(
    invocation: &RunPrepared,
    items: &BTreeMap<String, UnlockedItem>,
) -> AgentResponse {
    let Some(item) = items.get(&invocation.item) else {
        return refuse(format!(
            "'{}' is not unlocked in this agent. Unlocked: {}",
            invocation.item,
            items.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    };
    let Some(prepared) = item.prepared.iter().find(|c| c.name == invocation.command) else {
        return refuse(format!(
            "'{}' has no prepared command '{}'. Available: {}",
            invocation.item,
            invocation.command,
            if item.prepared.is_empty() {
                "(none)".to_string()
            } else {
                item.prepared.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", ")
            }
        ));
    };

    // Every supplied parameter must be one the command declared. An undeclared parameter is a
    // caller trying to reach something the template did not offer.
    for name in invocation.params.keys() {
        if !prepared.params.contains(name) {
            return refuse(format!(
                "'{name}' is not a parameter of '{}'. Declared: {}",
                prepared.name,
                if prepared.params.is_empty() { "(none)".into() } else { prepared.params.join(", ") }
            ));
        }
    }
    for name in &prepared.params {
        if !invocation.params.contains_key(name) {
            return refuse(format!("'{}' requires the parameter '{name}'", prepared.name));
        }
    }

    // One pass, never rescanned: a parameter value containing "{{self}}" is inert text.
    let fill = |template: &str| -> String {
        let mut out = template.replace("{{self}}", &item.value);
        for (name, value) in &invocation.params {
            out = out.replace(&format!("{{{{param:{name}}}}}"), value);
        }
        out
    };

    let argv: Vec<String> = prepared.argv.iter().map(|a| fill(a)).collect();
    if argv.is_empty() {
        return refuse(format!("prepared command '{}' has no argv", prepared.name));
    }

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    for (key, value) in &prepared.env {
        command.env(key, fill(value));
    }
    let stdin_payload = prepared.stdin.as_ref().map(|s| fill(s));
    command
        .stdin(if stdin_payload.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(err) => return refuse(format!("running {}: {err}", argv[0])),
    };
    if let Some(payload) = &stdin_payload {
        if let Some(mut sink) = child.stdin.take() {
            let _ = sink.write_all(payload.as_bytes());
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(err) => return refuse(format!("waiting for {}: {err}", argv[0])),
    };

    // The secret is redacted whatever the template does, and a command declaring returnsOutput
    // false gives back nothing but its exit code — for tools that echo what they were handed.
    let used = vec![item.value.clone()];
    let (stdout, stderr) = if prepared.returns_output {
        (
            redact(&String::from_utf8_lossy(&out.stdout), &used),
            redact(&String::from_utf8_lossy(&out.stderr), &used),
        )
    } else {
        (String::new(), String::new())
    };
    AgentResponse { password: None, exit_code: out.status.code().unwrap_or(-1), stdout, stderr, error: None }
}

/// Listen until the deadline passes or the socket is removed.
pub fn serve(
    path: &Path,
    items: BTreeMap<String, UnlockedItem>,
    password: String,
    source: Option<VaultSource>,
    ttl: Duration,
    audit: Option<PathBuf>,
) -> Result<()> {
    let mut items = items;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_mode(parent, 0o700)?;
    }
    if path.exists() {
        // A live agent answers; a stale socket from a crash does not and is replaced.
        if UnixStream::connect(path).is_ok() {
            bail!("already unlocked — a live agent is listening on {}", path.display());
        }
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    set_mode(path, 0o600)?;

    // A polling accept loop rather than a blocking one with a thread that exits the process.
    // `serve` returning normally is what makes it testable, and a background thread calling
    // process::exit would take the whole test runner with it.
    listener.set_nonblocking(true)?;
    let deadline = SystemTime::now() + ttl;

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Back to blocking for the conversation itself; the non-blocking mode exists only
                // so that waiting for a connection can also watch the clock.
                stream.set_nonblocking(false)?;
                serve_one(stream, &mut items, &password, source.as_ref(), audit.as_deref());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if SystemTime::now() >= deadline {
                    let _ = std::fs::remove_file(path);
                    return Ok(());
                }
                // `vault lock` removes the socket; an agent nobody can reach should not linger.
                if !path.exists() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => continue,
        }
    }
}

/// Names a request refers to, so a miss can be detected before refusing.
fn referenced(request: &AgentRequest) -> Vec<String> {
    if let Some(run) = &request.run_prepared {
        return vec![run.item.clone()];
    }
    request
        .argv
        .iter()
        .chain(request.env.values())
        .flat_map(|t| placeholders(t))
        .collect()
}

fn serve_one(
    mut stream: UnixStream,
    items: &mut BTreeMap<String, UnlockedItem>,
    password: &str,
    source: Option<&VaultSource>,
    audit: Option<&Path>,
) {
    let Ok(clone) = stream.try_clone() else { return };
    let mut reader = BufReader::new(clone);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let response = match serde_json::from_str::<AgentRequest>(&line) {
        Ok(request) => {
            if let Some(log) = audit {
                append_audit(log, &request);
            }
            // An item added to the vault after unlocking is not in the snapshot. Re-reading on a
            // miss beats making someone lock and unlock to pick it up — and it cannot widen the
            // allowlist, because the same `wanted` list is applied again.
            if let Some(source) = source {
                let missing: Vec<String> = referenced(&request)
                    .into_iter()
                    .filter(|name| !items.contains_key(name))
                    .collect();
                if !missing.is_empty() {
                    let vault = crate::vault::Vault::new(
                        source.root.clone(), source.account.clone(), source.project.clone(),
                    );
                    if let Ok((fresh, _)) = load_items(&vault, password, &source.wanted) {
                        *items = fresh;
                    }
                }
            }
            handle(&request, items, password)
        }
        Err(err) => AgentResponse {
            password: None,
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(format!("malformed request: {err}")),
        },
    };
    let encoded = serde_json::to_string(&response).unwrap_or_default();
    let _ = writeln!(stream, "{encoded}");
    let _ = stream.flush();
}

/// What was asked for, never what was substituted.
fn append_audit(path: &Path, request: &AgentRequest) {
    use std::fs::OpenOptions;
    let when = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    let line = if request.request_password {
        format!("{when} REQUEST_PASSWORD (bigbang resolving its own vault: references)\n")
    } else if let Some(run) = &request.run_prepared {
        format!("{when} run {}/{} params={:?}\n", run.item, run.command, run.params.keys().collect::<Vec<_>>())
    } else {
        format!(
            "{when} argv={:?} env_keys={:?}\n",
            request.argv,
            request.env.keys().collect::<Vec<_>>()
        )
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

pub fn send(path: &Path, request: &AgentRequest) -> Result<AgentResponse> {
    let mut stream = UnixStream::connect(path).with_context(|| {
        format!(
            "no agent on {} — unlock one with: bigbang vault unlock --profile <profile>",
            path.display()
        )
    })?;
    writeln!(stream, "{}", serde_json::to_string(request)?)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).context("reading the agent's reply")?;
    serde_json::from_str(&line).context("parsing the agent's reply")
}

pub fn is_running(path: &Path) -> bool {
    path.exists() && UnixStream::connect(path).is_ok()
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::vault::{PreparedCommand, Restriction};

    fn plain(value: &str) -> UnlockedItem {
        UnlockedItem { value: value.into(), restriction: Restriction::None, prepared: vec![] }
    }

    fn items() -> BTreeMap<String, UnlockedItem> {
        let mut m = BTreeMap::new();
        m.insert("db_password".to_string(), plain("s3cr3t-value-long"));
        m.insert("token".to_string(), plain("tok-abcdefghij"));
        m
    }

    /// An item that may only be reached through a named capability.
    fn restricted() -> BTreeMap<String, UnlockedItem> {
        let mut m = items();
        m.insert(
            "registry_token".to_string(),
            UnlockedItem {
                value: "hunter2-registry-token".into(),
                restriction: Restriction::Prepared,
                prepared: vec![PreparedCommand {
                    name: "show-length".into(),
                    description: None,
                    // Reads the secret from stdin, so it never touches argv or the environment.
                    argv: vec!["sh".into(), "-c".into(), "wc -c".into()],
                    stdin: Some("{{self}}".into()),
                    env: BTreeMap::new(),
                    params: vec![],
                    returns_output: true,
                }],
            },
        );
        m
    }

    fn values() -> BTreeMap<String, String> {
        items().into_iter().map(|(k, v)| (k, v.value)).collect()
    }

    #[test]
    fn placeholders_are_replaced_and_recorded() {
        let mut used = Vec::new();
        let out = substitute("psql://{{db_password}}@host", &values(), &mut used).unwrap();
        assert_eq!(out, "psql://s3cr3t-value-long@host");
        assert_eq!(used, vec!["s3cr3t-value-long".to_string()]);
    }

    /// Leaving it as written would send the literal text onward as if it were the credential.
    #[test]
    fn an_unknown_placeholder_is_an_error_not_a_passthrough() {
        let mut used = Vec::new();
        let err = substitute("{{nope}}", &values(), &mut used).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("not unlocked"), "{text}");
        assert!(text.contains("db_password"), "it should say what is available: {text}");
    }

    #[test]
    fn shell_metacharacters_in_a_value_stay_data() {
        // Deliberately under six characters so redaction leaves it visible; the property under
        // test is that no shell parsed it, not that it was hidden.
        let mut m = BTreeMap::new();
        m.insert("v".to_string(), plain("a;b`c"));

        // Arrives whole: a shell would have split on ';' and run `c` as a command substitution.
        let response = handle(
            &AgentRequest { argv: vec!["echo".into(), "{{v}}".into()], env: BTreeMap::new(), cwd: None, run_prepared: None, request_password: false },
            &m, "pw",
        );
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.stdout.trim_end(), "a;b`c", "value did not survive intact");

        // And it is exactly one argument.
        let counted = handle(
            &AgentRequest {
                argv: vec!["sh".into(), "-c".into(), "echo $#".into(), "_".into(), "{{v}}".into()],
                env: BTreeMap::new(),
                cwd: None, run_prepared: None, request_password: false,
            },
            &m, "pw",
        );
        assert_eq!(counted.stdout.trim_end(), "1", "the value should be a single argument");
    }

    /// The counterpart: a value long enough to be worth hiding is hidden, even here.
    #[test]
    fn a_long_value_is_redacted_even_when_it_contains_metacharacters() {
        let mut m = BTreeMap::new();
        m.insert("v".to_string(), plain("a; rm -rf / --long-enough"));
        let response = handle(
            &AgentRequest { argv: vec!["echo".into(), "{{v}}".into()], env: BTreeMap::new(), cwd: None, run_prepared: None, request_password: false },
            &m, "pw",
        );
        assert!(!response.stdout.contains("rm -rf"), "leaked: {}", response.stdout);
        assert!(response.stdout.contains("«redacted»"), "{}", response.stdout);
    }

    #[test]
    fn injected_values_are_redacted_from_output() {
        let request = AgentRequest {
            argv: vec!["sh".into(), "-c".into(), "echo {{db_password}}".into()],
            env: BTreeMap::new(),
            cwd: None, run_prepared: None, request_password: false,
        };
        let response = handle(&request, &items(), "pw");
        assert!(!response.stdout.contains("s3cr3t-value-long"), "leaked: {}", response.stdout);
        assert!(response.stdout.contains("«redacted»"), "{}", response.stdout);
    }

    #[test]
    fn a_value_passed_as_environment_never_appears_in_the_argv() {
        let mut env = BTreeMap::new();
        env.insert("SECRET".to_string(), "{{token}}".to_string());
        let request = AgentRequest {
            argv: vec!["sh".into(), "-c".into(), "test -n \"$SECRET\" && echo present".into()],
            env,
            cwd: None, run_prepared: None, request_password: false,
        };
        let response = handle(&request, &items(), "pw");
        assert_eq!(response.exit_code, 0);
        assert!(response.stdout.contains("present"), "{}", response.stdout);
        // The command itself carries no trace of the value.
        assert!(!request.argv.iter().any(|a| a.contains("tok-abcdefghij")));
    }

    #[test]
    fn a_failing_command_returns_its_exit_code() {
        let request = AgentRequest {
            argv: vec!["sh".into(), "-c".into(), "exit 7".into()],
            env: BTreeMap::new(),
            cwd: None, run_prepared: None, request_password: false,
        };
        assert_eq!(handle(&request, &items(), "pw").exit_code, 7);
    }

    #[test]
    fn a_missing_binary_is_reported_rather_than_looking_like_success() {
        let request = AgentRequest {
            argv: vec!["definitely-not-a-real-binary-xyz".into()],
            env: BTreeMap::new(),
            cwd: None, run_prepared: None, request_password: false,
        };
        let response = handle(&request, &items(), "pw");
        assert_ne!(response.exit_code, 0);
        assert!(response.error.is_some());
    }

    /// The property the prepared tier exists for: there is no command anyone can compose that
    /// reaches the value, because it is not in the map placeholders resolve against.
    #[test]
    fn a_prepared_item_cannot_be_substituted_into_a_composed_command() {
        let response = handle(
            &AgentRequest {
                argv: vec!["echo".into(), "{{registry_token}}".into()],
                env: BTreeMap::new(), cwd: None, run_prepared: None, request_password: false,
            },
            &restricted(), "pw",
        );
        let error = response.error.expect("a restricted item must not substitute");
        assert!(error.contains("restricted"), "{error}");
        // It should say how to reach it properly rather than merely refusing.
        assert!(error.contains("--run"), "{error}");
        assert!(error.contains("show-length"), "{error}");

        // The same via the environment, which is the other injection path.
        let mut env = BTreeMap::new();
        env.insert("T".to_string(), "{{registry_token}}".to_string());
        let response = handle(
            &AgentRequest { argv: vec!["true".into()], env, cwd: None, run_prepared: None, request_password: false },
            &restricted(), "pw",
        );
        assert!(response.error.is_some(), "env injection must be refused too");
    }

    #[test]
    fn a_prepared_command_can_use_the_value_it_guards() {
        let response = handle(
            &AgentRequest {
                argv: vec![], env: BTreeMap::new(), cwd: None, request_password: false,
                run_prepared: Some(RunPrepared {
                    item: "registry_token".into(),
                    command: "show-length".into(),
                    params: BTreeMap::new(),
                }),
            },
            &restricted(), "pw",
        );
        assert_eq!(response.exit_code, 0, "{:?}", response.error);
        // wc -c over the secret: it reached the child, and only its length came back.
        assert_eq!(response.stdout.trim(), "22");
        assert!(!response.stdout.contains("hunter2"), "leaked: {}", response.stdout);
    }

    #[test]
    fn an_undeclared_parameter_is_refused() {
        let mut params = BTreeMap::new();
        params.insert("sneaky".to_string(), "value".to_string());
        let response = handle(
            &AgentRequest {
                argv: vec![], env: BTreeMap::new(), cwd: None, request_password: false,
                run_prepared: Some(RunPrepared {
                    item: "registry_token".into(),
                    command: "show-length".into(),
                    params,
                }),
            },
            &restricted(), "pw",
        );
        let error = response.error.expect("undeclared parameters must be refused");
        assert!(error.contains("sneaky"), "{error}");
    }

    /// A parameter is data. Substitution happens once and the result is never rescanned, so a
    /// parameter containing a placeholder cannot reach another secret — the injection this design
    /// borrows from prepared statements specifically to prevent.
    #[test]
    fn a_parameter_cannot_smuggle_in_another_placeholder() {
        let mut m = restricted();
        m.insert(
            "echoer".to_string(),
            UnlockedItem {
                value: "not-used".into(),
                restriction: Restriction::Prepared,
                prepared: vec![PreparedCommand {
                    name: "say".into(),
                    description: None,
                    argv: vec!["echo".into(), "{{param:text}}".into()],
                    stdin: None,
                    env: BTreeMap::new(),
                    params: vec!["text".into()],
                    returns_output: true,
                }],
            },
        );
        let mut params = BTreeMap::new();
        params.insert("text".to_string(), "{{db_password}} {{self}}".to_string());
        let response = handle(
            &AgentRequest {
                argv: vec![], env: BTreeMap::new(), cwd: None, request_password: false,
                run_prepared: Some(RunPrepared {
                    item: "echoer".into(), command: "say".into(), params,
                }),
            },
            &m, "pw",
        );
        assert_eq!(response.exit_code, 0, "{:?}", response.error);
        assert!(!response.stdout.contains("s3cr3t-value-long"), "reached another secret: {}", response.stdout);
        assert!(!response.stdout.contains("not-used"), "reached its own secret: {}", response.stdout);
        assert!(response.stdout.contains("{{db_password}}"), "should stay literal: {}", response.stdout);
    }

    #[test]
    fn an_unknown_prepared_command_lists_what_exists() {
        let response = handle(
            &AgentRequest {
                argv: vec![], env: BTreeMap::new(), cwd: None, request_password: false,
                run_prepared: Some(RunPrepared {
                    item: "registry_token".into(), command: "nope".into(), params: BTreeMap::new(),
                }),
            },
            &restricted(), "pw",
        );
        let error = response.error.unwrap();
        assert!(error.contains("show-length"), "{error}");
    }

    /// The one place the agent hands back a secret on purpose: bigbang resolving its own vault:
    /// references, which would otherwise prompt for every recipe run.
    #[test]
    fn the_agent_returns_the_vault_password_only_when_asked_for_it() {
        let asked = handle(
            &AgentRequest {
                argv: vec![], env: BTreeMap::new(), cwd: None,
                run_prepared: None, request_password: true,
            },
            &items(), "the-vault-password",
        );
        assert_eq!(asked.password.as_deref(), Some("the-vault-password"));
        assert_eq!(asked.exit_code, 0);

        // Every other request must leave it absent, so it cannot arrive by accident.
        let ordinary = handle(
            &AgentRequest {
                argv: vec!["true".into()], env: BTreeMap::new(), cwd: None,
                run_prepared: None, request_password: false,
            },
            &items(), "the-vault-password",
        );
        assert!(ordinary.password.is_none(), "a password came back unasked");
    }

    #[test]
    fn a_request_round_trips_over_the_socket() {
        let dir = std::env::temp_dir().join(format!("bb-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sock");

        let serve_path = path.clone();
        let handle_thread = std::thread::spawn(move || {
            let _ = serve(&serve_path, items(), "pw".into(), None, Duration::from_secs(20), None);
        });
        // Wait for the socket rather than sleeping a guessed interval.
        for _ in 0..100 {
            if is_running(&path) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(is_running(&path), "agent did not come up");

        let response = send(
            &path,
            &AgentRequest {
                argv: vec!["sh".into(), "-c".into(), "echo {{token}}".into()],
                env: BTreeMap::new(),
                cwd: None, run_prepared: None, request_password: false,
            },
        )
        .unwrap();
        assert_eq!(response.exit_code, 0);
        assert!(!response.stdout.contains("tok-abcdefghij"), "leaked over the socket");

        let _ = std::fs::remove_file(&path);
        let _ = handle_thread.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_socket_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bb-agent-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.sock");

        let serve_path = path.clone();
        std::thread::spawn(move || {
            let _ = serve(&serve_path, BTreeMap::new(), "pw".into(), None, Duration::from_secs(10), None);
        });
        for _ in 0..100 {
            if is_running(&path) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "an unlocked vault's socket must not be readable by others");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
