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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
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

/// Run one request: substitute, exec, redact.
pub fn handle(request: &AgentRequest, items: &BTreeMap<String, String>) -> AgentResponse {
    let mut used: Vec<String> = Vec::new();

    let argv: Result<Vec<String>> = request
        .argv
        .iter()
        .map(|a| substitute(a, items, &mut used))
        .collect();
    let argv = match argv {
        Ok(a) => a,
        Err(err) => {
            return AgentResponse { exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some(format!("{err:#}")) }
        }
    };
    if argv.is_empty() {
        return AgentResponse { exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some("no command given".into()) };
    }

    let mut env = BTreeMap::new();
    for (key, value) in &request.env {
        match substitute(value, items, &mut used) {
            Ok(v) => {
                env.insert(key.clone(), v);
            }
            Err(err) => {
                return AgentResponse { exit_code: 1, stdout: String::new(), stderr: String::new(), error: Some(format!("{err:#}")) }
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
            exit_code: out.status.code().unwrap_or(-1),
            stdout: redact(&String::from_utf8_lossy(&out.stdout), &used),
            stderr: redact(&String::from_utf8_lossy(&out.stderr), &used),
            error: None,
        },
        Err(err) => AgentResponse {
            exit_code: 127,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(format!("running {}: {err}", argv[0])),
        },
    }
}

/// Listen until the deadline passes or the socket is removed.
pub fn serve(
    path: &Path,
    items: BTreeMap<String, String>,
    ttl: Duration,
    audit: Option<PathBuf>,
) -> Result<()> {
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
                serve_one(stream, &items, audit.as_deref());
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

fn serve_one(mut stream: UnixStream, items: &BTreeMap<String, String>, audit: Option<&Path>) {
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
            handle(&request, items)
        }
        Err(err) => AgentResponse {
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
    let line = format!(
        "{when} argv={:?} env_keys={:?}\n",
        request.argv,
        request.env.keys().collect::<Vec<_>>()
    );
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

    fn items() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("db_password".to_string(), "s3cr3t-value-long".to_string());
        m.insert("token".to_string(), "tok-abcdefghij".to_string());
        m
    }

    #[test]
    fn placeholders_are_replaced_and_recorded() {
        let mut used = Vec::new();
        let out = substitute("psql://{{db_password}}@host", &items(), &mut used).unwrap();
        assert_eq!(out, "psql://s3cr3t-value-long@host");
        assert_eq!(used, vec!["s3cr3t-value-long".to_string()]);
    }

    /// Leaving it as written would send the literal text onward as if it were the credential.
    #[test]
    fn an_unknown_placeholder_is_an_error_not_a_passthrough() {
        let mut used = Vec::new();
        let err = substitute("{{nope}}", &items(), &mut used).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("not unlocked"), "{text}");
        assert!(text.contains("db_password"), "it should say what is available: {text}");
    }

    #[test]
    fn shell_metacharacters_in_a_value_stay_data() {
        // Deliberately under six characters so redaction leaves it visible; the property under
        // test is that no shell parsed it, not that it was hidden.
        let mut m = BTreeMap::new();
        m.insert("v".to_string(), "a;b`c".to_string());

        // Arrives whole: a shell would have split on ';' and run `c` as a command substitution.
        let response = handle(
            &AgentRequest { argv: vec!["echo".into(), "{{v}}".into()], env: BTreeMap::new(), cwd: None },
            &m,
        );
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.stdout.trim_end(), "a;b`c", "value did not survive intact");

        // And it is exactly one argument.
        let counted = handle(
            &AgentRequest {
                argv: vec!["sh".into(), "-c".into(), "echo $#".into(), "_".into(), "{{v}}".into()],
                env: BTreeMap::new(),
                cwd: None,
            },
            &m,
        );
        assert_eq!(counted.stdout.trim_end(), "1", "the value should be a single argument");
    }

    /// The counterpart: a value long enough to be worth hiding is hidden, even here.
    #[test]
    fn a_long_value_is_redacted_even_when_it_contains_metacharacters() {
        let mut m = BTreeMap::new();
        m.insert("v".to_string(), "a; rm -rf / --long-enough".to_string());
        let response = handle(
            &AgentRequest { argv: vec!["echo".into(), "{{v}}".into()], env: BTreeMap::new(), cwd: None },
            &m,
        );
        assert!(!response.stdout.contains("rm -rf"), "leaked: {}", response.stdout);
        assert!(response.stdout.contains("«redacted»"), "{}", response.stdout);
    }

    #[test]
    fn injected_values_are_redacted_from_output() {
        let request = AgentRequest {
            argv: vec!["sh".into(), "-c".into(), "echo {{db_password}}".into()],
            env: BTreeMap::new(),
            cwd: None,
        };
        let response = handle(&request, &items());
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
            cwd: None,
        };
        let response = handle(&request, &items());
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
            cwd: None,
        };
        assert_eq!(handle(&request, &items()).exit_code, 7);
    }

    #[test]
    fn a_missing_binary_is_reported_rather_than_looking_like_success() {
        let request = AgentRequest {
            argv: vec!["definitely-not-a-real-binary-xyz".into()],
            env: BTreeMap::new(),
            cwd: None,
        };
        let response = handle(&request, &items());
        assert_ne!(response.exit_code, 0);
        assert!(response.error.is_some());
    }

    #[test]
    fn a_request_round_trips_over_the_socket() {
        let dir = std::env::temp_dir().join(format!("bb-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sock");

        let serve_path = path.clone();
        let handle_thread = std::thread::spawn(move || {
            let _ = serve(&serve_path, items(), Duration::from_secs(20), None);
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
                cwd: None,
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
            let _ = serve(&serve_path, BTreeMap::new(), Duration::from_secs(10), None);
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
