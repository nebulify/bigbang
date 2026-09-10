//! Running commands, and the loop that decides which ones run.
//!
//! `CommandExecutor` is a trait for the same reason the Kotlin interface exists: the transport and
//! the decision-making are separate concerns. It also makes the loop testable — `skipIf`, retries,
//! `continueOnError` and verification are decided by this code, and a fake executor exercises all
//! of it deterministically, with no host, no key and no network.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::task::{substitute, DetailedCommand, Task, TaskDefinition};

const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Turn a rendered command into the string actually sent to a shell, honouring `runAs`.
///
/// This was missing, and only a real host revealed it: every task declaring `"runAs": "root"` ran
/// as the login user instead, so `apt-get update` came back with "Could not open lock file …
/// Permission denied". 275 of the repository's task steps declare runAs, so silently ignoring it
/// meant most of them could never have worked.
///
/// Matching the Kotlin executor: wrap in `bash -lc` so a login shell, `~` and PATH behave as a task
/// author expects, then elevate with `sudo -n` — non-interactive, so a host that would prompt for a
/// password fails immediately instead of hanging forever on a prompt nobody can answer.
/// Undo the shell wrapping for display.
///
/// `wrap_command` produces `bash -lc '<payload>'`, possibly behind `sudo -n`, with every
/// single quote in the payload escaped as `'"'"'`. Echoing that is why a well-written task
/// looked like line noise: a one-line guard reading
///
/// ```text
/// case "${stanza}" in ''|*'$'*) echo 'REFUSING: …' >&2; exit 1 ;; esac
/// ```
///
/// was shown as `bash -lc 'case "" in '"'"''"'"'|*'"'"'$'"'"'*) …'`. The wrapper is how
/// bigbang runs a command; it is not what an operator reading the log needs to see.
///
/// Display only — nothing is executed from this, so an imperfect reversal costs legibility
/// and never correctness. A payload this cannot unwrap is shown exactly as it runs.
pub fn unwrap_for_display(wrapped: &str) -> String {
    let (prefix, rest) = match wrapped.strip_prefix("sudo -n ") {
        Some(rest) => ("sudo ", rest),
        None => ("", wrapped),
    };
    let Some(inner) = rest.strip_prefix("bash -lc '").and_then(|r| r.strip_suffix('\'')) else {
        return wrapped.to_string();
    };
    format!("{prefix}{}", inner.replace("'\"'\"'", "'"))
}

pub fn wrap_command(rendered: &str, run_as: Option<&str>, variables: &BTreeMap<String, String>) -> String {
    // Single quotes inside the payload are escaped the shell's own way: close, emit an escaped
    // quote, reopen.
    let payload = rendered.replace('\'', "'\"'\"'");
    let wrapped = format!("bash -lc '{payload}'");

    match run_as {
        None => wrapped,
        Some(user) if user.trim().is_empty() => wrapped,
        Some("root") => format!("sudo -n {wrapped}"),
        // "user" is symbolic: it means whatever the recipe called `user`, and if it named nobody
        // then the command simply runs as the connecting account.
        Some("user") => match variables.get("user").filter(|v| !v.trim().is_empty()) {
            Some(named) => format!("sudo -n -u {named} {wrapped}"),
            None => wrapped,
        },
        Some(other) => format!("sudo -n -u {other} {wrapped}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub exit_code: i32,
    pub output: String,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

pub trait CommandExecutor {
    fn run(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult>;

    /// Run a command whose *text* must never be printed, however this executor is configured.
    ///
    /// An upload carries the whole file, base64-encoded, in its command line, and `mask` cannot
    /// help there: it replaces a secret's literal bytes, and the base64 of a file that contains a
    /// secret does not contain the base64 of the secret — the encoding is not aligned to it. So a
    /// pgbackrest.conf holding `repo1-cipher-pass` would be printed, reversibly, to the console
    /// and into the environment's history.
    ///
    /// The default is `run`, which is right for a recording executor in a test; the two real ones
    /// override it. Output is still shown and still masked: it is the payload that is silenced,
    /// not the result.
    fn run_unechoed(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        self.run(command, timeout_secs)
    }
}

/// Where a command is sent.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: String,
    /// `user@host:port` of a bastion, when the target is only reachable through one.
    pub jump: Option<String>,
}

pub struct SshExecutor {
    pub target: SshTarget,
    pub echo: bool,
    /// A socket for ssh to multiplex over, when the recipe asked for one
    /// session per host.
    ///
    /// `ControlMaster=auto` makes the first command open the connection and
    /// every later one reuse it. Deliberately additive: if the master cannot be
    /// created — an old ssh, a path too long for a unix socket, a filesystem
    /// that will not hold one — ssh falls back to connecting normally, so the
    /// recipe runs either way and only pays for it in time.
    pub control_path: Option<String>,
    /// Values that must never reach a log. Resolved secrets get substituted into commands, so an
    /// echoed command line would otherwise print the database password into CI output — where it
    /// is retained, searchable, and readable by anyone who can see the run.
    pub secrets: Vec<String>,
}

/// Run a child with a deadline, killing it and everything it started if the deadline passes.
///
/// This was `Command::new("timeout")` — GNU coreutils, which is absent on macOS unless
/// somebody installed it as `gtimeout`, and absent on Windows entirely. Shelling out to it
/// meant bigbang itself only ran on Linux, which is a larger limitation than any script's.
///
/// The kill is sent to the process *group*, not just the child. `ssh` without that leaves the
/// remote command running and the connection half-open: killing the local ssh does not tell
/// the far side to stop, but closing the whole group does tear down the pipe that ssh is
/// writing to, which is what makes the remote side notice. A plain `child.kill()` on the
/// immediate process is what a read-side deadline would have done, and the original comment
/// here was right to avoid it.
fn run_with_deadline(mut cmd: Command, timeout_secs: u64) -> Result<std::process::Output> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;

    // Its own process group, so the kill reaches what the child started too.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawning the command")?;

    // The pipes are drained on threads. Reading them in this loop instead would deadlock the
    // moment a command produced more output than a pipe buffer holds, which a deploy that
    // prints progress does immediately.
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
    let status = loop {
        match child.try_wait().context("waiting for the command")? {
            Some(status) => break status,
            None => {
                if std::time::Instant::now() >= deadline {
                    // SIGTERM to the group first, then SIGKILL if it is still there: a
                    // remote shell given the chance to exit cleanly leaves less behind.
                    let pid = child.id() as i32;
                    unsafe { libc::killpg(pid, libc::SIGTERM) };
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    if child.try_wait().ok().flatten().is_none() {
                        unsafe { libc::killpg(pid, libc::SIGKILL) };
                    }
                    break child.wait().context("reaping the command")?;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };

    Ok(std::process::Output {
        status,
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
    })
}

/// Replace every known secret with `***`.
///
/// Values shorter than six characters are left alone: masking those would shred unrelated output
/// for no gain, and a secret that short is not protected by masking anyway.
pub fn mask(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if secret.len() >= 6 {
            out = out.replace(secret.as_str(), "***");
        }
    }
    out
}

impl SshExecutor {
    /// The argv, built separately from running it so it can be asserted in a test.
    ///
    /// Flags match the Kotlin executor exactly. `StrictHostKeyChecking=no` with
    /// `UserKnownHostsFile=/dev/null` is what it already does — worth knowing rather than
    /// discovering: it accepts any host key, so this trusts the network path, and `IdentitiesOnly`
    /// stops a loaded agent quietly supplying a different key than the one named.
    pub fn argv(&self, command: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-o".into(), "StrictHostKeyChecking=no".into(),
            "-o".into(), "UserKnownHostsFile=/dev/null".into(),
            "-o".into(), "IdentitiesOnly=yes".into(),
            "-i".into(), self.target.key_path.clone(),
            "-p".into(), self.target.port.to_string(),
        ];
        if let Some(path) = &self.control_path {
            args.push("-o".into());
            args.push("ControlMaster=auto".into());
            args.push("-o".into());
            args.push(format!("ControlPath={path}"));
            // Long enough to cover the gap between two commands, short enough
            // that an abandoned run does not leave a connection open for hours.
            args.push("-o".into());
            args.push("ControlPersist=30".into());
        }
        if let Some(jump) = &self.target.jump {
            args.push("-J".into());
            args.push(jump.clone());
        }
        args.push(format!("{}@{}", self.target.user, self.target.host));
        args.push(command.to_string());
        args
    }
}

impl CommandExecutor for SshExecutor {
    fn run_unechoed(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        let echo = std::mem::replace(&mut self.echo, false);
        let result = self.run(command, timeout_secs);
        self.echo = echo;
        result
    }

    fn run(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        if self.echo {
            println!("[SSH] -> {}@{}:{}", self.target.user, self.target.host, self.target.port);
            println!("$ {}", mask(&unwrap_for_display(command), &self.secrets));
        }
        let mut cmd = Command::new("ssh");
        cmd.args(self.argv(command));
        cmd.stdin(Stdio::null());
        let out = run_with_deadline(cmd, timeout_secs).context("running ssh")?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        if self.echo && !text.is_empty() {
            // Output is masked too: a command that echoes its own arguments, or an error quoting
            // the failing statement, leaks what the command line alone would not.
            print!("{}", mask(&text, &self.secrets));
        }
        Ok(CommandResult { exit_code: out.status.code().unwrap_or(-1), output: text })
    }
}

/// Runs commands on the machine bigbang itself is running on.
///
/// Provisioning has nowhere to SSH to: the instance being created does not exist yet, and in an
/// empty project there is no host at all. Those commands belong on the operator's machine or the CI
/// runner, which until now this tool could not express — every executor was SSH.
///
/// An inventory entry with `"type": "LOCAL"` selects this. It is deliberately explicit rather than
/// inferred from an address like 127.0.0.1: "run this on my own machine" should be a stated
/// property of a host, not a coincidence of how it was written down.
pub struct LocalExecutor {
    pub echo: bool,
    pub secrets: Vec<String>,
}

impl CommandExecutor for LocalExecutor {
    fn run_unechoed(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        let echo = std::mem::replace(&mut self.echo, false);
        let result = self.run(command, timeout_secs);
        self.echo = echo;
        result
    }

    fn run(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        if self.echo {
            println!("[local]");
            println!("$ {}", mask(&unwrap_for_display(command), &self.secrets));
        }
        // Same shape as the SSH path: the deadline kills the whole process group, so a
        // command that hangs is killed rather than left behind.
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);
        cmd.stdin(Stdio::null());
        let out = run_with_deadline(cmd, timeout_secs).context("running a local command")?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        if self.echo && !text.is_empty() {
            print!("{}", mask(&text, &self.secrets));
        }
        Ok(CommandResult { exit_code: out.status.code().unwrap_or(-1), output: text })
    }
}

#[derive(Debug, Default)]
pub struct TaskOutcome {
    pub task_name: String,
    pub ran: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Option<String>,
}

/// Run one task definition, in order, honouring the guards each command declares.
pub fn run_definition(
    definition: &TaskDefinition,
    variables: &BTreeMap<String, String>,
    executor: &mut dyn CommandExecutor,
) -> Result<Vec<TaskOutcome>> {
    run_definition_with(definition, variables, executor, None)
}

/// As `run_definition`, with the context the non-shell functions need.
///
/// A run with no context can still execute commands; it simply cannot upload a file or write to
/// the vault, and says so rather than skipping quietly.
pub fn run_definition_with(
    definition: &TaskDefinition,
    variables: &BTreeMap<String, String>,
    executor: &mut dyn CommandExecutor,
    ctx: Option<&crate::functions::FunctionContext>,
) -> Result<Vec<TaskOutcome>> {
    // Refuse before anything runs, not after. A definition asking for something this executor
    // cannot do is not a definition that "mostly works": update-nginx-clicky-proxy declares
    // uploadTemplate, and without it the task deploys a config file by not deploying it, then
    // reports success.
    let unhonoured = crate::task::unhonoured_fields(definition);
    if !unhonoured.is_empty() {
        anyhow::bail!(
            "'{}' declares {} thing(s) this executor does not implement, so running it would do \
             less than it says:\n  {}\nImplement them or remove them from the definition — a \
             partial run that reports success is the failure mode this refuses.",
            definition.name,
            unhonoured.len(),
            unhonoured.join("\n  ")
        );
    }

    let mut merged = definition.variables.clone();
    for (k, v) in variables {
        merged.insert(k.clone(), v.clone());
    }
    // Values may name other variables, and this is the map the commands are actually rendered
    // against — resolving only in `merge_variables` left this path one pass short, which is how
    // `${postgres_major_version}` reached the shell verbatim.
    let merged = crate::task::resolve_nested(merged);

    // Variables change during a run now: captureOutput writes one, and a function can produce
    // one. A later task reads what an earlier one captured, which is the whole point of
    // fetch-kubeconfig capturing a file and handing it to the vault.
    let mut merged = merged;
    let mut outcomes = Vec::new();
    for task in &definition.tasks {
        let outcome = run_task_with(task, &mut merged, executor, ctx)?;
        let failed = outcome.failed.is_some();
        outcomes.push(outcome);
        if failed && !task.continue_on_error {
            break;
        }
    }
    Ok(outcomes)
}

fn run_task(
    task: &Task,
    variables: &BTreeMap<String, String>,
    executor: &mut dyn CommandExecutor,
) -> Result<TaskOutcome> {
    let mut owned = variables.clone();
    run_task_with(task, &mut owned, executor, None)
}

fn run_task_with(
    task: &Task,
    variables: &mut BTreeMap<String, String>,
    executor: &mut dyn CommandExecutor,
    ctx: Option<&crate::functions::FunctionContext>,
) -> Result<TaskOutcome> {
    let mut outcome = TaskOutcome { task_name: task.name.clone(), ..Default::default() };

    // A task-level condition gates everything below it.
    if let Some(condition) = &task.condition {
        let rendered = wrap_command(&substitute(condition, variables), task.run_as.as_deref(), variables);
        if !executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            outcome.skipped.push(format!("task '{}' (condition not met)", task.name));
            return Ok(outcome);
        }
    }

    // Before the commands: the definitions assume the file is already there. The Clicky task's
    // only command is `test -f <path>`, which checks that this upload happened.
    for function in &task.functions {
        let Some(ctx) = ctx else {
            outcome.failed = Some(format!(
                "task '{}' declares the function '{}', and this run has no context to perform it",
                task.name, function.label()
            ));
            return Ok(outcome);
        };
        if let Err(err) = crate::functions::run_function(
            function, variables, task.run_as.as_deref(), ctx, executor,
        ) {
            outcome.failed = Some(format!("function '{}': {err:#}", function.label()));
            return Ok(outcome);
        }
        outcome.ran.push(format!("[fn] {}", function.label()));
    }

    for command in &task.commands {
        let detail = command.detail();
        let rendered = wrap_command(&substitute(&detail.cmd, variables), task.run_as.as_deref(), variables);

        if should_skip(&detail, variables, task.run_as.as_deref(), executor)? {
            outcome.skipped.push(unwrap_for_display(&rendered));
            continue;
        }

        let result = run_with_retries(&detail, &rendered, executor)?;
        let expected = detail.expect_exit_code.unwrap_or(0);
        if result.exit_code == expected {
            // The exit code is often not the truth: psql exits 0 having printed
            // "ERROR: ... already exists". Assertions are checked on the success path precisely
            // because that is the case they exist to catch.
            if let Some(name) = detail.output_variable.as_ref().filter(|_| detail.capture_output.unwrap_or(false)) {
                variables.insert(name.clone(), result.output.trim().to_string());
            }
            if let Some(reason) = failed_assertion(&detail, &result.output) {
                let tolerated = detail.continue_on_error.unwrap_or(task.continue_on_error);
                if tolerated {
                    outcome.ran.push(unwrap_for_display(&rendered));
                    continue;
                }
                outcome.failed = Some(format!("{}: {reason}", unwrap_for_display(&rendered)));
                return Ok(outcome);
            }
            outcome.ran.push(unwrap_for_display(&rendered));
            continue;
        }

        let tolerated = detail.continue_on_error.unwrap_or(task.continue_on_error);
        if tolerated {
            outcome.ran.push(unwrap_for_display(&rendered));
            continue;
        }
        outcome.failed = Some(format!("{} (exit {})", unwrap_for_display(&rendered), result.exit_code));
        return Ok(outcome);
    }

    // Verification runs only once the task's own commands are done, and every one must pass.
    for check in &task.verification {
        let rendered = wrap_command(&substitute(check, variables), task.run_as.as_deref(), variables);
        if !executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            outcome.failed = Some(format!("verification failed: {}", unwrap_for_display(&rendered)));
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

/// The first assertion that does not hold, if any.
fn failed_assertion(detail: &DetailedCommand, output: &str) -> Option<String> {
    detail
        .assertions
        .iter()
        .find_map(|a| a.evaluate(output).err())
}

/// `skipIf` succeeding means the work is already done; `runIf` failing means it does not apply.
fn should_skip(
    detail: &DetailedCommand,
    variables: &BTreeMap<String, String>,
    run_as: Option<&str>,
    executor: &mut dyn CommandExecutor,
) -> Result<bool> {
    // The guard runs as the same user as the command it guards: a skipIf that checks a root-only
    // path would otherwise fail for lack of permission and run the work every time.
    if let Some(skip_if) = &detail.skip_if {
        let rendered = wrap_command(&substitute(skip_if, variables), run_as, variables);
        if executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            return Ok(true);
        }
    }
    if let Some(run_if) = &detail.run_if {
        let rendered = wrap_command(&substitute(run_if, variables), run_as, variables);
        if !executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn run_with_retries(
    detail: &DetailedCommand,
    rendered: &str,
    executor: &mut dyn CommandExecutor,
) -> Result<CommandResult> {
    let timeout = detail.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let attempts = detail.retries.unwrap_or(0) + 1;
    let mut last = CommandResult { exit_code: -1, output: String::new() };
    for attempt in 1..=attempts {
        last = executor.run(rendered, timeout)?;
        if last.success() {
            return Ok(last);
        }
        if attempt < attempts {
            if let Some(delay) = detail.retry_delay {
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskCommand;

    /// Records what it was asked to run and answers from a script of exit codes.
    struct Fake {
        seen: Vec<String>,
        answers: BTreeMap<String, i32>,
        default_code: i32,
        /// What the next command prints. Assertions read output, so a fake that always returns
        /// nothing cannot exercise them.
        next_output: Option<String>,
    }

    impl Fake {
        fn new(default_code: i32) -> Self {
            Self { seen: Vec::new(), answers: BTreeMap::new(), default_code, next_output: None }
        }
        fn answer(mut self, command: &str, code: i32) -> Self {
            self.answers.insert(command.to_string(), code);
            self
        }
    }

    impl CommandExecutor for Fake {
        fn run(&mut self, command: &str, _timeout: u64) -> Result<CommandResult> {
            self.seen.push(command.to_string());
            let code = *self.answers.get(command).unwrap_or(&self.default_code);
            let output = self.next_output.clone().unwrap_or_default();
            Ok(CommandResult { exit_code: code, output })
        }
    }

    fn task(commands: Vec<TaskCommand>) -> Task {
        Task {
            name: "t".into(), description: None, run_as: None,
            commands, continue_on_error: false, verification: vec![], condition: None,
            functions: vec![], extra: BTreeMap::new(),
        }
    }

    /// The bug this pins: `run_definition` merged the definition's variables by hand and never
    /// flattened values that name other variables, so a command was rendered with
    /// `${postgres_major_version}` still in it and ran against a path that cannot exist.
    #[test]
    fn a_definition_variable_naming_another_variable_reaches_the_command_resolved() {
        let mut variables = BTreeMap::new();
        variables.insert("postgres_major_version".to_string(), "17".to_string());
        variables.insert(
            "postgres_config_dir".to_string(),
            "/etc/postgresql/${postgres_major_version}/main".to_string(),
        );
        let definition = crate::task::TaskDefinition {
            group: None,
            name: "configure".into(),
            version: None,
            description: None,
            variables,
            environment: BTreeMap::new(),
            selectors: vec![],
            tasks: vec![task(vec![TaskCommand::Simple(
                "cp ${postgres_config_dir}/postgresql.conf /tmp/b".into(),
            )])],
            type_: None, single_session: None, extra: BTreeMap::new(),
        };

        let mut fake = Fake::new(0);
        run_definition(&definition, &BTreeMap::new(), &mut fake).unwrap();
        assert_eq!(fake.seen.len(), 1);
        assert!(
            fake.seen[0].contains("/etc/postgresql/17/main/postgresql.conf"),
            "expected a resolved path, got: {}",
            fake.seen[0]
        );
        assert!(!fake.seen[0].contains("${"), "no placeholder may survive: {}", fake.seen[0]);
    }

    /// The caller's layer must still win, and carry the nested value with it.
    #[test]
    fn a_caller_override_of_the_inner_variable_moves_the_outer_one() {
        let mut variables = BTreeMap::new();
        variables.insert("major".to_string(), "17".to_string());
        variables.insert("dir".to_string(), "/etc/postgresql/${major}/main".to_string());
        let definition = crate::task::TaskDefinition {
            group: None, name: "d".into(), version: None, description: None,
            variables, environment: BTreeMap::new(), selectors: vec![],
            tasks: vec![task(vec![TaskCommand::Simple("ls ${dir}".into())])],
            type_: None, single_session: None, extra: BTreeMap::new(),
        };

        let mut overrides = BTreeMap::new();
        overrides.insert("major".to_string(), "16".to_string());
        let mut fake = Fake::new(0);
        run_definition(&definition, &overrides, &mut fake).unwrap();
        assert!(fake.seen[0].contains("/etc/postgresql/16/main"), "got: {}", fake.seen[0]);
    }

    fn asserting(cmd: &str, assertions: Vec<crate::task::Assertion>) -> TaskCommand {
        TaskCommand::Detailed(DetailedCommand { cmd: cmd.into(), assertions, ..Default::default() })
    }

    fn assertion(type_: &str, pattern: &str, case_sensitive: bool) -> crate::task::Assertion {
        crate::task::Assertion {
            type_: type_.into(),
            pattern: pattern.into(),
            message: Some(format!("{type_} {pattern}")),
            case_sensitive,
        }
    }

    /// The whole point: psql exits 0 having printed an error, so the exit code says success.
    #[test]
    fn an_assertion_fails_a_command_that_exited_zero_with_an_error_in_its_output() {
        let mut fake = Fake::new(0);
        fake.next_output = Some("ERROR:  database \"appdb\" already exists".into());
        let cmd = asserting("createdb appdb", vec![assertion("NOT_CONTAINS", "ERROR", true)]);

        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        let failure = outcome.failed.expect("a zero exit with ERROR in the output must fail");
        assert!(failure.contains("NOT_CONTAINS"), "got: {failure}");
        assert!(outcome.ran.is_empty(), "a failed assertion must not count as a command that ran");
    }

    #[test]
    fn assertions_that_hold_let_the_command_pass() {
        let mut fake = Fake::new(0);
        fake.next_output = Some("secret/regcred created".into());
        let cmd = asserting(
            "kubectl create secret",
            vec![
                assertion("CONTAINS", "created", true),
                assertion("NOT_CONTAINS", "NotFound", true),
                assertion("MATCHES", r"secret/\w+ created", true),
            ],
        );
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_none(), "unexpected failure: {:?}", outcome.failed);
        assert_eq!(outcome.ran.len(), 1);
    }

    #[test]
    fn case_insensitivity_is_honoured_for_both_contains_and_matches() {
        let mut fake = Fake::new(0);
        fake.next_output = Some("Error: something went wrong".into());
        // caseSensitive false must catch "Error" with the pattern "ERROR".
        let cmd = asserting("cmd", vec![assertion("NOT_CONTAINS", "ERROR", false)]);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_some(), "case-insensitive NOT_CONTAINS should have matched");

        // And case-sensitively, it must not.
        let mut fake = Fake::new(0);
        fake.next_output = Some("Error: something went wrong".into());
        let cmd = asserting("cmd", vec![assertion("NOT_CONTAINS", "ERROR", true)]);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_none(), "case-sensitive NOT_CONTAINS should not have matched");

        let mut fake = Fake::new(0);
        fake.next_output = Some("FAILED".into());
        let cmd = asserting("cmd", vec![assertion("NOT_MATCHES", ".*(error|failed).*", false)]);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_some(), "case-insensitive NOT_MATCHES should have matched");
    }

    /// An unrecognised type must not be treated as satisfied — that is the fault this whole
    /// feature had, and re-creating it inside the feature would be worse than not having it.
    #[test]
    fn an_unknown_assertion_type_fails_rather_than_passing_quietly() {
        let mut fake = Fake::new(0);
        fake.next_output = Some("anything".into());
        let cmd = asserting("cmd", vec![assertion("ENDS_WITH", "x", true)]);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        let failure = outcome.failed.expect("an unknown assertion type must fail");
        assert!(failure.contains("unknown assertion type"), "got: {failure}");
    }

    /// The definitions in the repository must actually reach the model now.
    #[test]
    fn assertions_declared_in_a_repository_definition_are_parsed() {
        let json = r#"{
            "name": "d",
            "tasks": [{
              "name": "t",
              "commands": [{
                "cmd": "createdb x",
                "assertions": [
                  {"type": "NOT_CONTAINS", "pattern": "ERROR", "message": "should succeed"},
                  {"type": "CONTAINS", "pattern": "created", "message": "m", "caseSensitive": false}
                ]
              }]
            }]
        }"#;
        let def: crate::task::TaskDefinition = serde_json::from_str(json).unwrap();
        let detail = def.tasks[0].commands[0].detail();
        assert_eq!(detail.assertions.len(), 2, "assertions must survive deserialization");
        assert!(detail.assertions[0].case_sensitive, "caseSensitive defaults to true");
        assert!(!detail.assertions[1].case_sensitive);
    }

    fn definition_with_extra(extra: serde_json::Value) -> crate::task::TaskDefinition {
        let mut json = serde_json::json!({
            "name": "deploy-config",
            "tasks": [{ "name": "Deploy", "commands": ["true"] }]
        });
        // Merge the unknown declaration into the task, as the real definitions carry it.
        let task = &mut json["tasks"][0];
        for (k, v) in extra.as_object().unwrap() {
            task[k] = v.clone();
        }
        serde_json::from_value(json).unwrap()
    }

    /// A definition asking for something this executor cannot do must refuse before running
    /// anything, rather than running the part it understands and reporting success.
    #[test]
    fn a_definition_declaring_an_unimplemented_feature_refuses_to_run() {
        // `onFailure` is still not implemented — `functions` is, so it no longer belongs here.
        let def = definition_with_extra(serde_json::json!({
            "onFailure": [{"do": "something this executor knows nothing about"}]
        }));
        let mut fake = Fake::new(0);
        let err = run_definition(&def, &BTreeMap::new(), &mut fake).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("onFailure"), "the offending field must be named: {text}");
        assert!(text.contains("does not implement"), "got: {text}");
        assert!(fake.seen.is_empty(), "nothing may run before the refusal");
    }

    /// An empty placeholder asks for nothing, and several generated definitions carry them.
    #[test]
    fn empty_placeholder_fields_do_not_block_a_run() {
        let def = definition_with_extra(serde_json::json!({
            "functions": [], "onFailure": [], "selectors": [], "steps": []
        }));
        let mut fake = Fake::new(0);
        let outcomes = run_definition(&def, &BTreeMap::new(), &mut fake)
            .expect("empty declarations must not refuse");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(fake.seen.len(), 1, "the command should still have run");
    }

    #[test]
    fn skip_if_succeeding_means_the_work_is_already_done() {
        let cmd = TaskCommand::Detailed(DetailedCommand {
            cmd: "create schema".into(),
            skip_if: Some("schema exists".into()),
            ..Default::default()
        });
        let mut fake = Fake::new(1).answer("bash -lc 'schema exists'", 0);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert_eq!(outcome.ran.len(), 0);
        assert_eq!(outcome.skipped.len(), 1);
        assert!(!fake.seen.iter().any(|c| c.contains("create schema")), "the guarded command must not run");
    }

    #[test]
    fn a_failure_stops_the_task_unless_tolerated() {
        let boom = TaskCommand::Simple("boom".into());
        let after = TaskCommand::Simple("after".into());
        let mut fake = Fake::new(0).answer("bash -lc 'boom'", 3);
        let outcome = run_task(&task(vec![boom.clone(), after.clone()]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_some());
        assert!(!fake.seen.iter().any(|c| c.contains("after")), "must not continue past a failure");

        let mut tolerant = task(vec![boom, after]);
        tolerant.continue_on_error = true;
        let mut fake2 = Fake::new(0).answer("bash -lc 'boom'", 3);
        let outcome2 = run_task(&tolerant, &BTreeMap::new(), &mut fake2).unwrap();
        assert!(outcome2.failed.is_none());
        assert!(fake2.seen.iter().any(|c| c.contains("after")));
    }

    #[test]
    fn retries_stop_at_the_first_success() {
        let detail = DetailedCommand { cmd: "flaky".into(), retries: Some(3), ..Default::default() };
        let mut fake = Fake::new(0);
        let result = run_with_retries(&detail, "flaky", &mut fake).unwrap();
        assert!(result.success());
        assert_eq!(fake.seen.len(), 1, "a command that succeeds must not be retried");
    }

    #[test]
    fn retries_are_bounded() {
        let detail = DetailedCommand { cmd: "always fails".into(), retries: Some(2), ..Default::default() };
        let mut fake = Fake::new(1);
        let result = run_with_retries(&detail, "always fails", &mut fake).unwrap();
        assert!(!result.success());
        assert_eq!(fake.seen.len(), 3, "1 attempt + 2 retries");
    }

    #[test]
    fn verification_failure_fails_the_task_even_when_commands_passed() {
        let mut t = task(vec![TaskCommand::Simple("do it".into())]);
        t.verification = vec!["check it".into()];
        let mut fake = Fake::new(0).answer("bash -lc 'check it'", 1);
        let outcome = run_task(&t, &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.unwrap().contains("verification failed"));
    }

    #[test]
    fn expect_exit_code_treats_a_non_zero_as_success() {
        let cmd = TaskCommand::Detailed(DetailedCommand {
            cmd: "grep -q missing".into(),
            expect_exit_code: Some(1),
            ..Default::default()
        });
        let mut fake = Fake::new(1);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_none());
    }

    #[test]
    fn run_as_root_elevates_and_run_as_nothing_does_not() {
        let vars = BTreeMap::new();
        assert_eq!(wrap_command("apt-get update", None, &vars), "bash -lc 'apt-get update'");
        assert_eq!(wrap_command("apt-get update", Some("root"), &vars),
                   "sudo -n bash -lc 'apt-get update'");
        assert_eq!(wrap_command("psql", Some("postgres"), &vars),
                   "sudo -n -u postgres bash -lc 'psql'");
    }

    #[test]
    fn a_single_quote_in_a_command_survives_the_wrapping() {
        let vars = BTreeMap::new();
        let wrapped = wrap_command("echo 'not present'", Some("root"), &vars);
        assert_eq!(wrapped, r#"sudo -n bash -lc 'echo '"'"'not present'"'"''"#);
    }

    #[test]
    fn symbolic_user_resolves_through_the_variables() {
        let mut vars = BTreeMap::new();
        // Nobody named: no elevation rather than sudo to a user that does not exist.
        assert_eq!(wrap_command("id", Some("user"), &vars), "bash -lc 'id'");
        vars.insert("user".to_string(), "debian".to_string());
        assert_eq!(wrap_command("id", Some("user"), &vars), "sudo -n -u debian bash -lc 'id'");
    }

    #[test]
    fn secrets_are_masked_in_anything_echoed() {
        let secrets = vec![String::from("s3cret-password"), String::from("ab")];
        let line = String::from("psql -c \"ALTER USER x PASSWORD 's3cret-password'\"");
        let masked = mask(&line, &secrets);
        assert!(!masked.contains("s3cret-password"), "the secret survived: {masked}");
        assert!(masked.contains("***"));
        // Too short to be worth masking, and masking it would shred unrelated output.
        assert_eq!(mask("about", &secrets), "about");
    }

    #[test]
    fn ssh_argv_matches_the_kotlin_flags() {
        let ssh = SshExecutor {
            target: SshTarget {
                host: "10.1.1.75".into(), port: 22, user: "debian".into(),
                key_path: "/k/id".into(), jump: Some("debian@57.129.31.14".into()),
            },
            echo: false,
            secrets: Vec::new(),
            control_path: None,
        };
        let argv = ssh.argv("uptime");
        assert_eq!(argv[argv.len() - 2], "debian@10.1.1.75");
        assert_eq!(argv[argv.len() - 1], "uptime");
        assert!(argv.windows(2).any(|w| w[0] == "-J" && w[1] == "debian@57.129.31.14"));
        assert!(argv.windows(2).any(|w| w[0] == "-i" && w[1] == "/k/id"));
        assert!(argv.contains(&"StrictHostKeyChecking=no".to_string()));
        // Without singleSession there is no multiplexing, and the flags are
        // exactly what they always were.
        assert!(!argv.iter().any(|a| a.starts_with("ControlPath")));
    }

    #[test]
    fn a_single_session_recipe_multiplexes_over_one_connection() {
        // What `singleSession: true` buys: one TCP connection and one key
        // exchange per host instead of one per command. It does not change what
        // runs — each command still gets its own shell — which is why it is
        // safe to switch on for recipes that have been running without it.
        let ssh = SshExecutor {
            target: SshTarget {
                host: "10.1.1.75".into(), port: 22, user: "debian".into(),
                key_path: "/k/id".into(), jump: None,
            },
            echo: false,
            secrets: Vec::new(),
            control_path: Some("/tmp/bb-abc/s".into()),
        };
        let argv = ssh.argv("uptime");
        assert!(argv.windows(2).any(|w| w[0] == "-o" && w[1] == "ControlMaster=auto"));
        assert!(argv.windows(2).any(|w| w[0] == "-o" && w[1] == "ControlPath=/tmp/bb-abc/s"));
        assert!(argv.windows(2).any(|w| w[0] == "-o" && w[1] == "ControlPersist=30"));
        // The command still comes last: multiplexing must not reorder argv.
        assert_eq!(argv[argv.len() - 1], "uptime");
        assert_eq!(argv[argv.len() - 2], "debian@10.1.1.75");
    }

    #[test]
    fn a_command_that_finishes_returns_its_output_and_code() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("printf hello; printf oops >&2; exit 7");
        let out = run_with_deadline(cmd, 10).expect("should run");
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "oops");
    }

    #[test]
    fn a_command_that_hangs_is_killed_at_the_deadline() {
        let started = std::time::Instant::now();
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 30");
        let out = run_with_deadline(cmd, 1).expect("should return");
        let waited = started.elapsed();
        assert!(!out.status.success(), "a killed command must not look successful");
        assert!(waited < std::time::Duration::from_secs(10), "waited {waited:?}");
    }

    #[test]
    fn more_output_than_a_pipe_holds_does_not_deadlock() {
        // Reading the pipes after waiting would hang here: a pipe buffer is 64 KB,
        // and a deploy that prints progress passes that immediately.
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("i=0; while [ $i -lt 20000 ]; do echo 'a line of output'; i=$((i+1)); done");
        let out = run_with_deadline(cmd, 20).expect("should run");
        assert!(out.status.success());
        assert!(out.stdout.len() > 200_000, "got {} bytes", out.stdout.len());
    }

    #[test]
    fn a_child_of_the_killed_command_does_not_survive_it() {
        // The kill goes to the process group. Killing only the immediate child leaves
        // whatever it started running — for ssh that is a remote command and a
        // half-open connection.
        let marker = std::env::temp_dir().join(format!("bb-group-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "sh -c 'sleep 3; touch {}' & wait",
            marker.display()
        );
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&script);
        let _ = run_with_deadline(cmd, 1).expect("should return");
        std::thread::sleep(std::time::Duration::from_secs(4));
        assert!(
            !marker.exists(),
            "a grandchild outlived the deadline and finished its work"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn a_command_is_shown_as_the_task_wrote_it() {
        // What made well-written tasks look like line noise: the log showed the wrapper
        // and the doubled quote escaping instead of the command.
        let guard = "case \"${stanza}\" in ''|*'$'*) echo 'REFUSING: stanza' >&2; exit 1 ;; esac";
        let wrapped = wrap_command(guard, None, &BTreeMap::new());
        assert!(wrapped.contains("'\"'\"'"), "the wrapper should escape quotes: {wrapped}");
        assert_eq!(unwrap_for_display(&wrapped), guard);
    }

    #[test]
    fn running_as_root_is_shown_as_sudo_without_the_flag_noise() {
        let wrapped = wrap_command("systemctl reload nginx", Some("root"), &BTreeMap::new());
        assert_eq!(unwrap_for_display(&wrapped), "sudo systemctl reload nginx");
    }

    #[test]
    fn anything_it_cannot_unwrap_is_shown_exactly_as_it_runs() {
        // Display only: an imperfect reversal must cost legibility, never correctness.
        assert_eq!(unwrap_for_display("echo plain"), "echo plain");
        assert_eq!(unwrap_for_display("bash -lc 'unterminated"), "bash -lc 'unterminated");
    }
}
