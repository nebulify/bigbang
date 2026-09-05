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
    fn run(&mut self, command: &str, timeout_secs: u64) -> Result<CommandResult> {
        if self.echo {
            println!("[SSH] -> {}@{}:{}", self.target.user, self.target.host, self.target.port);
            println!("$ {command}");
        }
        // `timeout` wraps ssh rather than being enforced in-process: it kills the whole child,
        // including a remote command still producing output, which a read-side deadline would not.
        let mut cmd = Command::new("timeout");
        cmd.arg(timeout_secs.to_string()).arg("ssh").args(self.argv(command));
        cmd.stdin(Stdio::null());
        let out = cmd.output().context("spawning ssh")?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        if self.echo && !text.is_empty() {
            print!("{text}");
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
    let mut merged = definition.variables.clone();
    for (k, v) in variables {
        merged.insert(k.clone(), v.clone());
    }

    let mut outcomes = Vec::new();
    for task in &definition.tasks {
        let outcome = run_task(task, &merged, executor)?;
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
    let mut outcome = TaskOutcome { task_name: task.name.clone(), ..Default::default() };

    // A task-level condition gates everything below it.
    if let Some(condition) = &task.condition {
        let rendered = substitute(condition, variables);
        if !executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            outcome.skipped.push(format!("task '{}' (condition not met)", task.name));
            return Ok(outcome);
        }
    }

    for command in &task.commands {
        let detail = command.detail();
        let rendered = substitute(&detail.cmd, variables);

        if should_skip(&detail, variables, executor)? {
            outcome.skipped.push(rendered);
            continue;
        }

        let result = run_with_retries(&detail, &rendered, executor)?;
        let expected = detail.expect_exit_code.unwrap_or(0);
        if result.exit_code == expected {
            outcome.ran.push(rendered);
            continue;
        }

        let tolerated = detail.continue_on_error.unwrap_or(task.continue_on_error);
        if tolerated {
            outcome.ran.push(rendered);
            continue;
        }
        outcome.failed = Some(format!("{rendered} (exit {})", result.exit_code));
        return Ok(outcome);
    }

    // Verification runs only once the task's own commands are done, and every one must pass.
    for check in &task.verification {
        let rendered = substitute(check, variables);
        if !executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            outcome.failed = Some(format!("verification failed: {rendered}"));
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

/// `skipIf` succeeding means the work is already done; `runIf` failing means it does not apply.
fn should_skip(
    detail: &DetailedCommand,
    variables: &BTreeMap<String, String>,
    executor: &mut dyn CommandExecutor,
) -> Result<bool> {
    if let Some(skip_if) = &detail.skip_if {
        let rendered = substitute(skip_if, variables);
        if executor.run(&rendered, DEFAULT_TIMEOUT_SECS)?.success() {
            return Ok(true);
        }
    }
    if let Some(run_if) = &detail.run_if {
        let rendered = substitute(run_if, variables);
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
    }

    impl Fake {
        fn new(default_code: i32) -> Self {
            Self { seen: Vec::new(), answers: BTreeMap::new(), default_code }
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
            Ok(CommandResult { exit_code: code, output: String::new() })
        }
    }

    fn task(commands: Vec<TaskCommand>) -> Task {
        Task {
            name: "t".into(), description: None, run_as: None,
            commands, continue_on_error: false, verification: vec![], condition: None,
        }
    }

    #[test]
    fn skip_if_succeeding_means_the_work_is_already_done() {
        let cmd = TaskCommand::Detailed(DetailedCommand {
            cmd: "create schema".into(),
            skip_if: Some("schema exists".into()),
            ..Default::default()
        });
        let mut fake = Fake::new(1).answer("schema exists", 0);
        let outcome = run_task(&task(vec![cmd]), &BTreeMap::new(), &mut fake).unwrap();
        assert_eq!(outcome.ran.len(), 0);
        assert_eq!(outcome.skipped, vec!["create schema".to_string()]);
        assert!(!fake.seen.contains(&"create schema".to_string()), "the guarded command must not run");
    }

    #[test]
    fn a_failure_stops_the_task_unless_tolerated() {
        let boom = TaskCommand::Simple("boom".into());
        let after = TaskCommand::Simple("after".into());
        let mut fake = Fake::new(0).answer("boom", 3);
        let outcome = run_task(&task(vec![boom.clone(), after.clone()]), &BTreeMap::new(), &mut fake).unwrap();
        assert!(outcome.failed.is_some());
        assert!(!fake.seen.contains(&"after".to_string()), "must not continue past a failure");

        let mut tolerant = task(vec![boom, after]);
        tolerant.continue_on_error = true;
        let mut fake2 = Fake::new(0).answer("boom", 3);
        let outcome2 = run_task(&tolerant, &BTreeMap::new(), &mut fake2).unwrap();
        assert!(outcome2.failed.is_none());
        assert!(fake2.seen.contains(&"after".to_string()));
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
        let mut fake = Fake::new(0).answer("check it", 1);
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
    fn ssh_argv_matches_the_kotlin_flags() {
        let ssh = SshExecutor {
            target: SshTarget {
                host: "10.1.1.75".into(), port: 22, user: "debian".into(),
                key_path: "/k/id".into(), jump: Some("debian@57.129.31.14".into()),
            },
            echo: false,
        };
        let argv = ssh.argv("uptime");
        assert_eq!(argv[argv.len() - 2], "debian@10.1.1.75");
        assert_eq!(argv[argv.len() - 1], "uptime");
        assert!(argv.windows(2).any(|w| w[0] == "-J" && w[1] == "debian@57.129.31.14"));
        assert!(argv.windows(2).any(|w| w[0] == "-i" && w[1] == "/k/id"));
        assert!(argv.contains(&"StrictHostKeyChecking=no".to_string()));
    }
}
