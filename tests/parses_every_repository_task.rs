//! The model has to parse what is actually in the repository, not a tidied subset of it.
//!
//! These 35 files are the real input to every deployment. A field this model does not know about
//! is not a theoretical problem — it is a task that silently loses a command, or a run that fails
//! at parse time in front of a half-configured host. Parsing all of them, and asserting the
//! commands survive, is cheap insurance that costs one test.

use std::path::PathBuf;

use bigbang::task::TaskDefinition;

fn tasks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../src/main/resources/deployment/tasks")
}

#[test]
fn every_task_definition_in_the_repository_parses() {
    let dir = tasks_dir();
    if !dir.exists() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }

    let mut parsed = 0usize;
    let mut commands = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&dir).expect("reading the tasks directory") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        match TaskDefinition::load_file(&path) {
            Ok(def) => {
                parsed += 1;
                commands += def.tasks.iter().map(|t| t.commands.len()).sum::<usize>();
                for task in &def.tasks {
                    for command in &task.commands {
                        assert!(
                            !command.detail().cmd.trim().is_empty(),
                            "{}: task '{}' has an empty command — a form the model mis-read",
                            path.display(), task.name
                        );
                    }
                }
            }
            Err(err) => failures.push(format!("{}: {err:#}", path.display())),
        }
    }

    assert!(failures.is_empty(), "{} file(s) failed to parse:\n{}", failures.len(), failures.join("\n"));
    assert!(parsed >= 30, "expected the repository's task files, parsed only {parsed}");
    assert!(commands >= 500, "expected several hundred commands, counted {commands}");
    eprintln!("parsed {parsed} task definitions, {commands} commands");
}

/// No task may bring a firewall up without a way back in.
///
/// `setup-postgresql-firewall` enabled UFW as its second step and only then tried to add SSH
/// rules. Both SSH branches were guarded on `jump_host_private_ip`, empty for int, so both skipped
/// and the firewall came up with default deny-incoming and no rules. The host stayed up and
/// answered ICMP; port 22 was simply shut, and nothing could reach it again. Production would have
/// gone the same way.
///
/// The failure has a class, so this asserts across every task rather than the one that bit. A
/// definition that enables a firewall must either add an SSH rule *before* the enable, or guard
/// the enable so it cannot run until one exists.
#[test]
fn no_task_enables_a_firewall_before_allowing_ssh() {
    let dir = tasks_dir();
    if !dir.exists() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }

    fn enables_firewall(cmd: &str) -> bool {
        let c = cmd.to_lowercase();
        c.contains("ufw") && c.contains("enable") && !c.contains("disable")
    }
    // An SSH allow rule: a `ufw allow` naming the ssh port, literally or through a variable.
    fn allows_ssh(cmd: &str) -> bool {
        let c = cmd.to_lowercase();
        c.contains("allow")
            && (c.contains("22") || c.contains("${ssh_port}") || c.contains("ssh"))
    }

    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for entry in std::fs::read_dir(&dir).expect("reading the tasks directory") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(def) = TaskDefinition::load_file(&path) else { continue };

        // Flatten to the order the executor runs them in.
        let ordered: Vec<(String, Option<String>)> = def
            .tasks
            .iter()
            .flat_map(|t| t.commands.iter().map(|c| {
                let d = c.detail();
                (d.cmd.clone(), d.run_if.clone())
            }))
            .collect();

        let mut ssh_allowed_so_far = false;
        for (cmd, run_if) in &ordered {
            if enables_firewall(cmd) {
                checked += 1;
                // An interlock on the enable itself is equally good — better, in fact, since it
                // also covers the case where the earlier allow was skipped at runtime.
                let interlocked = run_if
                    .as_deref()
                    .map(|g| g.contains("show added") || allows_ssh(g))
                    .unwrap_or(false);
                if !ssh_allowed_so_far && !interlocked {
                    offenders.push(format!(
                        "{}: '{}' enables the firewall with no preceding SSH allow rule and no runIf interlock",
                        path.file_name().unwrap().to_string_lossy(),
                        cmd.trim()
                    ));
                }
            }
            if allows_ssh(cmd) {
                ssh_allowed_so_far = true;
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} firewall enable(s) could lock the host out:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
    assert!(checked > 0, "expected to find at least one firewall enable to check");
    eprintln!("checked {checked} firewall enable command(s)");
}
