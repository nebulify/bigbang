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

/// Which definitions declare something this executor cannot do.
///
/// A shrink-only list. Every entry is a task that runs green today while doing less than it says —
/// `uploadTemplate` declared and never uploading, `vaultAddItem` declared and never writing. The
/// executor now refuses them outright, so this list records what is owed rather than what is
/// broken silently. Nothing may be added to it; entries leave as the features land.
const DECLARES_UNIMPLEMENTED: &[&str] = &[
    "fetch-kubeconfig.json",
    "setup-nginx-upstream-metallb.json",
    "update-nginx-clicky-proxy.json",
];

#[test]
fn only_the_known_definitions_declare_unimplemented_features() {
    let dir = tasks_dir();
    if !dir.exists() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }

    let mut offenders: Vec<(String, Vec<String>)> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("reading the tasks directory") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(def) = TaskDefinition::load_file(&path) else { continue };
        let unhonoured = bigbang::task::unhonoured_fields(&def);
        if !unhonoured.is_empty() {
            offenders.push((
                path.file_name().unwrap().to_string_lossy().to_string(),
                unhonoured,
            ));
        }
    }

    let names: Vec<&str> = offenders.iter().map(|(n, _)| n.as_str()).collect();
    for (name, fields) in &offenders {
        assert!(
            DECLARES_UNIMPLEMENTED.contains(&name.as_str()),
            "{name} declares something the executor cannot honour, and is not on the known list — \
             implement it or remove it, do not extend the list:\n  {}",
            fields.join("\n  ")
        );
    }
    // Shrink-only: an entry that no longer offends must come off the list.
    for known in DECLARES_UNIMPLEMENTED {
        assert!(
            names.contains(known),
            "{known} no longer declares anything unimplemented — remove it from DECLARES_UNIMPLEMENTED"
        );
    }
    eprintln!("{} definition(s) still declare unimplemented features", offenders.len());
    for (name, fields) in &offenders {
        eprintln!("  {name}: {}", fields.join(", "));
    }
}

/// The assertions written in the repository must reach the model.
///
/// They were declared for a long time and silently dropped: `DetailedCommand` had no such field,
/// so serde discarded them without complaint and every "output must not contain ERROR" check was
/// inert. A count asserted here means the field cannot quietly disappear again.
#[test]
fn assertions_in_repository_definitions_are_not_dropped() {
    let dir = tasks_dir();
    if !dir.exists() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }

    let mut total = 0usize;
    let mut files_with = Vec::new();

    for entry in std::fs::read_dir(&dir).expect("reading the tasks directory") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        // Only count what the raw file actually declares, so this compares model against file.
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        if !raw.contains("\"assertions\"") {
            continue;
        }
        let def = TaskDefinition::load_file(&path).expect("a file with assertions must parse");
        let parsed: usize = def
            .tasks
            .iter()
            .flat_map(|t| t.commands.iter())
            .map(|c| c.detail().assertions.len())
            .sum();
        assert!(
            parsed > 0,
            "{} declares assertions but the model parsed none",
            path.display()
        );
        // Every one must be a type the executor understands, or it is a check that cannot pass.
        for task in &def.tasks {
            for command in &task.commands {
                for assertion in &command.detail().assertions {
                    let err = assertion.evaluate("").err().unwrap_or_default();
                    assert!(
                        !err.contains("unknown assertion type"),
                        "{}: {}",
                        path.display(), err
                    );
                }
            }
        }
        total += parsed;
        files_with.push(path.file_name().unwrap().to_string_lossy().to_string());
    }

    assert!(total > 0, "expected the repository's declared assertions to parse, found none");
    eprintln!("parsed {total} assertion(s) across {}", files_with.join(", "));
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
