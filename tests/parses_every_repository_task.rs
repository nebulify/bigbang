//! The model has to parse real definitions, not a tidied subset of them.
//!
//! A field this model does not know about is not a theoretical problem — it is a task that
//! silently loses a command, or a run that fails at parse time in front of a half-configured
//! host. Parsing every definition, and asserting the commands survive, is cheap insurance.
//!
//! # Where the definitions come from
//!
//! `tests/corpus/` always, and anything `BIGBANG_TASK_CORPUS` names (colon-separated) as well.
//!
//! This used to be one hardcoded path into the repository that contained this crate, skipped
//! with a printed line when absent. Extracting this crate into its own repository made that
//! path vanish, and all four guards below went on reporting `ok` while reading nothing: 44
//! definitions and 888 commands of coverage, gone silently. A skip is how a structural guard
//! dies, so there is none — an empty corpus fails.

use std::path::PathBuf;

use bigbang::task::TaskDefinition;

/// Every definition the guards should read.
///
/// Panics rather than returning empty. The whole point of these tests is breadth, and breadth
/// that can quietly become zero is not a guard.
fn corpus() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")];
    match std::env::var("BIGBANG_TASK_CORPUS").as_deref() {
        // An explicit opt-out, for somewhere there is genuinely nothing to point at. It still
        // leaves the bundled corpus, so it cannot reduce this to nothing.
        Ok("none") | Err(_) => {}
        Ok(list) => roots.extend(list.split(':').filter(|p| !p.is_empty()).map(PathBuf::from)),
    }
    // Kept so this still sweeps everything when the two repositories sit side by side.
    for sibling in ["../bigbang-library/tasks", "../src/main/resources/deployment/tasks"] {
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(sibling);
        if candidate.is_dir() {
            roots.push(candidate);
        }
    }

    // By file name, later roots winning: a corpus pointed at the library replaces the bundled
    // copy of the same definition rather than being counted beside it.
    let mut by_name: std::collections::BTreeMap<String, PathBuf> = std::collections::BTreeMap::new();
    for root in &roots {
        if !root.is_dir() {
            panic!(
                "BIGBANG_TASK_CORPUS names {}, which is not a directory",
                root.display()
            );
        }
        for entry in std::fs::read_dir(root).expect("reading a corpus directory") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                by_name.insert(name, path);
            }
        }
    }
    let files: Vec<PathBuf> = by_name.into_values().collect();
    assert!(
        !files.is_empty(),
        "no task definitions found in {:?}. tests/corpus/ ships with this repository, so an \
         empty result means it was deleted — these guards measure breadth and cannot pass \
         against nothing.",
        roots
    );
    files
}

#[test]
fn every_task_definition_in_the_repository_parses() {
    let files = corpus();

    let mut parsed = 0usize;
    let mut commands = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for path in &files {
        let path = path.as_path();
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
    assert_eq!(
        parsed, files.len(),
        "every definition in the corpus must parse — {} of {} did",
        parsed, files.len()
    );
    assert!(commands > 0, "a corpus of {} file(s) produced no commands at all", files.len());
    eprintln!("parsed {parsed} task definitions, {commands} commands");
}

/// Which definitions declare something this executor cannot do.
///
/// A shrink-only list. Every entry is a task that runs green today while doing less than it says —
/// `uploadTemplate` declared and never uploading, `vaultAddItem` declared and never writing. The
/// executor now refuses them outright, so this list records what is owed rather than what is
/// broken silently. Nothing may be added to it; entries leave as the features land.
/// Empty, and it should stay that way. uploadTemplate, vaultAddItem, captureOutput and
/// outputVariable were the last three entries; they landed, so they came off.
const DECLARES_UNIMPLEMENTED: &[&str] = &[];

#[test]
fn only_the_known_definitions_declare_unimplemented_features() {
    let files = corpus();

    let mut offenders: Vec<(String, Vec<String>)> = Vec::new();
    for path in &files {
        let path = path.as_path();
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
    let files = corpus();

    let mut total = 0usize;
    let mut files_with = Vec::new();

    for path in &files {
        let path = path.as_path();
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
    let files = corpus();

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

    for path in &files {
        let path = path.as_path();
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
