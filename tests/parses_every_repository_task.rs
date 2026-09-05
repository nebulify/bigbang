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
