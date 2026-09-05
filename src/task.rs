//! Task definitions, and the variable substitution they run through.
//!
//! The shape is taken from the 35 task files in this repository rather than from the Kotlin
//! classes, because the files are what has to parse. Across them, 675 commands are written as bare
//! strings and 235 as objects:
//!
//! ```json
//! "commands": [
//!   "apt-get update",
//!   { "cmd": "apt-get install -y postgresql", "timeout": 300, "retries": 2 }
//! ]
//! ```
//!
//! Jackson needs a hand-written `JsonDeserializer` for that; here it is `#[serde(untagged)]`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDefinition {
    #[serde(default)]
    pub group: Option<String>,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub selectors: Vec<String>,
    #[serde(default)]
    pub tasks: Vec<Task>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "runAs", default)]
    pub run_as: Option<String>,
    #[serde(default)]
    pub commands: Vec<TaskCommand>,
    #[serde(rename = "continueOnError", default)]
    pub continue_on_error: bool,
    /// Commands that must all succeed after the task's own commands have run.
    #[serde(default)]
    pub verification: Vec<String>,
    /// Skip the whole task unless this command succeeds.
    #[serde(default)]
    pub condition: Option<String>,
}

/// A command is either a bare string or an object. Both forms normalise to the same thing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TaskCommand {
    Simple(String),
    Detailed(DetailedCommand),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetailedCommand {
    pub cmd: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Seconds. The Kotlin default is 30.
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub retries: Option<u32>,
    #[serde(rename = "retryDelay", default)]
    pub retry_delay: Option<u64>,
    #[serde(rename = "continueOnError", default)]
    pub continue_on_error: Option<bool>,
    /// If this command succeeds, the main command is skipped — an idempotency guard.
    #[serde(rename = "skipIf", default)]
    pub skip_if: Option<String>,
    /// If present, the main command runs only when this succeeds.
    #[serde(rename = "runIf", default)]
    pub run_if: Option<String>,
    #[serde(rename = "expectExitCode", default)]
    pub expect_exit_code: Option<i32>,
}

impl TaskCommand {
    pub fn detail(&self) -> DetailedCommand {
        match self {
            TaskCommand::Simple(cmd) => DetailedCommand { cmd: cmd.clone(), ..Default::default() },
            TaskCommand::Detailed(d) => d.clone(),
        }
    }
}

impl TaskDefinition {
    /// `libraryRoot/group/name/version/task.json`
    pub fn load_from_library(library_root: &Path, coordinate: &str) -> Result<Self> {
        let parts: Vec<&str> = coordinate.split('/').collect();
        if parts.len() != 3 {
            anyhow::bail!("package coordinate must be group/name/version, got '{coordinate}'");
        }
        let dir = library_root.join(parts[0]).join(parts[1]).join(parts[2]);
        // The file is named after its type; task is the only one execution loads.
        for candidate in ["task.json", "package.json"] {
            let path = dir.join(candidate);
            if path.exists() {
                return Self::load_file(&path);
            }
        }
        anyhow::bail!("no task.json or package.json under {}", dir.display())
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn library_dir(library_root: &Path, coordinate: &str) -> PathBuf {
        let parts: Vec<&str> = coordinate.split('/').collect();
        parts.iter().fold(library_root.to_path_buf(), |acc, p| acc.join(p))
    }
}

/// Replaces `${name}` from the merged variable map.
///
/// Unknown placeholders are left as written rather than blanked. A command that still contains
/// `${db_name}` fails loudly and legibly on the remote host; one silently rewritten to
/// `psql -d ''` does something else entirely, and looks like it worked.
pub fn substitute(input: &str, variables: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = input[i + 2..].find('}') {
                let key = &input[i + 2..i + 2 + end];
                match variables.get(key) {
                    Some(value) => out.push_str(value),
                    None => out.push_str(&input[i..i + 2 + end + 1]),
                }
                i = i + 2 + end + 1;
                continue;
            }
        }
        out.push(input[i..].chars().next().unwrap());
        i += input[i..].chars().next().unwrap().len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> BTreeMap<String, String> {
        let mut v = BTreeMap::new();
        v.insert("db_name".into(), "appdb".into());
        v.insert("schema_name".into(), "app".into());
        v
    }

    #[test]
    fn both_command_forms_parse() {
        let json = r#"["apt-get update", {"cmd": "install", "timeout": 300, "retries": 2}]"#;
        let cmds: Vec<TaskCommand> = serde_json::from_str(json).unwrap();
        assert_eq!(cmds[0].detail().cmd, "apt-get update");
        assert_eq!(cmds[0].detail().timeout, None);
        assert_eq!(cmds[1].detail().cmd, "install");
        assert_eq!(cmds[1].detail().timeout, Some(300));
        assert_eq!(cmds[1].detail().retries, Some(2));
    }

    #[test]
    fn substitution_replaces_known_names() {
        assert_eq!(substitute("psql -d ${db_name}", &vars()), "psql -d appdb");
        assert_eq!(substitute("${db_name}/${schema_name}", &vars()), "appdb/app");
    }

    #[test]
    fn an_unknown_placeholder_is_left_alone_not_blanked() {
        // Blanking would turn `psql -d ${missing}` into `psql -d `, which runs and does the wrong
        // thing. Leaving it fails loudly on the host instead.
        assert_eq!(substitute("psql -d ${missing}", &vars()), "psql -d ${missing}");
    }

    #[test]
    fn a_lone_dollar_or_unclosed_brace_is_untouched() {
        assert_eq!(substitute("echo $HOME", &vars()), "echo $HOME");
        assert_eq!(substitute("echo ${unclosed", &vars()), "echo ${unclosed");
        assert_eq!(substitute("cost: 5$", &vars()), "cost: 5$");
    }
}
