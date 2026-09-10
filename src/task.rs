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
    /// The `blaster:task` discriminator. Carried so it does not land in `extra` and read as an
    /// unhonoured declaration; the library installer is what actually acts on it.
    #[serde(rename = "type", default)]
    pub type_: Option<String>,
    #[serde(rename = "singleSession", default)]
    pub single_session: Option<bool>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
    /// Work that is not a shell command: putting a file on the host, writing to the vault.
    ///
    /// These run **before** the task's commands, which is what the definitions assume — the Clicky
    /// task's single command is `test -f <path>`, checking that the upload its function performs
    /// actually landed.
    #[serde(default)]
    pub functions: Vec<Function>,
    /// Anything the model does not implement.
    ///
    /// Kept rather than discarded so it can be refused. Silently dropping these is how
    /// `uploadTemplate` came to be declared by two production nginx tasks that then ran green
    /// without uploading anything.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
    /// Checks against the command's combined output, applied when the command is otherwise
    /// considered to have succeeded.
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    /// Keep this command's output in a variable for later commands and functions to use.
    #[serde(rename = "captureOutput", default)]
    pub capture_output: Option<bool>,
    #[serde(rename = "outputVariable", default)]
    pub output_variable: Option<String>,
    /// Anything the model does not implement — see `Task::extra`.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A unit of work the shell cannot express.
///
/// `uploadTemplate` puts a file on the host; `vaultAddItem` writes a secret. Both were declared in
/// the definitions and silently discarded, so two nginx tasks deployed configuration by not
/// deploying it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    /// Which function to run: `uploadTemplate`, `vaultAddItem`.
    pub function: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    /// Where to put whatever the function produces.
    #[serde(rename = "outputVariable", default)]
    pub output_variable: Option<String>,
}

impl Function {
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.function.clone())
    }
    /// A parameter with variables already substituted.
    pub fn param(&self, key: &str, variables: &BTreeMap<String, String>) -> Option<String> {
        self.params.get(key).map(|v| substitute(v, variables))
    }
}

/// A field is only a demand if it asks for something.
///
/// `"functions": []` declares no function, and several definitions carry empty placeholders left
/// by whatever generated them. Refusing those would be noise; refusing a populated one is the
/// point.
pub fn declares_nothing(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(b) => !b,
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
        serde_json::Value::String(s) => s.trim().is_empty(),
        _ => false,
    }
}

/// Field names that are declared, populated, and that this executor cannot honour.
///
/// The whole class of fault this addresses: serde discards what the model does not declare, so an
/// unimplemented feature is indistinguishable from a working one at the console. `runAs`,
/// packages, nested variables and assertions each shipped that way. Whatever is left over is now
/// surfaced instead of dropped, so the next one fails loudly the first time it is run.
pub fn unhonoured_fields(definition: &TaskDefinition) -> Vec<String> {
    let mut out = Vec::new();
    let mut note = |where_: &str, key: &str| out.push(format!("{where_}: '{key}'"));

    for (k, v) in &definition.extra {
        if !declares_nothing(v) {
            note("definition", k);
        }
    }
    for task in &definition.tasks {
        for (k, v) in &task.extra {
            if !declares_nothing(v) {
                note(&format!("task '{}'", task.name), k);
            }
        }
        for command in &task.commands {
            for (k, v) in &command.detail().extra {
                if !declares_nothing(v) {
                    note(&format!("task '{}' command", task.name), k);
                }
            }
        }
    }
    out
}

/// A check on what a command printed, not on what it returned.
///
/// This exists because an exit code is often not the truth: `psql` will exit 0 having printed
/// `ERROR: relation already exists`, and `kubectl` will exit 0 on `NotFound` in several paths. The
/// definitions in this repository have declared assertions for a long time; the model simply had no
/// field for them, so serde dropped them silently and every one of these checks was inert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    #[serde(rename = "type")]
    pub type_: String,
    pub pattern: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(rename = "caseSensitive", default = "default_case_sensitive")]
    pub case_sensitive: bool,
}

fn default_case_sensitive() -> bool {
    true
}

impl Assertion {
    /// `Ok(())` when the assertion holds; `Err(reason)` when it does not.
    ///
    /// An unrecognised type is a failure rather than a pass. Treating it as satisfied would
    /// reintroduce exactly the fault this feature had — a check that is written down, looks
    /// enforced, and silently is not.
    pub fn evaluate(&self, output: &str) -> Result<(), String> {
        let describe = |verdict: &str| {
            let msg = self.message.as_deref().unwrap_or("assertion failed");
            format!("{msg} ({verdict}: {} {:?})", self.type_, self.pattern)
        };

        match self.type_.to_ascii_uppercase().as_str() {
            "CONTAINS" | "NOT_CONTAINS" => {
                let found = if self.case_sensitive {
                    output.contains(&self.pattern)
                } else {
                    output.to_lowercase().contains(&self.pattern.to_lowercase())
                };
                let want = self.type_.to_ascii_uppercase() == "CONTAINS";
                if found == want {
                    Ok(())
                } else if want {
                    Err(describe("output does not contain"))
                } else {
                    Err(describe("output contains"))
                }
            }
            "MATCHES" | "NOT_MATCHES" => {
                let pattern = if self.case_sensitive {
                    self.pattern.clone()
                } else {
                    format!("(?i){}", self.pattern)
                };
                let re = regex::Regex::new(&pattern)
                    .map_err(|e| format!("assertion pattern is not a valid regex: {e}"))?;
                let found = re.is_match(output);
                let want = self.type_.to_ascii_uppercase() == "MATCHES";
                if found == want {
                    Ok(())
                } else if want {
                    Err(describe("output does not match"))
                } else {
                    Err(describe("output matches"))
                }
            }
            other => Err(format!(
                "unknown assertion type '{other}' — refusing to treat an unrecognised check as passed"
            )),
        }
    }
}

impl TaskCommand {
    pub fn detail(&self) -> DetailedCommand {
        match self {
            TaskCommand::Simple(cmd) => DetailedCommand { cmd: cmd.clone(), ..Default::default() },
            TaskCommand::Detailed(d) => d.clone(),
        }
    }
}

/// A package: metadata plus an ordered list of task references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDefinition {
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
    pub tasks: Vec<PackageRef>,
    /// What a host must have for this package to work.
    ///
    /// Declared in every package in this repository since they were written, and read by
    /// nothing until now: `postgres-vps-setup` asks for 2048 MB and 20 GB on Debian or
    /// Ubuntu, and the deployment would proceed on a 512 MB Alpine box and fail somewhere
    /// inside apt. A requirement nobody checks reads as a guarantee.
    #[serde(rename = "minRequirements", default)]
    pub min_requirements: Option<MinRequirements>,
}

/// A package's host requirements, turned into prerequisites at run time.
///
/// The point of keeping them here rather than repeating them in every recipe: the
/// component that needs the memory is the component that should say so, and a recipe
/// composed of three packages then inherits all three sets without copying anything.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinRequirements {
    #[serde(rename = "minMemoryMb", default)]
    pub min_memory_mb: Option<u64>,
    #[serde(rename = "minDiskGb", default)]
    pub min_disk_gb: Option<u64>,
    #[serde(rename = "supportedOsSystems", default)]
    pub supported_os: Vec<String>,
}

impl MinRequirements {
    /// The shell checks these requirements amount to, as `(what, command, why)`.
    ///
    /// Debian-family commands, because that is what `supportedOsSystems` admits and what
    /// every task in this library installs with. A check that cannot run on the host it is
    /// checking would be worse than none.
    pub fn checks(&self, package: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        if let Some(mb) = self.min_memory_mb {
            out.push((
                format!("{mb} MB of memory, for {package}"),
                format!("[ \"$(free -m | awk '/^Mem:/{{print $2}}')\" -ge {mb} ]"),
                format!("{package} needs at least {mb} MB of memory"),
            ));
        }
        if let Some(gb) = self.min_disk_gb {
            out.push((
                format!("{gb} GB free on /, for {package}"),
                format!(
                    "[ \"$(df -BG --output=avail / | tail -1 | tr -dc '0-9')\" -ge {gb} ]"
                ),
                format!("{package} needs at least {gb} GB free on /"),
            ));
        }
        if !self.supported_os.is_empty() {
            // Matched against ID and ID_LIKE, so Ubuntu satisfies a package that says
            // "debian" — which is what every apt-based task in this library means by it.
            let pattern = self.supported_os.join("|");
            out.push((
                format!("a supported OS ({}), for {package}", self.supported_os.join(", ")),
                format!("grep -qE '^ID(_LIKE)?=.*({pattern})' /etc/os-release"),
                format!(
                    "{package} supports {} and this host is none of them",
                    self.supported_os.join(" or ")
                ),
            ));
        }
        out
    }
}

/// Both forms occur in this repository: some packages list bare coordinate strings, others list
/// objects carrying `path` alongside a name, order and an `optional` flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageRef {
    Simple(String),
    Detailed {
        path: String,
        #[serde(default)]
        order: Option<i64>,
        #[serde(default)]
        optional: Option<bool>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        description: Option<String>,
    },
}

impl PackageRef {
    pub fn path(&self) -> &str {
        match self {
            PackageRef::Simple(p) => p,
            PackageRef::Detailed { path, .. } => path,
        }
    }
    /// Unordered references keep their file order by sorting after everything numbered.
    pub fn order(&self) -> i64 {
        match self {
            PackageRef::Simple(_) => i64::MAX,
            PackageRef::Detailed { order, .. } => order.unwrap_or(i64::MAX),
        }
    }
}

impl PackageDefinition {
    /// The host requirements a coordinate declares, when it is a package.
    ///
    /// `None` for a task: a task is one step and the package it belongs to is where the
    /// shape of the host is declared. Looked up without expanding, so asking what a
    /// deployment needs does not mean loading every command it would run.
    pub fn requirements_of(
        library_root: &Path,
        coordinate: &str,
    ) -> Option<(String, MinRequirements)> {
        let parts: Vec<&str> = coordinate.split('/').collect();
        if parts.len() != 3 {
            return None;
        }
        let dir = library_root.join(parts[0]).join(parts[1]).join(parts[2]);
        let package = PackageDefinition::load_file(&dir.join("package.json")).ok()?;
        package
            .min_requirements
            .map(|req| (package.name.clone(), req))
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }
}

impl TaskDefinition {
    /// `libraryRoot/group/name/version/task.json`
    pub fn load_from_library(library_root: &Path, coordinate: &str) -> Result<Self> {
        let parts: Vec<&str> = coordinate.split('/').collect();
        if parts.len() != 3 {
            anyhow::bail!("package coordinate must be group/name/version, got '{coordinate}'");
        }
        Self::load_from_library_guarded(library_root, coordinate, &mut Vec::new())
    }

    /// A package is a *list of task references*, not a list of commands.
    ///
    /// Loading `package.json` straight into a `TaskDefinition` used to "work": its `tasks` entries
    /// carry `path`/`order`/`optional` and no `commands`, so every one deserialized to an empty
    /// command list and the recipe reported success having run nothing at all. Eight of the
    /// fifteen recipes in this repository reach their work through a package — including the
    /// application deployment, the database provisioning and the load balancer — so the failure
    /// was both silent and total.
    ///
    /// A package is therefore expanded: each referenced coordinate is loaded in `order` and its
    /// tasks are concatenated. Package variables become defaults, overridden by the task's own.
    fn load_from_library_guarded(
        library_root: &Path,
        coordinate: &str,
        seen: &mut Vec<String>,
    ) -> Result<Self> {
        if seen.iter().any(|c| c == coordinate) {
            anyhow::bail!(
                "package cycle: {} -> {coordinate}",
                seen.join(" -> ")
            );
        }
        seen.push(coordinate.to_string());

        let parts: Vec<&str> = coordinate.split('/').collect();
        if parts.len() != 3 {
            anyhow::bail!("package coordinate must be group/name/version, got '{coordinate}'");
        }
        let dir = library_root.join(parts[0]).join(parts[1]).join(parts[2]);

        let task_path = dir.join("task.json");
        if task_path.exists() {
            return Self::load_file(&task_path);
        }

        let package_path = dir.join("package.json");
        if !package_path.exists() {
            anyhow::bail!("no task.json or package.json under {}", dir.display());
        }

        let package = PackageDefinition::load_file(&package_path)?;
        let mut refs: Vec<&PackageRef> = package.tasks.iter().collect();
        refs.sort_by_key(|r| r.order());

        let mut expanded = TaskDefinition {
            group: package.group.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            description: package.description.clone(),
            variables: package.variables.clone(),
            environment: package.environment.clone(),
            selectors: package.selectors.clone(),
            tasks: Vec::new(),
            type_: None,
            single_session: None,
            extra: BTreeMap::new(),
        };
        for reference in refs {
            let child = Self::load_from_library_guarded(library_root, reference.path(), seen)?
                ;
            // The package's own variables are defaults; a referenced task's win where they collide.
            for (k, v) in child.variables {
                expanded.variables.insert(k, v);
            }
            for (k, v) in child.environment {
                expanded.environment.insert(k, v);
            }
            expanded.tasks.extend(child.tasks);
        }

        // A package that expands to nothing is a broken package, not an empty job. Returning it
        // silently is precisely the failure this function exists to end.
        if expanded.tasks.is_empty() {
            anyhow::bail!(
                "package {coordinate} expanded to no tasks — it references {} item(s) that contain none",
                package.tasks.len()
            );
        }
        seen.pop();
        Ok(expanded)
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

/// Substitute variable values into one another until nothing changes.
///
/// A variable's *value* may name another variable: `postgres_config_dir` is
/// `/etc/postgresql/${postgres_major_version}/main`, because the major version is the knob anyone
/// would actually turn. Substituting a command in a single pass expanded the outer name and left
/// the inner one intact, so the shell received the literal `${postgres_major_version}` and `cp`
/// failed on a path that cannot exist.
///
/// Bounded rather than recursive: two variables naming each other would otherwise spin forever. On
/// reaching the bound the values stand as they are, so an unresolved placeholder reaches the host
/// and fails loudly — the right direction, since blanking it would silently aim a command at the
/// wrong path.
pub fn resolve_nested(mut vars: BTreeMap<String, String>) -> BTreeMap<String, String> {
    const MAX_PASSES: usize = 10;
    for _ in 0..MAX_PASSES {
        let mut changed = false;
        let snapshot = vars.clone();
        for (key, value) in vars.iter_mut() {
            if !value.contains("${") {
                continue;
            }
            // A variable must not expand itself; leaving it be keeps the failure legible.
            let mut without_self = snapshot.clone();
            without_self.remove(key);
            let resolved = substitute(value, &without_self);
            if &resolved != value {
                *value = resolved;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    vars
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
                // A shell script may contain a literal `${` — `case "$v" in *'${'*)` is a real
                // pattern people write. Without this check the scan found that `${`, searched on
                // for a closing brace, matched the one belonging to the *next* genuine reference,
                // and swallowed everything between: a guard comparing against ${forbidden_db} was
                // left unsubstituted and silently matched nothing. A variable name is an
                // identifier, so anything else is not a placeholder and the `$` is passed through.
                let is_name = !key.is_empty()
                    && key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
                if !is_name {
                    out.push('$');
                    i += 1;
                    continue;
                }
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

    /// A literal `${` in a shell script used to swallow the next real reference.
    ///
    /// `case "$v" in *'${'*)` is a pattern people write to detect an unsubstituted placeholder.
    /// The scan found that `${`, looked on for a closing brace, matched the one belonging to the
    /// following genuine `${name}`, and consumed everything between — so a guard comparing against
    /// a variable was left as literal text and matched nothing. It reported success while checking
    /// nothing at all.
    #[test]
    fn a_literal_dollar_brace_does_not_swallow_the_next_variable() {
        let mut vars = BTreeMap::new();
        vars.insert("forbidden_db".to_string(), "db_colistor".to_string());

        let input = r#"case "$v" in *'${'*) exit 1;; '${forbidden_db}') exit 1;; esac"#;
        let out = substitute(input, &vars);
        assert!(out.contains("'db_colistor'"), "the real reference must resolve: {out}");
        assert!(out.contains("*'${'*"), "the literal must survive unchanged: {out}");
    }

    #[test]
    fn only_identifiers_are_treated_as_placeholders() {
        let vars = vars();
        // Not names: these must pass through rather than being consumed as a reference.
        assert_eq!(substitute("${ }", &vars), "${ }");
        assert_eq!(substitute("${a b}", &vars), "${a b}");
        assert_eq!(substitute("${}", &vars), "${}");
        // Names, including the dotted form vault items use.
        let mut dotted = BTreeMap::new();
        dotted.insert("ai.encryption.key".to_string(), "x".to_string());
        assert_eq!(substitute("${ai.encryption.key}", &dotted), "x");
    }

    fn write_library(root: &Path, coordinate: &str, file: &str, body: &str) {
        let parts: Vec<&str> = coordinate.split('/').collect();
        let dir = root.join(parts[0]).join(parts[1]).join(parts[2]);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(file), body).unwrap();
    }

    /// The regression that mattered: a package used to load as a `TaskDefinition` whose `tasks`
    /// entries carried `path` and no `commands`, so it ran nothing and reported success.
    #[test]
    fn a_package_expands_into_the_commands_of_the_tasks_it_references() {
        let root = std::env::temp_dir().join(format!("bigbang-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        write_library(
            &root,
            "g/install/1.0",
            "task.json",
            r#"{"name":"install","variables":{"port":"5432"},
                "tasks":[{"name":"Install","runAs":"root","commands":["apt-get install -y postgresql"]}]}"#,
        );
        write_library(
            &root,
            "g/configure/1.0",
            "task.json",
            r#"{"name":"configure",
                "tasks":[{"name":"Configure","runAs":"root","commands":[{"cmd":"systemctl restart postgresql"}]}]}"#,
        );
        // Deliberately out of order in the file, to prove `order` is what decides.
        write_library(
            &root,
            "g/setup/1.0",
            "package.json",
            r#"{"name":"setup","variables":{"port":"1111","extra":"x"},
                "tasks":[{"path":"g/configure/1.0","order":2},{"path":"g/install/1.0","order":1}]}"#,
        );

        let def = TaskDefinition::load_from_library(&root, "g/setup/1.0").unwrap();

        let commands: usize = def.tasks.iter().map(|t| t.commands.len()).sum();
        assert_eq!(def.tasks.len(), 2, "both referenced tasks must appear");
        assert_eq!(commands, 2, "a package must contribute its tasks' commands, not zero");
        assert_eq!(def.tasks[0].name, "Install", "order decides, not file position");
        assert_eq!(def.tasks[1].name, "Configure");
        // runAs has to survive expansion, or every elevated command silently drops to the login user.
        assert_eq!(def.tasks[0].run_as.as_deref(), Some("root"));
        // A referenced task's variables win over the package's defaults.
        assert_eq!(def.variables.get("port").map(String::as_str), Some("5432"));
        assert_eq!(def.variables.get("extra").map(String::as_str), Some("x"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_that_expands_to_nothing_is_an_error_not_an_empty_run() {
        let root = std::env::temp_dir().join(format!("bigbang-pkg-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_library(&root, "g/hollow/1.0", "task.json", r#"{"name":"hollow","tasks":[]}"#);
        write_library(
            &root,
            "g/empty/1.0",
            "package.json",
            r#"{"name":"empty","tasks":[{"path":"g/hollow/1.0","order":1}]}"#,
        );
        let err = TaskDefinition::load_from_library(&root, "g/empty/1.0").unwrap_err();
        assert!(format!("{err:#}").contains("expanded to no tasks"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_cycle_is_refused_rather_than_recursing_forever() {
        // The directory must not contain the word this test asserts on: errors embed the path, so
        // naming the temp dir "…-cycle-…" made this assertion pass against a build with no cycle
        // detection at all. It matched the folder name, not the diagnosis.
        let root = std::env::temp_dir().join(format!("bigbang-pkg-loop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_library(&root, "g/a/1.0", "package.json", r#"{"name":"a","tasks":["g/b/1.0"]}"#);
        write_library(&root, "g/b/1.0", "package.json", r#"{"name":"b","tasks":["g/a/1.0"]}"#);
        let err = format!("{:#}", TaskDefinition::load_from_library(&root, "g/a/1.0").unwrap_err());
        assert!(err.contains("package cycle"), "expected a cycle diagnosis, got: {err}");
        // The chain has to name the path taken, or the message cannot be acted on.
        assert!(err.contains("g/a/1.0") && err.contains("g/b/1.0"), "got: {err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_packages_declared_requirements_become_checks_naming_the_package() {
        // These were declared in every package in this repository and read by nothing.
        // postgres-vps-setup asks for 2048 MB, 20 GB and a Debian-family OS; the
        // deployment would have proceeded on a 512 MB Alpine box and failed inside apt.
        let req = MinRequirements {
            min_memory_mb: Some(2048),
            min_disk_gb: Some(20),
            supported_os: vec!["debian".into(), "ubuntu".into()],
        };
        let checks = req.checks("postgres-vps-setup");
        assert_eq!(checks.len(), 3);
        for (what, command, why) in &checks {
            // The package is named in both, because a recipe composed of three packages
            // must say which one is asking rather than leaving you to guess.
            assert!(what.contains("postgres-vps-setup"), "{what}");
            assert!(why.contains("postgres-vps-setup"), "{why}");
            assert!(!command.is_empty());
        }
        assert!(checks[0].1.contains("free -m"));
        assert!(checks[1].1.contains("df -BG"));
        // ID_LIKE as well as ID, so Ubuntu satisfies a package that says "debian" —
        // which is what every apt-based task in this library means by it.
        assert!(checks[2].1.contains("ID(_LIKE)?"), "{}", checks[2].1);
        assert!(checks[2].1.contains("debian|ubuntu"), "{}", checks[2].1);
    }

    #[test]
    fn a_package_declaring_nothing_adds_no_checks() {
        // Most packages will not declare requirements, and inventing some for them
        // would make every deployment fail on a box that was fine.
        assert!(MinRequirements::default().checks("anything").is_empty());
    }

    #[test]
    fn requirements_are_read_from_a_package_and_not_from_a_task() {
        // A task is one step; the package it belongs to is where the shape of the host
        // is declared. Asking a task would silently find nothing and check nothing.
        let root = std::env::temp_dir().join(format!("bb-req-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let pkg = root.join("infra/db-stack/1.0");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join("package.json"),
            r#"{"type":"blaster:package","group":"infra","name":"db-stack","version":"1.0",
                "minRequirements":{"minMemoryMb":1024,"supportedOsSystems":["debian"]},
                "tasks":[{"path":"infra/install-db/1.0","order":1}]}"#,
        )
        .unwrap();
        let task = root.join("infra/install-db/1.0");
        fs::create_dir_all(&task).unwrap();
        fs::write(
            task.join("task.json"),
            r#"{"type":"blaster:task","group":"infra","name":"install-db","version":"1.0",
                "tasks":[{"name":"x","commands":[{"cmd":"true"}]}]}"#,
        )
        .unwrap();

        let found = PackageDefinition::requirements_of(&root, "infra/db-stack/1.0")
            .expect("a package declaring requirements");
        assert_eq!(found.0, "db-stack");
        assert_eq!(found.1.min_memory_mb, Some(1024));
        assert!(PackageDefinition::requirements_of(&root, "infra/install-db/1.0").is_none());
        let _ = fs::remove_dir_all(&root);
    }
}
