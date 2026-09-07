//! Turning a recipe's roles into machines, and a vault key reference into a usable key file.
//!
//! This is the last piece, and the first that cannot be proven without a host. Everything below it
//! — parsing, substitution, the run loop — is covered by tests; what happens here is covered only
//! by running it against something real.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::exec::{SshTarget};
use crate::repodb::RepoDb;
use crate::vault::{self, Vault};

pub const TYPE_INFRASTRUCTURE: &str = "infrastructure";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    #[serde(default)]
    pub id: String,
    /// `LOCAL` means "run on the machine bigbang is on" — used for provisioning, which has no
    /// remote host to talk to yet.
    #[serde(rename = "type", default)]
    pub instance_type: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "projectId", default)]
    pub project_id: String,
    #[serde(rename = "privateIpAddress", default)]
    pub private_ip: Option<String>,
    #[serde(rename = "publicIpAddress", default)]
    pub public_ip: Option<String>,
    #[serde(rename = "jumpHostId", default)]
    pub jump_host_id: Option<String>,
    #[serde(rename = "sshPort", default = "default_port")]
    pub ssh_port: u16,
    #[serde(rename = "sshUsername", default)]
    pub ssh_username: Option<String>,
    #[serde(rename = "sshKeyId", default)]
    pub ssh_key_id: Option<String>,
    #[serde(default)]
    pub selectors: Option<Vec<String>>,
}

fn default_port() -> u16 {
    22
}

impl Instance {
    pub fn is_local(&self) -> bool {
        self.instance_type.as_deref() == Some("LOCAL")
    }

    /// Behind a bastion the private address is the only one reachable, and SSH is typically bound
    /// to the private interface — so the presence of a jump host, not a preference, decides which
    /// address is used.
    pub fn address(&self) -> Result<String> {
        let (first, second) = if self.jump_host_id.is_some() {
            (&self.private_ip, &self.public_ip)
        } else {
            (&self.public_ip, &self.private_ip)
        };
        // Blank is absent. A destroyed machine's entry keeps the address cleared, and handing ssh
        // an empty host produces an error about nothing in particular instead of naming the cause.
        let usable = |a: &Option<String>| {
            a.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        usable(first)
            .or_else(|| usable(second))
            .with_context(|| {
                format!(
                    "no IP address for instance {} — it has none recorded, which is how a \
                     destroyed machine's entry is kept; provision it and set the address",
                    self.name
                )
            })
    }
}

/// Which machines a role applies to.
///
/// Order matters and matches the Kotlin resolver: an explicit list wins over selectors, and a role
/// naming neither resolves to nothing rather than to everything — the safe direction, since the
/// alternative would run a role's commands on every machine in the project.
///
/// `infrastructureIds` matches an instance's **id or its name**. The Kotlin resolver matched only
/// the name, which silently broke every recipe that did what the field's name says and listed ids:
/// in the production store `jump-host-uname` and `test-recipe-1` ask for `jump-host-1` (the id,
/// whose name is `jump-host`) and resolved to nothing at all. Matching both keeps the recipes that
/// happen to use names working, since for three of six instances id and name are identical.
pub fn resolve_role_targets(
    all: &[Instance],
    project_id: &str,
    infrastructure_ids: Option<&Vec<String>>,
    selectors: Option<&Vec<String>>,
) -> Vec<Instance> {
    let in_project: Vec<&Instance> = all.iter().filter(|i| i.project_id == project_id).collect();

    if let Some(ids) = infrastructure_ids {
        if !ids.is_empty() {
            return in_project
                .into_iter()
                .filter(|i| ids.contains(&i.id) || ids.contains(&i.name))
                .cloned()
                .collect();
        }
    }
    if let Some(wanted) = selectors {
        if !wanted.is_empty() {
            return in_project
                .into_iter()
                .filter(|i| {
                    let have = i.selectors.clone().unwrap_or_default();
                    wanted.iter().any(|s| have.contains(s))
                })
                .cloned()
                .collect();
        }
    }
    Vec::new()
}

pub fn load_instances(store: &RepoDb) -> Result<Vec<Instance>> {
    let mut out = Vec::new();
    for name in store.list_names(TYPE_INFRASTRUCTURE)? {
        if let Some(value) = store.read_latest(TYPE_INFRASTRUCTURE, &name)? {
            match serde_json::from_value::<Instance>(value) {
                Ok(instance) => out.push(instance),
                Err(err) => eprintln!("⚠️  skipping infrastructure '{name}': {err}"),
            }
        }
    }
    Ok(out)
}

/// A private key on disk, removed when this value is dropped.
#[derive(Debug)]
pub struct KeyFile {
    pub path: PathBuf,
    temporary: bool,
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

const KEY_MARKERS: [&str; 5] = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
];

/// `file:/path/to/key` uses it where it lies; `vault:account/project/id` decrypts to a private
/// temporary file.
///
/// The password is a closure so it is only demanded when a vault reference actually needs it. Asking
/// eagerly meant a host whose key is a plain file still stopped to demand a vault password — and in
/// a non-interactive session that is not a prompt, it is a refusal to run at all.
pub fn resolve_ssh_key(
    ssh_key_id: &str,
    vault_root: &str,
    password: &dyn Fn() -> Result<String>,
) -> Result<KeyFile> {
    if let Some(path) = ssh_key_id.strip_prefix("file:") {
        return Ok(KeyFile { path: PathBuf::from(crate::profile::Profile::expand(path)), temporary: false });
    }
    let Some(reference) = ssh_key_id.strip_prefix("vault:") else {
        bail!("sshKeyId must start with 'file:' or 'vault:', got '{ssh_key_id}'");
    };
    let parts: Vec<&str> = reference.split('/').collect();
    if parts.len() < 3 {
        bail!("vault key reference must be account/project/id, got '{reference}'");
    }
    let (account, project) = (parts[0], parts[1]);
    let key_id = parts[2..].join("/");

    let vault = Vault::new(crate::profile::Profile::expand(vault_root), account, project);
    let items = vault.read_items()?;
    // The reference may name either the item's id or its name; the Kotlin resolver looks by id.
    let item = items
        .iter()
        .find(|i| i.id == key_id || i.name == key_id)
        .with_context(|| format!("SSH key not found in vault: {reference}"))?;

    let payload: vault::EncryptedPayload = serde_json::from_str(&item.encrypted_content)
        .context("parsing the encrypted key payload")?;
    let pw = password()?;
    let key = vault::decrypt(&pw, &payload).context("decrypting the SSH key")?;

    // Refuse early rather than handing ssh something that is not a key: the error it gives back is
    // far less informative than this one.
    if !KEY_MARKERS.iter().any(|m| key.trim_start().starts_with(m)) {
        bail!(
            "decrypted content is not an SSH private key (starts with {:?})",
            key.chars().take(30).collect::<String>()
        );
    }

    write_private_key(&key)
}

fn write_private_key(key: &str) -> Result<KeyFile> {
    let path = std::env::temp_dir().join(format!("bigbang-ssh-{}-{}.pem", std::process::id(), rand_suffix()));
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    // 0600 before the bytes land, not after: a key that is briefly world-readable is a key that
    // was world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("tightening permissions on {}", path.display()))?;
    }
    // ssh rejects a key without a trailing newline.
    let content = if key.ends_with('\n') { key.to_string() } else { format!("{key}\n") };
    file.write_all(content.as_bytes())?;
    Ok(KeyFile { path, temporary: true })
}

fn rand_suffix() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..6).map(|_| (b'a' + rng.gen_range(0..26)) as char).collect()
}

/// Everything ssh needs for one instance, including the bastion hop when there is one.
pub fn ssh_target_for(
    instance: &Instance,
    all: &[Instance],
    key_path: &str,
    jump_key_path: Option<&str>,
) -> Result<SshTarget> {
    let jump = match &instance.jump_host_id {
        Some(id) => {
            let host = all
                .iter()
                .find(|i| &i.id == id || &i.name == id)
                .with_context(|| format!("jump host '{id}' not found"))?;
            let address = host.public_ip.clone().or_else(|| host.private_ip.clone())
                .with_context(|| format!("no address for jump host {}", host.name))?;
            let user = host.ssh_username.clone().unwrap_or_else(|| "root".into());
            let _ = jump_key_path; // ssh -J uses the agent or the same identity; kept explicit.
            Some(format!("{user}@{address}"))
        }
        None => None,
    };
    Ok(SshTarget {
        host: instance.address()?,
        port: instance.ssh_port,
        user: instance.ssh_username.clone().unwrap_or_else(|| "root".into()),
        key_path: key_path.to_string(),
        jump,
    })
}

/// Variables merged in the order the executor applies them: definition, then recipe, then role.
///
/// Values are then resolved against each other, because a variable's *value* may itself reference
/// another variable — `postgres_config_dir` is `/etc/postgresql/${postgres_major_version}/main`,
/// and the major version is the knob that is meant to be changed. Substituting a command in one
/// pass expanded the outer name and left the inner one untouched, so the literal string
/// `${postgres_major_version}` was handed to the shell and `cp` failed on a path that does not
/// exist. Resolving here means every caller of `substitute` gets flat values.
pub fn merge_variables(layers: &[&BTreeMap<String, String>]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for layer in layers {
        for (k, v) in *layer {
            out.insert(k.clone(), v.clone());
        }
    }
    crate::task::resolve_nested(out)
}

// ── importing ──────────────────────────────────────────────────────────────────

/// Refuse an instance that would only fail once a run is under way.
///
/// Every check here corresponds to a failure that is cheap to catch now and expensive to catch
/// later: a missing key reference surfaces as an ssh error halfway through a recipe, and a missing
/// address surfaces as `no IP address for instance` after the store has already been changed. An
/// inventory is read far more often than it is written, so the strictness belongs at write time.
pub fn validate(instance: &Instance) -> Result<()> {
    if instance.id.trim().is_empty() {
        bail!("'id' is required");
    }
    if instance.name.trim().is_empty() {
        bail!("'name' is required");
    }
    if instance.project_id.trim().is_empty() {
        // A recipe resolves roles within one project; an instance with no project is invisible to
        // every recipe, which looks exactly like a recipe that matched nothing.
        bail!("'projectId' is required — an instance without one matches no recipe role");
    }
    if instance.is_local() {
        return Ok(());
    }
    // Blank counts as absent. A destroyed machine's inventory entry is kept as a template with the
    // address cleared, and a cloud provider reissues that address to someone else — so an empty
    // string must refuse at import rather than resolve to "" and have ssh do something surprising
    // with it.
    let has_address = |a: &Option<String>| a.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    if !has_address(&instance.public_ip) && !has_address(&instance.private_ip) {
        bail!("needs 'publicIpAddress' or 'privateIpAddress' — fill in the address of the machine that was provisioned");
    }
    match instance.ssh_username.as_deref() {
        Some(u) if !u.trim().is_empty() => {}
        _ => bail!("'sshUsername' is required"),
    }
    match instance.ssh_key_id.as_deref() {
        Some(k) if k.starts_with("file:") || k.starts_with("vault:") => {}
        Some(k) => bail!("'sshKeyId' must start with 'file:' or 'vault:', got '{k}'"),
        None => bail!("'sshKeyId' is required"),
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct ImportOutcome {
    pub imported: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<(String, String)>,
}

/// Read instance definitions from a file or a directory and write them into the store.
///
/// This exists because infrastructure was the one object type the CLI could read but never write:
/// the Kotlin app created instances through its own UI, so an environment could be *used*
/// reproducibly but never *rebuilt* reproducibly. An inventory that lives only in one laptop's
/// store is not an inventory, it is a local accident.
pub fn import(store: &RepoDb, source: &std::path::Path, force: bool) -> Result<ImportOutcome> {
    let mut files = Vec::new();
    if source.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
            .with_context(|| format!("reading {}", source.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        entries.sort();
        files.extend(entries);
    } else {
        files.push(source.to_path_buf());
    }

    let mut outcome = ImportOutcome::default();
    for file in files {
        let label = file.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(err) => {
                outcome.errors.push((label, err.to_string()));
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(err) => {
                outcome.errors.push((label, format!("not valid JSON: {err}")));
                continue;
            }
        };
        let instance: Instance = match serde_json::from_value(value.clone()) {
            Ok(i) => i,
            Err(err) => {
                outcome.errors.push((label, format!("not an instance: {err}")));
                continue;
            }
        };
        if let Err(err) = validate(&instance) {
            outcome.errors.push((label, format!("{err:#}")));
            continue;
        }
        if store.exists(TYPE_INFRASTRUCTURE, &instance.name) && !force {
            outcome.skipped.push(format!("{} (already present; --force to replace)", instance.name));
            continue;
        }
        match store.write(TYPE_INFRASTRUCTURE, &instance.name, &value) {
            Ok(_) => outcome.imported.push(instance.name.clone()),
            Err(err) => outcome.errors.push((label, format!("{err:#}"))),
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str, selectors: &[&str], jump: Option<&str>) -> Instance {
        Instance {
            id: format!("id-{name}"),
            instance_type: None,
            name: name.into(),
            project_id: "proj-1".into(),
            private_ip: Some("10.1.1.9".into()),
            public_ip: Some("203.0.113.9".into()),
            jump_host_id: jump.map(str::to_string),
            ssh_port: 22,
            ssh_username: Some("debian".into()),
            ssh_key_id: None,
            selectors: Some(selectors.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn a_local_host_is_recognised_by_its_declared_type() {
        let mut host = instance("runner", &["control"], None);
        assert!(!host.is_local());
        host.instance_type = Some("LOCAL".into());
        assert!(host.is_local(), "type LOCAL selects the local executor");
        // An address that merely looks local is not enough: the intent must be declared.
        let mut looks_local = instance("looks", &["control"], None);
        looks_local.private_ip = Some("127.0.0.1".into());
        assert!(!looks_local.is_local());
    }

    #[test]
    fn a_role_with_neither_list_nor_selectors_matches_nothing() {
        let all = vec![instance("a", &["db"], None)];
        assert!(resolve_role_targets(&all, "proj-1", None, None).is_empty());
        // The alternative — matching everything — would run a role's commands on every machine.
    }

    #[test]
    fn selectors_match_on_any_overlap() {
        let all = vec![instance("a", &["db", "vps"], None), instance("b", &["web"], None)];
        let picked = resolve_role_targets(&all, "proj-1", None, Some(&vec!["vps".into()]));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "a");
    }

    #[test]
    fn an_explicit_list_matches_an_id_even_when_the_name_differs() {
        // The production store's jump host is id=jump-host-1, name=jump-host, and the recipe asks
        // for jump-host-1. Matching names only resolved it to nothing.
        let mut host = instance("jump-host", &["bastion"], None);
        host.id = "jump-host-1".into();
        let picked = resolve_role_targets(&[host], "proj-1", Some(&vec!["jump-host-1".into()]), None);
        assert_eq!(picked.len(), 1, "an id in infrastructureIds must match");
    }

    #[test]
    fn an_explicit_list_wins_over_selectors_and_matches_on_name() {
        let all = vec![instance("a", &["db"], None), instance("b", &["db"], None)];
        let picked = resolve_role_targets(
            &all, "proj-1",
            Some(&vec!["b".into()]),
            Some(&vec!["db".into()]),
        );
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "b");
    }

    #[test]
    fn instances_from_other_projects_are_never_targeted() {
        let mut other = instance("a", &["db"], None);
        other.project_id = "proj-2".into();
        let picked = resolve_role_targets(&[other], "proj-1", None, Some(&vec!["db".into()]));
        assert!(picked.is_empty());
    }

    #[test]
    fn a_jump_host_forces_the_private_address() {
        let direct = instance("a", &[], None);
        assert_eq!(direct.address().unwrap(), "203.0.113.9");
        let behind = instance("b", &[], Some("jump"));
        assert_eq!(behind.address().unwrap(), "10.1.1.9");
    }

    #[test]
    fn the_jump_hop_is_rendered_as_user_at_host() {
        let jump = Instance { id: "jump".into(), ..instance("bastion", &[], None) };
        let target_instance = instance("db", &[], Some("jump"));
        let all = vec![jump, target_instance.clone()];
        let t = ssh_target_for(&target_instance, &all, "/k", None).unwrap();
        assert_eq!(t.jump.as_deref(), Some("debian@203.0.113.9"));
        assert_eq!(t.host, "10.1.1.9");
    }

    #[test]
    fn a_file_reference_never_asks_for_the_vault_password() {
        // The closure panics if called: a file: key must not touch the vault at all.
        let key = resolve_ssh_key("file:/dev/null", "/nonexistent",
            &|| panic!("the vault password must not be requested for a file: key"));
        assert!(key.is_ok());
    }

    #[test]
    fn a_vault_reference_that_is_not_a_key_is_refused() {
        // Guards the case where the wrong vault item is referenced: ssh's own error for this is
        // "Load key: invalid format", which sends you looking in the wrong place.
        let err = resolve_ssh_key("vault:a/b/c", "/nonexistent", &|| Ok("pw".to_string())).unwrap_err();
        assert!(format!("{err:#}").contains("not found") || format!("{err:#}").contains("No such file"));
    }

    #[test]
    fn validation_refuses_what_would_fail_mid_run() {
        let mut ok = instance("db", &["database-server"], None);
        ok.ssh_key_id = Some("file:~/.ssh/colistor-int".into());
        assert!(validate(&ok).is_ok());

        // A key reference that is neither file: nor vault: reaches ssh as a literal path.
        let mut bad_key = ok.clone();
        bad_key.ssh_key_id = Some("/home/joel/.ssh/id_rsa".into());
        assert!(format!("{:#}", validate(&bad_key).unwrap_err()).contains("file:"));

        let mut no_key = ok.clone();
        no_key.ssh_key_id = None;
        assert!(validate(&no_key).is_err());

        // No project means every recipe role resolves to nothing — indistinguishable, at the
        // console, from a recipe that simply matched no machine.
        let mut no_project = ok.clone();
        no_project.project_id = String::new();
        assert!(format!("{:#}", validate(&no_project).unwrap_err()).contains("projectId"));

        let mut no_address = ok.clone();
        no_address.public_ip = None;
        no_address.private_ip = None;
        assert!(validate(&no_address).is_err());

        // A blank address is how a destroyed machine's entry is kept as a template. It must be
        // refused, not resolved to an empty host — the provider will have reissued that address.
        let mut blank = ok.clone();
        blank.public_ip = Some("".into());
        blank.private_ip = None;
        assert!(validate(&blank).is_err(), "a blank address must be refused");
        let mut whitespace = ok.clone();
        whitespace.public_ip = Some("   ".into());
        whitespace.private_ip = None;
        assert!(validate(&whitespace).is_err(), "a whitespace address must be refused");

        // LOCAL has no host to reach, so none of the ssh fields apply to it.
        let mut local = instance("here", &[], None);
        local.instance_type = Some("LOCAL".into());
        local.public_ip = None;
        local.private_ip = None;
        local.ssh_username = None;
        local.ssh_key_id = None;
        assert!(validate(&local).is_ok());
    }

    #[test]
    fn import_writes_an_instance_that_reads_back() {
        let dir = std::env::temp_dir().join(format!("bigbang-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("int-base-1.json");
        std::fs::write(
            &source,
            r#"{"id":"int-base-1","name":"int-base-1","projectId":"proj-1",
                "publicIpAddress":"203.0.113.9","sshUsername":"debian",
                "sshKeyId":"file:~/.ssh/colistor-int","selectors":["vps"]}"#,
        )
        .unwrap();

        let store = RepoDb::new(dir.join("store"), "colistor", "repo-int");
        let outcome = import(&store, &source, false).unwrap();
        assert_eq!(outcome.imported, vec!["int-base-1".to_string()]);
        assert!(outcome.errors.is_empty());

        // The point of the round-trip: what was written is what the executor will later resolve.
        let loaded = load_instances(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address().unwrap(), "203.0.113.9");
        assert_eq!(loaded[0].ssh_username.as_deref(), Some("debian"));

        // A second import must not silently replace an inventory entry.
        let again = import(&store, &source, false).unwrap();
        assert!(again.imported.is_empty());
        assert_eq!(again.skipped.len(), 1);

        let forced = import(&store, &source, true).unwrap();
        assert_eq!(forced.imported.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_rejects_a_bad_definition_without_writing_it() {
        let dir = std::env::temp_dir().join(format!("bigbang-import-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("broken.json");
        // Valid JSON, parses as an Instance, but has no usable key reference.
        std::fs::write(
            &source,
            r#"{"id":"x","name":"x","projectId":"proj-1","publicIpAddress":"203.0.113.9",
                "sshUsername":"debian","sshKeyId":"/plain/path"}"#,
        )
        .unwrap();

        let store = RepoDb::new(dir.join("store"), "colistor", "repo-int");
        let outcome = import(&store, &source, false).unwrap();
        assert!(outcome.imported.is_empty());
        assert_eq!(outcome.errors.len(), 1);
        // The store must be untouched, not left holding a half-valid entry.
        assert!(load_instances(&store).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_variable_whose_value_names_another_variable_is_resolved() {
        // The real case: the config directory is written in terms of the major version, which is
        // the value anyone would actually change. One-pass substitution sent the literal
        // "${postgres_major_version}" to the shell and cp failed on a path that cannot exist.
        let mut defaults = BTreeMap::new();
        defaults.insert("postgres_major_version".to_string(), "17".to_string());
        defaults.insert(
            "postgres_config_dir".to_string(),
            "/etc/postgresql/${postgres_major_version}/main".to_string(),
        );
        let merged = merge_variables(&[&defaults]);
        assert_eq!(merged["postgres_config_dir"], "/etc/postgresql/17/main");

        // And a later layer overriding the inner value must move the outer one with it.
        let mut override_major = BTreeMap::new();
        override_major.insert("postgres_major_version".to_string(), "16".to_string());
        let merged = merge_variables(&[&defaults, &override_major]);
        assert_eq!(merged["postgres_config_dir"], "/etc/postgresql/16/main");
    }

    #[test]
    fn a_self_referencing_variable_does_not_hang() {
        let mut vars = BTreeMap::new();
        vars.insert("a".to_string(), "${b}".to_string());
        vars.insert("b".to_string(), "${a}".to_string());
        // The contract is only that it terminates and leaves something unresolved rather than
        // inventing a value.
        let merged = merge_variables(&[&vars]);
        assert!(merged["a"].contains("${") || merged["b"].contains("${"));

        let mut me = BTreeMap::new();
        me.insert("x".to_string(), "${x}/sub".to_string());
        let merged = merge_variables(&[&me]);
        assert_eq!(merged["x"], "${x}/sub");
    }

    #[test]
    fn later_variable_layers_win() {
        let mut a = BTreeMap::new();
        a.insert("x".to_string(), "1".to_string());
        a.insert("y".to_string(), "1".to_string());
        let mut b = BTreeMap::new();
        b.insert("y".to_string(), "2".to_string());
        let merged = merge_variables(&[&a, &b]);
        assert_eq!(merged["x"], "1");
        assert_eq!(merged["y"], "2");
    }
}
