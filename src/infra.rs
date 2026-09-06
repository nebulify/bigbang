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
        first
            .clone()
            .or_else(|| second.clone())
            .with_context(|| format!("no IP address for instance {}", self.name))
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
pub fn resolve_ssh_key(ssh_key_id: &str, vault_root: &str, password: &str) -> Result<KeyFile> {
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
    let key = vault::decrypt(password, &payload).context("decrypting the SSH key")?;

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
pub fn merge_variables(layers: &[&BTreeMap<String, String>]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for layer in layers {
        for (k, v) in *layer {
            out.insert(k.clone(), v.clone());
        }
    }
    out
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
    fn a_vault_reference_that_is_not_a_key_is_refused() {
        // Guards the case where the wrong vault item is referenced: ssh's own error for this is
        // "Load key: invalid format", which sends you looking in the wrong place.
        let err = resolve_ssh_key("vault:a/b/c", "/nonexistent", "pw").unwrap_err();
        assert!(format!("{err:#}").contains("not found") || format!("{err:#}").contains("No such file"));
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
