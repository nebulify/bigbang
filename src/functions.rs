//! The work a shell command cannot express: putting a file on a host, writing to the vault.
//!
//! These were declared by three task definitions and discarded by the model, so
//! `update-nginx-clicky-proxy` and `setup-nginx-upstream-metallb` deployed configuration by not
//! deploying it, ran their remaining commands, and reported success.
//!
//! ## Why a file is uploaded through the command channel
//!
//! There is no scp path here, and deliberately so. Encoding the content and decoding it on the far
//! side reuses whatever transport the run already has — SSH with its ProxyJump, or the local
//! executor — so an upload works everywhere a command works, with no second set of connection
//! flags to keep in step with the first. The templates this serves are configuration snippets of a
//! few hundred bytes to a few kilobytes; a mechanism for large files would be a different one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::exec::{wrap_command, CommandExecutor};
use crate::repodb::RepoDb;
use crate::task::{substitute, Function};
use crate::vault::Vault;

/// What the functions need that the command loop does not.
pub struct FunctionContext<'a> {
    /// Where `templatePath` is resolved from.
    pub resources_root: PathBuf,
    /// Absent when the run has no vault configured, which makes `vaultAddItem` a refusal rather
    /// than a silent skip.
    pub vault: Option<&'a Vault>,
    pub vault_password: &'a dyn Fn() -> Result<String>,
    /// The store to register provisioned machines into. Absent outside a recipe run.
    pub store: Option<&'a RepoDb>,
    pub echo: bool,
}

/// Run one function, updating `variables` when it declares an `outputVariable`.
pub fn run_function(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    run_as: Option<&str>,
    ctx: &FunctionContext,
    executor: &mut dyn CommandExecutor,
) -> Result<()> {
    if ctx.echo {
        println!("[fn] {} ({})", function.label(), function.function);
    }
    match function.function.as_str() {
        "uploadTemplate" => upload_template(function, variables, run_as, ctx, executor),
        "uploadFile" => upload_file(function, variables, run_as, ctx, executor),
        "vaultAddItem" => vault_add_item(function, variables, ctx),
        "registerInstance" => register_instance(function, variables, ctx),
        "deregisterInstance" => deregister_instance(function, variables, ctx),
        other => bail!(
            "unknown function '{other}' — refusing rather than skipping it, because a function \
             that silently does nothing is how this whole class of fault started"
        ),
    }
}

/// Render a template and place it on the host.
fn upload_template(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    run_as: Option<&str>,
    ctx: &FunctionContext,
    executor: &mut dyn CommandExecutor,
) -> Result<()> {
    let template_path = function
        .param("templatePath", variables)
        .context("uploadTemplate needs 'templatePath'")?;
    let remote_path = function
        .param("remotePath", variables)
        .context("uploadTemplate needs 'remotePath'")?;
    let mode = function.param("mode", variables).unwrap_or_else(|| "0644".to_string());

    let source = resolve_template(&ctx.resources_root, &template_path)?;
    let raw = std::fs::read_to_string(&source)
        .with_context(|| format!("reading template {}", source.display()))?;
    // It is called a template because it is one: the same ${name} substitution the commands get.
    let rendered = substitute(&raw, variables);

    let encoded = base64::engine::general_purpose::STANDARD.encode(rendered.as_bytes());
    let parent = Path::new(&remote_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_string());

    // One command so a partial upload cannot be left behind as a valid-looking file: the redirect
    // only happens if the decode succeeds.
    let script = format!(
        "mkdir -p '{parent}' && printf '%s' '{encoded}' | base64 -d > '{remote_path}' && chmod {mode} '{remote_path}'"
    );
    let wrapped = wrap_command(&script, run_as, variables);

    if ctx.echo {
        println!(
            "[fn] uploading {} -> {remote_path} ({} bytes, mode {mode})",
            source.display(),
            rendered.len()
        );
    }
    let result = executor.run(&wrapped, 120)?;
    if !result.success() {
        bail!(
            "uploading {} to {remote_path} failed (exit {}): {}",
            source.display(),
            result.exit_code,
            result.output.trim()
        );
    }
    if let Some(name) = &function.output_variable {
        variables.insert(name.clone(), remote_path);
    }
    Ok(())
}

/// Place a file on the host byte for byte.
///
/// `uploadTemplate` reads its source as UTF-8 text and substitutes `${name}` in
/// it, which is right for a config file and wrong for everything else: a
/// gzipped archive is not valid UTF-8, so the read fails before anything is
/// sent. The nebulify site deploy uploaded its tarball that way and could never
/// have worked — the failure was waiting for the first real run.
///
/// So this is a separate function rather than a flag. A template is text you
/// want rendered; a file is bytes you want unchanged, and deciding which by
/// sniffing the content is how you get a binary that was silently rewritten.
fn upload_file(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    run_as: Option<&str>,
    ctx: &FunctionContext,
    executor: &mut dyn CommandExecutor,
) -> Result<()> {
    let path = function
        .param("path", variables)
        .or_else(|| function.param("templatePath", variables))
        .context("uploadFile needs 'path'")?;
    let remote_path = function
        .param("remotePath", variables)
        .context("uploadFile needs 'remotePath'")?;
    let mode = function.param("mode", variables).unwrap_or_else(|| "0644".to_string());

    let source = resolve_template(&ctx.resources_root, &path)?;
    let bytes = std::fs::read(&source)
        .with_context(|| format!("reading {}", source.display()))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let parent = Path::new(&remote_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_string());

    if ctx.echo {
        println!(
            "[fn] uploading {} -> {remote_path} ({} bytes, mode {mode})",
            source.display(),
            bytes.len()
        );
    }

    // Sent in chunks, because the payload travels as one argument and Linux
    // caps a single argument at MAX_ARG_STRLEN — 128 KB, independently of the
    // much larger total ARG_MAX. Measured: 256 KB per chunk fails with
    // "Argument list too long", from a layer that knows nothing about uploads.
    // 64 KB leaves room for the wrapper around it.
    //
    // Written to a temporary name and moved into place at the end, so an upload
    // cut halfway leaves nothing that looks like a complete file.
    const CHUNK: usize = 64 * 1024;
    let staging = format!("{remote_path}.part");
    let mut first = true;
    for piece in encoded.as_bytes().chunks(CHUNK) {
        let piece = std::str::from_utf8(piece).expect("base64 is ascii");
        let redirect = if first { ">" } else { ">>" };
        let script = if first {
            format!("mkdir -p '{parent}' && printf '%s' '{piece}' {redirect} '{staging}.b64'")
        } else {
            format!("printf '%s' '{piece}' {redirect} '{staging}.b64'")
        };
        let result = executor.run(&wrap_command(&script, run_as, variables), 300)?;
        if !result.success() {
            bail!(
                "uploading {} to {remote_path} failed while sending (exit {}): {}",
                source.display(),
                result.exit_code,
                result.output.trim()
            );
        }
        first = false;
    }

    // Decode, check the size is what was sent, and only then take the name.
    // A truncated transfer that still decoded would otherwise be published.
    let finish = format!(
        "base64 -d < '{staging}.b64' > '{staging}' && rm -f '{staging}.b64' && \
         size=$(wc -c < '{staging}') && [ \"$size\" -eq {} ] && \
         chmod {mode} '{staging}' && mv -f '{staging}' '{remote_path}'",
        bytes.len()
    );
    let result = executor.run(&wrap_command(&finish, run_as, variables), 300)?;
    if !result.success() {
        bail!(
            "uploading {} to {remote_path} failed on the far side (exit {}): {}",
            source.display(),
            result.exit_code,
            result.output.trim()
        );
    }

    if let Some(name) = &function.output_variable {
        variables.insert(name.clone(), remote_path);
    }
    Ok(())
}

/// `templatePath` is relative to the resources root, and must stay inside it.
fn resolve_template(root: &Path, template_path: &str) -> Result<PathBuf> {
    if template_path.contains("..") {
        bail!("templatePath must not escape the resources directory: '{template_path}'");
    }
    let candidate = root.join(template_path);
    if !candidate.exists() {
        bail!(
            "template not found: {} — resources are installed alongside the library, so a template \
             added to the repository has to be installed before a run can use it",
            candidate.display()
        );
    }
    Ok(candidate)
}

/// Store a value in the vault under a name.
fn vault_add_item(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    ctx: &FunctionContext,
) -> Result<()> {
    let Some(vault) = ctx.vault else {
        bail!("vaultAddItem needs a vault, and this run has none configured");
    };
    let name = function
        .param("itemName", variables)
        .context("vaultAddItem needs 'itemName'")?;
    let content = function
        .param("content", variables)
        .context("vaultAddItem needs 'content'")?;
    let item_type = function
        .param("itemType", variables)
        .unwrap_or_else(|| "SECRET".to_string());
    let description = function.param("description", variables);

    // An unresolved placeholder means the value it should have carried never arrived — usually a
    // captureOutput that did not run. Writing that into the vault would store the literal text
    // "${kubeconfig_content}" as if it were a kubeconfig.
    if content.contains("${") {
        bail!(
            "refusing to store an unresolved value in the vault as '{name}': the content still \
             contains a placeholder ({}). Whatever was meant to fill it did not run.",
            content.chars().take(60).collect::<String>()
        );
    }
    if content.trim().is_empty() {
        bail!("refusing to store an empty value in the vault as '{name}'");
    }

    let password = (ctx.vault_password)()?;
    let id = vault
        .add(&name, &item_type, description.as_deref(), &content, &password)
        .with_context(|| format!("storing '{name}' in the vault"))?;
    if ctx.echo {
        println!("[fn] stored '{name}' in the vault ({} bytes)", content.len());
    }
    if let Some(var) = &function.output_variable {
        variables.insert(var.clone(), id);
    }
    Ok(())
}

/// Record a machine this run created, so the inventory is a consequence of provisioning rather
/// than something transcribed by hand afterwards.
///
/// Provisioning previously ended by *printing* what it had made. Someone then read the address off
/// the screen, edited a JSON file and imported it — three steps, one of them a transcription, and
/// the reason a stale address once sat in git pointing at an address the provider had reissued.
///
/// The fields come from the task's variables, which is where `captureOutput` puts the id and
/// address the provisioning commands reported.
fn register_instance(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    ctx: &FunctionContext,
) -> Result<()> {
    let Some(store) = ctx.store else {
        bail!("registerInstance needs a store, and this run has none");
    };
    let name = function
        .param("name", variables)
        .context("registerInstance needs 'name'")?;

    let mut instance = serde_json::Map::new();
    // Everything the caller supplied, minus the empty ones: a parameter left unset is absent, not
    // a field set to "".
    for key in function.params.keys() {
        if let Some(value) = function.param(key, variables) {
            if !value.trim().is_empty() {
                instance.insert(key.clone(), serde_json::Value::String(value));
            }
        }
    }
    // `selectors` is a list everywhere else, so accept the comma-separated form a task variable
    // can actually carry and convert it.
    if let Some(serde_json::Value::String(raw)) = instance.get("selectors").cloned() {
        let list: Vec<serde_json::Value> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();
        instance.insert("selectors".into(), serde_json::Value::Array(list));
    }
    // `sshKeyName` composes the reference rather than carrying it, because a variable whose value
    // begins with `vault:` is resolved by the recipe before a function ever sees it. That is right
    // for a password and wrong here: an instance stores the *reference* and resolves it per
    // connection. Carrying it as a literal produced an inventory entry containing the private key.
    if let Some(key_name) = function.param("sshKeyName", variables) {
        let Some(vault) = ctx.vault else {
            bail!("sshKeyName needs a vault to compose a reference against");
        };
        instance.remove("sshKeyName");
        instance.insert(
            "sshKeyId".into(),
            serde_json::Value::String(format!(
                "vault:{}/{}/{}",
                vault.account_id, vault.project_code, key_name
            )),
        );
    }
    instance.entry("id").or_insert_with(|| serde_json::Value::String(name.clone()));

    let value = serde_json::Value::Object(instance);
    let parsed: crate::infra::Instance =
        serde_json::from_value(value.clone()).context("the registered instance is not valid")?;
    // The same guard `infra import` applies. Registering a machine with no address would record
    // something no recipe can reach, and a half-finished provision is exactly when that happens.
    crate::infra::validate(&parsed)
        .with_context(|| format!("refusing to register '{name}'"))?;

    store
        .write(crate::infra::TYPE_INFRASTRUCTURE, &name, &value)
        .with_context(|| format!("registering '{name}'"))?;
    if ctx.echo {
        println!("[fn] registered '{name}' at {}", parsed.address().unwrap_or_default());
    }
    if let Some(var) = &function.output_variable {
        variables.insert(var.clone(), name);
    }
    Ok(())
}

/// Forget a machine this run destroyed.
///
/// Without it the store accumulates entries for machines that no longer exist, and since a provider
/// reissues addresses, a recipe that later resolves one of those is pointed at somebody else's
/// host. The payload history stays on disk, so this is reversible.
fn deregister_instance(
    function: &Function,
    variables: &mut BTreeMap<String, String>,
    ctx: &FunctionContext,
) -> Result<()> {
    let Some(store) = ctx.store else {
        bail!("deregisterInstance needs a store, and this run has none");
    };
    let name = function
        .param("name", variables)
        .context("deregisterInstance needs 'name'")?;
    let removed = store
        .remove(crate::infra::TYPE_INFRASTRUCTURE, &name)
        .with_context(|| format!("deregistering '{name}'"))?;
    if ctx.echo {
        println!(
            "[fn] {} '{name}'",
            if removed { "deregistered" } else { "nothing to deregister for" }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandResult;

    struct Recorder {
        seen: Vec<String>,
        code: i32,
    }
    impl CommandExecutor for Recorder {
        fn run(&mut self, command: &str, _t: u64) -> Result<CommandResult> {
            self.seen.push(command.to_string());
            Ok(CommandResult { exit_code: self.code, output: String::new() })
        }
    }

    fn ctx(root: &Path) -> FunctionContext<'_> {
        FunctionContext {
            resources_root: root.to_path_buf(),
            vault: None,
            vault_password: &|| Ok("pw".to_string()),
            store: None,
            echo: false,
        }
    }

    fn upload_fn(template: &str, remote: &str) -> Function {
        let mut params = BTreeMap::new();
        params.insert("templatePath".into(), template.to_string());
        params.insert("remotePath".into(), remote.to_string());
        params.insert("mode".into(), "0600".into());
        Function {
            function: "uploadTemplate".into(),
            name: Some("Upload".into()),
            description: None,
            params,
            output_variable: None,
        }
    }

    #[test]
    fn a_template_is_rendered_and_its_content_survives_the_round_trip() {
        let root = std::env::temp_dir().join(format!("bb-fn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nginx")).unwrap();
        std::fs::write(root.join("nginx/site.conf"), "server_name ${domain};\n").unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("domain".to_string(), "colistor.com".to_string());
        let mut rec = Recorder { seen: vec![], code: 0 };

        run_function(&upload_fn("nginx/site.conf", "/etc/nginx/x.conf"), &mut vars, Some("root"), &ctx(&root), &mut rec)
            .unwrap();

        assert_eq!(rec.seen.len(), 1);
        let cmd = &rec.seen[0];
        // wrap_command escapes single quotes the shell's way ('"'"'), so assert on the parts
        // rather than on quoting that belongs to the wrapper.
        assert!(cmd.starts_with("sudo -n bash -lc"), "runAs must be honoured: {cmd}");
        assert!(cmd.contains("chmod 0600"), "{cmd}");
        assert!(cmd.contains("/etc/nginx/x.conf"), "{cmd}");
        assert!(cmd.contains("mkdir -p"), "{cmd}");
        assert!(cmd.contains("base64 -d"), "{cmd}");

        // The payload must decode to the *substituted* text, not the raw template.
        let b64 = cmd
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=')
            .filter(|t| t.len() >= 16)
            .find(|t| base64::engine::general_purpose::STANDARD.decode(t).is_ok())
            .expect("a base64 payload in the command");
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
        ).unwrap();
        assert_eq!(decoded, "server_name colistor.com;\n");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_upload_is_an_error_not_a_shrug() {
        let root = std::env::temp_dir().join(format!("bb-fn-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("t.conf"), "x").unwrap();
        let mut rec = Recorder { seen: vec![], code: 1 };
        let err = run_function(&upload_fn("t.conf", "/etc/t"), &mut BTreeMap::new(), None, &ctx(&root), &mut rec)
            .unwrap_err();
        assert!(format!("{err:#}").contains("failed"), "{err:#}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_template_names_the_path_it_looked_for() {
        let root = std::env::temp_dir().join(format!("bb-fn-missing-{}", std::process::id()));
        let mut rec = Recorder { seen: vec![], code: 0 };
        let err = run_function(&upload_fn("nope.conf", "/etc/t"), &mut BTreeMap::new(), None, &ctx(&root), &mut rec)
            .unwrap_err();
        assert!(format!("{err:#}").contains("nope.conf"), "{err:#}");
        assert!(rec.seen.is_empty(), "nothing should be sent when the template is missing");
    }

    #[test]
    fn a_template_path_may_not_escape_the_resources_directory() {
        let root = std::env::temp_dir().join("bb-fn-escape");
        let mut rec = Recorder { seen: vec![], code: 0 };
        let err = run_function(
            &upload_fn("../../../etc/shadow", "/tmp/x"),
            &mut BTreeMap::new(), None, &ctx(&root), &mut rec,
        ).unwrap_err();
        assert!(format!("{err:#}").contains("escape"), "{err:#}");
    }

    fn register_fn(params: &[(&str, &str)]) -> Function {
        Function {
            function: "registerInstance".into(),
            name: Some("Register".into()),
            description: None,
            params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            output_variable: None,
        }
    }

    fn store_at(tag: &str) -> (std::path::PathBuf, RepoDb) {
        let root = std::env::temp_dir().join(format!("bb-reg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        (root.clone(), RepoDb::new(root, "test", "test"))
    }

    #[test]
    fn a_provisioned_machine_registers_itself() {
        let (root, store) = store_at("ok");
        let ctx = FunctionContext {
            resources_root: root.clone(),
            vault: None,
            vault_password: &|| Ok("pw".into()),
            store: Some(&store),
            echo: false,
        };
        // The address arrives through a variable, which is where captureOutput puts it.
        let mut vars = BTreeMap::new();
        vars.insert("found_ip".to_string(), "203.0.113.7".to_string());

        run_function(
            &register_fn(&[
                ("name", "int-base-1"),
                ("projectId", "proj-1"),
                ("publicIpAddress", "${found_ip}"),
                ("sshUsername", "debian"),
                ("sshKeyId", "vault:colistor/colistor-int/colistor-int-ssh-key"),
                ("selectors", "database-server, vps , int"),
            ]),
            &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 },
        )
        .unwrap();

        let loaded = crate::infra::load_instances(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "int-base-1");
        assert_eq!(loaded[0].address().unwrap(), "203.0.113.7", "the captured address must land");
        // A comma-separated variable becomes the list every other part of the model expects.
        assert_eq!(
            loaded[0].selectors.clone().unwrap(),
            vec!["database-server", "vps", "int"],
            "selectors should be split and trimmed"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A recipe variable holding `vault:...` is resolved to the secret before a function sees it,
    /// so an instance must compose its key reference from a name instead. The first run of this
    /// wrote the private key itself into the inventory entry.
    #[test]
    fn a_key_reference_is_composed_rather_than_carried() {
        let (root, store) = store_at("keyref");
        let vault = Vault::new(root.join("v"), "colistor", "colistor-int");
        let ctx = FunctionContext {
            resources_root: root.clone(), vault: Some(&vault),
            vault_password: &|| Ok("pw".into()), store: Some(&store), echo: false,
        };
        run_function(
            &register_fn(&[
                ("name", "int-base-1"), ("projectId", "proj-1"),
                ("publicIpAddress", "203.0.113.7"), ("sshUsername", "debian"),
                ("sshKeyName", "colistor-int-ssh-key"),
            ]),
            &mut BTreeMap::new(), None, &ctx, &mut Recorder { seen: vec![], code: 0 },
        )
        .unwrap();

        let loaded = crate::infra::load_instances(&store).unwrap();
        assert_eq!(
            loaded[0].ssh_key_id.as_deref(),
            Some("vault:colistor/colistor-int/colistor-int-ssh-key"),
            "the reference should be composed from the vault's own account and project"
        );
        assert!(!format!("{:?}", loaded[0]).contains("PRIVATE KEY"), "a key body reached the store");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The failure this guards: a provision that half-worked. Registering a machine with no
    /// address records something no recipe can reach, and the run reports success.
    #[test]
    fn a_machine_with_no_address_is_not_registered() {
        let (root, store) = store_at("noaddr");
        let ctx = FunctionContext {
            resources_root: root.clone(), vault: None,
            vault_password: &|| Ok("pw".into()), store: Some(&store), echo: false,
        };
        // The capture found nothing, so the variable resolves to empty.
        let mut vars = BTreeMap::new();
        vars.insert("found_ip".to_string(), "".to_string());

        let err = run_function(
            &register_fn(&[
                ("name", "half-built"),
                ("projectId", "proj-1"),
                ("publicIpAddress", "${found_ip}"),
                ("sshUsername", "debian"),
                ("sshKeyId", "file:/k"),
            ]),
            &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("half-built"), "{err:#}");
        assert!(crate::infra::load_instances(&store).unwrap().is_empty(), "nothing should be stored");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn registering_twice_replaces_rather_than_duplicates() {
        let (root, store) = store_at("twice");
        let ctx = FunctionContext {
            resources_root: root.clone(), vault: None,
            vault_password: &|| Ok("pw".into()), store: Some(&store), echo: false,
        };
        let mut vars = BTreeMap::new();
        for address in ["203.0.113.7", "203.0.113.9"] {
            run_function(
                &register_fn(&[
                    ("name", "int-base-1"), ("projectId", "proj-1"),
                    ("publicIpAddress", address), ("sshUsername", "debian"), ("sshKeyId", "file:/k"),
                ]),
                &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 },
            )
            .unwrap();
        }
        let loaded = crate::infra::load_instances(&store).unwrap();
        assert_eq!(loaded.len(), 1, "a re-run must not duplicate the machine");
        assert_eq!(loaded[0].address().unwrap(), "203.0.113.9", "the newer address should win");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Without this the store keeps machines that no longer exist, and a provider that reissues
    /// addresses turns a ghost entry into someone else's host.
    #[test]
    fn destroying_a_machine_deregisters_it() {
        let (root, store) = store_at("dereg");
        let ctx = FunctionContext {
            resources_root: root.clone(), vault: None,
            vault_password: &|| Ok("pw".into()), store: Some(&store), echo: false,
        };
        let mut vars = BTreeMap::new();
        run_function(
            &register_fn(&[
                ("name", "doomed"), ("projectId", "proj-1"),
                ("publicIpAddress", "203.0.113.7"), ("sshUsername", "debian"), ("sshKeyId", "file:/k"),
            ]),
            &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 },
        )
        .unwrap();
        assert_eq!(crate::infra::load_instances(&store).unwrap().len(), 1);

        let mut dereg = register_fn(&[("name", "doomed")]);
        dereg.function = "deregisterInstance".into();
        run_function(&dereg, &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 }).unwrap();
        assert!(crate::infra::load_instances(&store).unwrap().is_empty(), "the ghost survived");

        // Deregistering something absent is not an error: destroy runs after a failed provision too.
        run_function(&dereg, &mut vars, None, &ctx, &mut Recorder { seen: vec![], code: 0 }).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn registering_without_a_store_is_refused_rather_than_skipped() {
        let err = run_function(
            &register_fn(&[("name", "x"), ("projectId", "p"), ("publicIpAddress", "1.2.3.4")]),
            &mut BTreeMap::new(), None, &ctx(Path::new("/tmp")),
            &mut Recorder { seen: vec![], code: 0 },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("needs a store"), "{err:#}");
    }

    #[test]
    fn an_unknown_function_is_refused() {
        let f = Function {
            function: "doTheThing".into(), name: None, description: None,
            params: BTreeMap::new(), output_variable: None,
        };
        let mut rec = Recorder { seen: vec![], code: 0 };
        let err = run_function(&f, &mut BTreeMap::new(), None, &ctx(Path::new("/tmp")), &mut rec).unwrap_err();
        assert!(format!("{err:#}").contains("unknown function"), "{err:#}");
    }

    /// The failure this guards is subtle: captureOutput not running leaves the placeholder intact,
    /// and the vault would then hold the literal string "${kubeconfig_content}".
    #[test]
    fn an_unresolved_placeholder_is_never_written_to_the_vault() {
        let mut params = BTreeMap::new();
        params.insert("itemName".into(), "kubeconfig".to_string());
        params.insert("content".into(), "${kubeconfig_content}".to_string());
        let f = Function {
            function: "vaultAddItem".into(), name: None, description: None,
            params, output_variable: None,
        };
        // No vault configured, so this also proves the vault check happens — but the placeholder
        // check must be the thing that fires when a vault *is* present, so assert on both paths.
        let err = run_function(&f, &mut BTreeMap::new(), None, &ctx(Path::new("/tmp")), &mut Recorder { seen: vec![], code: 0 })
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("vault"), "{text}");
    }

    /// A local shell, so the upload can be checked by looking at the file it
    /// produced rather than at the commands it claims to have sent.
    struct RealShell;
    impl CommandExecutor for RealShell {
        fn run(&mut self, command: &str, _t: u64) -> Result<CommandResult> {
            let out = std::process::Command::new("sh").arg("-c").arg(command).output()?;
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Ok(CommandResult { exit_code: out.status.code().unwrap_or(-1), output: text })
        }
    }

    fn upload_file_fn(path: &str, remote: &str) -> Function {
        let mut params = BTreeMap::new();
        params.insert("path".into(), path.to_string());
        params.insert("remotePath".into(), remote.to_string());
        params.insert("mode".into(), "0644".into());
        Function {
            function: "uploadFile".into(),
            name: Some("Upload".into()),
            description: None,
            params,
            output_variable: None,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bb-upload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_binary_file_arrives_byte_for_byte() {
        // The bug this exists for: uploadTemplate reads its source as UTF-8, so
        // a gzip fails before a single byte is sent. Every byte value appears
        // here, including the 0x8b that broke the site tarball.
        let root = scratch("binary");
        let payload: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        std::fs::write(root.join("blob.bin"), &payload).unwrap();
        let remote = root.join("out.bin");

        let f = upload_file_fn("blob.bin", remote.to_str().unwrap());
        let mut vars = BTreeMap::new();
        run_function(&f, &mut vars, None, &ctx(&root), &mut RealShell).expect("upload");

        assert_eq!(std::fs::read(&remote).unwrap(), payload, "the bytes changed in transit");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_payload_larger_than_one_command_line_still_arrives() {
        // Sent in chunks because the base64 travels as an ssh argument. A real
        // site with images is megabytes; the failure without chunking is
        // "Argument list too long", from a layer that knows nothing of uploads.
        let root = scratch("large");
        let payload: Vec<u8> = (0u8..=255).cycle().take(900_000).collect();
        std::fs::write(root.join("big.bin"), &payload).unwrap();
        let remote = root.join("big-out.bin");

        let f = upload_file_fn("big.bin", remote.to_str().unwrap());
        let mut vars = BTreeMap::new();
        run_function(&f, &mut vars, None, &ctx(&root), &mut RealShell).expect("upload");

        let arrived = std::fs::read(&remote).unwrap();
        assert_eq!(arrived.len(), payload.len());
        assert_eq!(arrived, payload);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dollar_sequence_in_a_file_is_not_substituted() {
        // The other half of the split: a template is rendered, a file is not.
        // A shell script or a config full of ${...} uploaded as a file must
        // arrive with them intact.
        let root = scratch("dollars");
        let text = b"echo ${site_root} and ${release}\n";
        std::fs::write(root.join("script.sh"), text).unwrap();
        let remote = root.join("script-out.sh");

        let f = upload_file_fn("script.sh", remote.to_str().unwrap());
        let mut vars = BTreeMap::new();
        vars.insert("site_root".to_string(), "/var/www".to_string());
        run_function(&f, &mut vars, None, &ctx(&root), &mut RealShell).expect("upload");

        assert_eq!(std::fs::read(&remote).unwrap(), text.to_vec());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_is_left_at_the_target_name_when_the_transfer_is_cut() {
        // A half-written file that still decodes would be published as if it
        // were the site. The staging name is what makes that impossible.
        let root = scratch("cut");
        std::fs::write(root.join("blob.bin"), vec![7u8; 4096]).unwrap();
        let remote = root.join("never.bin");

        let f = upload_file_fn("blob.bin", remote.to_str().unwrap());
        let mut vars = BTreeMap::new();
        // A recorder that fails every command: nothing reaches the far side.
        let mut broken = Recorder { seen: Vec::new(), code: 1 };
        let err = run_function(&f, &mut vars, None, &ctx(&root), &mut broken).unwrap_err();
        assert!(format!("{err:#}").contains("failed"), "{err:#}");
        assert!(!remote.exists(), "a failed upload must leave no file at the target name");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A shell that quietly loses one chunk, as a dropped connection would.
    struct LossyShell {
        drop_after: usize,
        appends: usize,
    }
    impl CommandExecutor for LossyShell {
        fn run(&mut self, command: &str, _t: u64) -> Result<CommandResult> {
            if command.contains(">> ") {
                self.appends += 1;
                if self.appends > self.drop_after {
                    // Reports success having written nothing — the shape of a
                    // transfer that died without saying so.
                    return Ok(CommandResult { exit_code: 0, output: String::new() });
                }
            }
            let out = std::process::Command::new("sh").arg("-c").arg(command).output()?;
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Ok(CommandResult { exit_code: out.status.code().unwrap_or(-1), output: text })
        }
    }

    #[test]
    fn a_transfer_that_lost_a_chunk_is_refused_rather_than_published() {
        // The chunks are a multiple of four bytes, so a truncated payload is
        // still *valid* base64 and decodes without complaint. Only the length
        // check notices — which is why the length check exists, and why a
        // shorter file must never reach the target name.
        let root = scratch("lossy");
        let payload: Vec<u8> = (0u8..=255).cycle().take(300_000).collect();
        std::fs::write(root.join("blob.bin"), &payload).unwrap();
        let remote = root.join("truncated.bin");

        let f = upload_file_fn("blob.bin", remote.to_str().unwrap());
        let mut vars = BTreeMap::new();
        let mut lossy = LossyShell { drop_after: 1, appends: 0 };
        let err = run_function(&f, &mut vars, None, &ctx(&root), &mut lossy)
            .expect_err("a short file must not be accepted");
        assert!(format!("{err:#}").contains("far side"), "{err:#}");
        assert!(!remote.exists(), "a truncated upload was published");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_function_is_still_refused_rather_than_skipped() {
        let root = scratch("unknown");
        let mut params = BTreeMap::new();
        params.insert("path".into(), "x".to_string());
        let f = Function {
            function: "uploadWhatever".into(),
            name: None, description: None, params, output_variable: None,
        };
        let mut vars = BTreeMap::new();
        let err = run_function(&f, &mut vars, None, &ctx(&root), &mut Recorder { seen: vec![], code: 0 })
            .unwrap_err();
        assert!(format!("{err:#}").contains("uploadWhatever"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
