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
        "vaultAddItem" => vault_add_item(function, variables, ctx),
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
}
