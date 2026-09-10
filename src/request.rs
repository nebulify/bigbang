//! Asking the operator for a secret, through a channel this process cannot read.
//!
//! WHY THIS EXISTS
//! A secret typed into this process is a secret this process has seen. When the thing
//! driving bigbang is an assistant, or a script, or anything you would rather not hand a
//! password to, the useful property is that it can *ask* for a credential without ever
//! being able to observe it being given.
//!
//! So this writes a request and then watches the vault. The operator types into a terminal
//! that bgconsole owns; nothing is ever written back here. The outcome is discovered by
//! looking at the artefact — does the item exist now? — rather than by reading a reply,
//! because a reply channel is a way for the secret to come back.
//!
//! WHAT THIS IS AND IS NOT WORTH
//! On a machine where the caller runs as the same user, this raises the cost of observing a
//! secret; it does not make it impossible. Measured on the machine this was written for, on
//! a live prompt opened through this channel:
//!
//!   ptrace_scope = 1     reading /proc/<prompt>/mem is refused — Permission denied
//!   wayland session      one client cannot keylog another through the display server
//!   sudo needs a password    the caller cannot simply become another user
//!   /proc/<prompt>/environ   IS readable — which is why --prompt exists: the value is
//!                            never in the environment or in argv
//!   /dev/pts/<n>         IS openable by the same uid (crw--w---- joel tty)
//!
//! That last line is the honest limit. A process of the same user can open the prompting
//! terminal and compete for what is typed into it. Two attempts to demonstrate a steal here
//! failed — the reading process lost the race both times — so this is a race, not a reliable
//! read, but "I could not do it twice" is not "it cannot be done".
//!
//! So: this protects the *entry* of a secret against reading memory and against the display
//! server, and it keeps the value out of argv, the environment and any file. It does not
//! protect against a same-uid process that is trying. The vault file afterwards is not
//! protected at all: same user, readable. For a real boundary the vault and its prompt have
//! to run as a different user, which this module does not create — it is worth knowing which
//! half you are getting.
//!
//! THE REQUEST NAMES AN ACTION, NEVER A COMMAND
//! The request carries a kind and a few validated parameters. The receiving side composes
//! the command itself from a fixed list. If a request could carry a command string, this
//! file would be a way for anything on the machine to run code inside a terminal the
//! operator trusts, which is the opposite of the point.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Where bgconsole watches. One file per requesting process, drained and truncated by the
/// receiver, so two requests cannot be read twice or lost against each other.
///
/// A directory of its own, under bgconsole's existing `requests/`. That parent already holds
/// one file per bgconsole window for its editor channel, and a watcher draining the whole
/// parent would swallow another window's lines before it read them. Separating the two makes
/// that collision impossible rather than unlikely.
pub fn request_dir() -> PathBuf {
    dirs_data_root()
        .join("bgconsole")
        .join("requests")
        .join("typed")
}

fn dirs_data_root() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local")
                .join("share")
        })
}

/// A parameter that will be pasted into a command line by the receiver.
///
/// Restricted to characters that cannot mean anything to a shell. This is the single most
/// important check in the file: the receiver composes a command from these, so a value
/// containing a quote, a semicolon or a backtick would be an injection into a terminal the
/// operator trusts. Rejecting here as well as there is deliberate — the receiver must not
/// be the only thing standing between a bad parameter and a shell.
pub fn validate_param(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if value.len() > 128 {
        anyhow::bail!("{name} is too long");
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        anyhow::bail!(
            "{name} may contain only letters, digits, dot, dash and underscore — \
             it is placed on a command line and anything else could change what runs"
        );
    }
    Ok(())
}

/// Emit a request for the operator to store one vault item.
///
/// Returns as soon as the request is written; the caller polls for the item.
pub fn ask_for_item(
    profile: &str,
    item_id: &str,
    type_: &str,
    description: Option<&str>,
) -> Result<PathBuf> {
    validate_param("profile", profile)?;
    validate_param("item-id", item_id)?;
    validate_param("type", type_)?;

    let dir = request_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;

    // Named for this process so a receiver draining one file cannot swallow another's.
    let path = dir.join(format!("{}-vault", std::process::id()));

    // Hand-built rather than serialised: the payload is three validated fields and a
    // description that is escaped, and keeping it explicit makes the wire format readable
    // in the file when something goes wrong.
    let desc = description.unwrap_or("").replace('\\', "").replace('"', "'");
    let line = format!(
        "{{\"kind\":\"vault-add\",\"profile\":\"{profile}\",\"item_id\":\"{item_id}\",\
         \"type\":\"{type_}\",\"description\":\"{desc}\"}}\n"
    );

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;

    Ok(path)
}

/// Whether a receiver is listening.
///
/// Checked before waiting, because the failure to report is the one that wastes the most
/// time: without it, a request into a directory nothing watches looks exactly like an
/// operator who has not got round to typing yet.
///
/// A receiver announces itself with a `receiver-<pid>` file. The pid is checked rather than
/// trusted, so a bgconsole that crashed does not leave behind a promise it can no longer
/// keep — the marker of a dead process is removed on sight instead of being counted.
pub fn receiver_present() -> bool {
    let dir = request_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    let mut alive = false;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.strip_prefix("receiver-") else {
            continue;
        };
        if pid.parse::<u32>().is_ok() && std::path::Path::new(&format!("/proc/{pid}")).exists() {
            alive = true;
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    alive
}

/// Wait until `present` reports the item has arrived.
///
/// Polls rather than watching, because the thing being waited for is a human, and a second
/// of latency against a person typing a password is not worth an inotify handle.
pub fn wait_for<F>(deadline: Duration, mut present: F) -> Result<bool>
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    let mut announced = false;
    while start.elapsed() < deadline {
        if present() {
            return Ok(true);
        }
        if !announced && start.elapsed() > Duration::from_secs(3) {
            eprintln!("   waiting for the value to be entered…");
            announced = true;
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    Ok(false)
}

/// Remove a request file this process wrote, so an abandoned request is not acted on later.
pub fn withdraw(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_that_could_change_a_command_are_refused() {
        // Each of these would mean something to a shell. The receiver composes a command
        // from these values, so anything here that survives is a command injection into a
        // terminal the operator trusts.
        for bad in [
            "a;rm -rf /", "a b", "a$(id)", "a`id`", "a|b", "a>b", "a&b", "a'b", "a\"b",
            "../escape", "a\nb", "",
        ] {
            assert!(
                validate_param("item-id", bad).is_err(),
                "should have been refused: {bad:?}"
            );
        }
    }

    #[test]
    fn ordinary_identifiers_are_accepted() {
        for good in ["nebulify-ssh-key", "int_db_password", "brevo.api.key", "a1"] {
            assert!(validate_param("item-id", good).is_ok(), "should be fine: {good:?}");
        }
    }

    #[test]
    fn an_over_long_parameter_is_refused() {
        assert!(validate_param("item-id", &"a".repeat(129)).is_err());
    }
}
