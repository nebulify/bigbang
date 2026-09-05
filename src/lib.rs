//! BigBang, in Rust.
//!
//! A port of the Kotlin CLI, undertaken because the JVM's cost lands in the wrong place for this
//! tool: a process that runs briefly and exits, on a workstation, many times a day. The native
//! image was an attempt to fix that and brought its own tax — reflection metadata that is only as
//! complete as the commands someone happened to trace, which silently failed to deserialize a
//! `Recipe` and would have failed on `TaskDefinition` next.
//!
//! The two things that looked hardest turned out not to be:
//!
//! * **Crypto.** The vault is PBKDF2-HMAC-SHA256 (120_000 iterations, 256-bit) into AES-256-GCM
//!   with a 12-byte IV, 16-byte salt and 128-bit tag, all base64. Every piece has a Rust crate,
//!   and the format is reproduced byte for byte so both binaries read the same vault.
//! * **SSH.** There is no Java SSH library on the classpath — the Kotlin CLI shells out to `ssh`
//!   with `-o StrictHostKeyChecking=no -i <key> -p <port>` and a ProxyJump for the bastion. Rust
//!   does the same thing with `std::process::Command`, so behaviour is identical by construction.
//!
//! And the union types that need hand-written `JsonDeserializer`s in Jackson — a command being
//! either `"apt-get update"` or `{"cmd": …, "skipIf": …}` — are `#[serde(untagged)]` here.
//!
//! ## On-disk compatibility is the hard requirement
//!
//! Both binaries must read and write the same RepoDB while the port is in progress, so the layout
//! is reproduced exactly as observed from stores the Kotlin CLI wrote:
//!
//! ```text
//! <base>/<account>/<db>/<type>/<name>.rev      pointer, one line, relative path to the payload
//! <base>/<account>/<db>/<type>/<name>/<ver>.json   payload, the object verbatim, compact
//! ```
//!
//! where `<ver>` is `yyyyMMdd-HHmmss-SSS-xx-<name>` and names are sanitised by replacing every
//! character outside `[A-Za-z0-9._-]` with `-`.

pub mod exec;
pub mod infra;
pub mod library;
pub mod profile;
pub mod recipe;
pub mod repodb;
pub mod shell;
pub mod task;
pub mod vault;

/// The operation was attempted and failed.
pub const EXIT_FAILURE: u8 = 1;
/// Input was required and this session could not ask for it. Distinct from a failure so a pipeline
/// can tell "nobody could answer" from "the thing went wrong".
pub const EXIT_NEEDS_INPUT: u8 = 2;
