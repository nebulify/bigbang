# A corpus these guards can always run against

Five real definitions, copied from `nebulify/bigbang-library`. They are fixtures, not a
second home for the library: each is here because it exercises something the guards in
`../parses_every_repository_task.rs` exist to catch.

| | why it is here |
|---|---|
| `create-postgresql-database.json` | declares `assertions` — the field serde silently dropped for a long time |
| `setup-postgresql-firewall.json` | enables UFW, the command that once locked a host out |
| `setup-nginx-proxy.json` | uploads resources, and enables UFW after allowing SSH |
| `configure-haproxy.json` | a refusal step, `condition`, and an upload |
| `restore-drill.json` | `continueOnError`, `skipIf`, captured output |

The guards also read any corpus named by `BIGBANG_TASK_CORPUS`, so pointing them at a whole
library sweeps every definition in it. What this directory guarantees is that a bare clone
still checks something real — before it was here, extracting this repository turned four
structural guards into four tests that passed while reading nothing.

Refresh them when the library's own copies change in a way these guards care about.
