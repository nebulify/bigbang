# bigbang

A deployment CLI. A *recipe* says what to do and which roles do it; an *inventory* says
which machines answer to a role; a *library* holds the tasks; a *vault* holds the secrets.
Nothing in this repository knows about any particular environment — that is the point.

```sh
./install.sh                                       # build, test, put bigbang and bb on PATH
bigbang profile list
bigbang recipe execute --id site-deploy --profile prod --dry-run
```

## What it is

| | |
|---|---|
| `bigbang` | the CLI: recipes, library, inventory, vault, profiles, and an interactive shell |
| `bb` | runs one command with vault items in its environment, against an unlocked vault |

A run resolves a recipe's variables (including `vault:` references), matches each role to
machines in the inventory, refuses before touching anything if a role's `count` is not met
or a prerequisite is missing, then executes each task over ssh — with `skipIf`, retries,
output assertions and per-task verification decided here rather than by the exit code alone.

## The three things it will not do

**Default anything environment-specific.** A variable whose value differs between
environments is declared empty and refused at the start of a run. A production-shaped
default is how a deploy silently overwrites the wrong thing.

**Put a secret on a command line.** `vault request` opens a terminal where the operator
types a value; the asking process never sees it. `vault add --data <value>` writes the value
into the shell's history, so it is the wrong door. Commands are masked when echoed, and an
upload never prints its payload at all — a base64 blob cannot be masked, because the
encoding is not aligned to the secret inside it.

**Claim to have done something it did not.** Every field a definition declares is either
honoured or refused: `serde` silently dropping unknown fields once left eight of fifteen
recipes doing nothing while reporting success, and the structural guard in
`tests/parses_every_repository_task.rs` exists to keep that from recurring.

## Tests

```sh
cargo test                                                  # unit + the bundled corpus
BIGBANG_TASK_CORPUS=../bigbang-library/tasks cargo test      # sweep a whole library too
```

`tests/corpus/` holds real definitions so the structural guards always have something to
read. They check that every definition parses, that no declared field is silently dropped,
that declared assertions reach the model, and that no task brings a firewall up before
allowing SSH — which is a guard because it happened.

## Related repositories

- **`nebulify/bigbang-library`** — the shared infrastructure tasks and packages
- **`nebulify/scaffold-template`** — a project skeleton that brings its own recipe and commands
