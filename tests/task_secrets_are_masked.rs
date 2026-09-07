//! A task's own `vault:` variables must be known to the mask before any command is echoed.
//!
//! WHAT WENT WRONG
//! The executor is handed a *snapshot* of the secret list when it is constructed. Task-level
//! variables were resolved afterwards, so a secret declared in a task's own `variables` block —
//! `"s3_access_key": "vault:colistor_s3_access_key"` — was substituted into every command that
//! referenced it while being absent from the mask. The command echo then printed it in clear.
//! An S3 access key and its secret reached a terminal that way during a test-data run.
//!
//! Nothing failed. The recipe succeeded, the data was correct, and the only evidence was the
//! credential sitting in the scrollback — which is the worst shape a security defect can take,
//! because there is no error to notice and the leak is silent by construction.
//!
//! WHY THIS TEST IS SHAPED LIKE THIS
//! The defect is an ordering invariant inside `recipe_execute`, a function that wants a vault, a
//! password, an SSH target and a live host before it will run. Reproducing it end to end would
//! mean standing all of that up to assert something that is really a property of the source:
//! resolution must precede construction. So the source is what gets asserted. It is a blunt
//! instrument, but it fails loudly if the two blocks are ever swapped back, which is exactly the
//! regression it exists to catch.

const MAIN: &str = include_str!("../src/main.rs");

#[test]
fn task_variables_are_resolved_before_the_executor_snapshots_the_secret_list() {
    let resolve = MAIN
        .find("let task_resolved = resolve_all_in(")
        .expect("recipe_execute should still resolve a task's own variables");
    let snapshot = MAIN
        .find("let secrets: Vec<String> = secret_values.clone();")
        .expect("the executor should still be given a snapshot of the secret list");

    assert!(
        resolve < snapshot,
        "task-level `vault:` variables are resolved at byte {resolve}, after the executor \
         snapshots the secret list at byte {snapshot}. In that order a secret declared in a \
         task's own variables is substituted into commands but never masked, and the command \
         echo prints it in clear."
    );
}

#[test]
fn the_secret_list_is_extended_with_what_task_resolution_found() {
    // Ordering alone is not enough: the resolved secrets have to actually be added to the list
    // the snapshot is taken from. Without this line the reorder above would be inert.
    let extend = MAIN
        .find("secret_values.extend(task_resolved.secrets.clone());")
        .expect("task-level secrets must be added to the masked set");
    let snapshot = MAIN
        .find("let secrets: Vec<String> = secret_values.clone();")
        .expect("the executor should still be given a snapshot of the secret list");

    assert!(
        extend < snapshot,
        "task-level secrets are added to the masked set after the snapshot is taken, so the \
         executor never sees them"
    );
}
