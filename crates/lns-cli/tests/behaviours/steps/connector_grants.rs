use crate::world::BehaviourWorld;
use cucumber::{given, then};
use lns_policy::grants::{
    GrantRecord, GrantStore, JsonFileGrantStore, WorkloadGrantFile, WorkloadIdentity, project_key,
};
use std::path::PathBuf;

fn cwd(world: &mut BehaviourWorld) -> PathBuf {
    if world.cwd.is_none() {
        world.cwd = Some(tempfile::TempDir::new().expect("create tempdir"));
    }
    world.cwd.as_ref().unwrap().path().to_path_buf()
}

fn store(world: &mut BehaviourWorld) -> JsonFileGrantStore {
    JsonFileGrantStore::new(cwd(world).join(".lns/workload-grants.json"))
}

/// Derived the same way the commands derive it, so a seeded grant keys identically to one a real run would have left.
fn this_project(world: &mut BehaviourWorld) -> String {
    project_key(&cwd(world))
}

fn workload_of(key: &str) -> WorkloadIdentity {
    let dir = key
        .strip_prefix("def:")
        .unwrap_or_else(|| panic!("unrecognized workload key {key}"));
    WorkloadIdentity::definition(dir)
}

fn seed(world: &mut BehaviourWorld, record: GrantRecord) {
    let store = store(world);
    let mut file = store.load().expect("load grants");
    file.upsert(record);
    store.save(&file).expect("save grants");
}

fn loaded(world: &mut BehaviourWorld) -> WorkloadGrantFile {
    store(world).load().expect("load grants")
}

fn output(world: &BehaviourWorld) -> &str {
    &world
        .result
        .as_ref()
        .expect("a run must have happened")
        .output
}

#[given("this project has a decisions file")]
fn project_has_a_decisions_file(world: &mut BehaviourWorld) {
    std::fs::write(cwd(world).join("lns-local-mixin.yaml"), "").expect("write the decisions file");
}

#[given(regex = r#"^this project connects "([^"]+)"$"#)]
fn project_connects(world: &mut BehaviourWorld, id: String) {
    let project = this_project(world);
    let store = JsonFileGrantStore::new(cwd(world).join(".lns/workload-grants.json"));
    let mut file = store.load().expect("the sidecar reads back");
    file.connect(&project, &id);
    store.save(&file).expect("seeding the sidecar");
}

#[given(regex = r#"^the workload "([^"]+)" was granted "([^"]+)"$"#)]
fn workload_granted(world: &mut BehaviourWorld, workload: String, id: String) {
    let project = this_project(world);
    seed(
        world,
        GrantRecord::allow(
            project,
            &workload_of(&workload),
            id,
            "SOME_TOKEN",
            vec!["api.some-provider.example".into()],
        ),
    );
}

#[given(regex = r#"^the workload "([^"]+)" was denied "([^"]+)"$"#)]
fn workload_denied(world: &mut BehaviourWorld, workload: String, id: String) {
    let project = this_project(world);
    seed(
        world,
        GrantRecord::deny(
            project,
            &workload_of(&workload),
            id,
            "SOME_TOKEN",
            vec!["api.some-provider.example".into()],
        ),
    );
}

#[given("the grant sidecar cannot be updated")]
fn grant_sidecar_unwritable(world: &mut BehaviourWorld) {
    let lock = cwd(world).join(".lns/workload-grants.json.lock");
    std::fs::create_dir(&lock).expect("occupy the lock path");
}

#[then("the command fails naming the path as not a project directory")]
fn fails_not_a_project_dir(world: &mut BehaviourWorld) {
    let run = world.result.as_ref().expect("a run must have happened");
    assert_eq!(run.exit_code, 1, "got: {}", run.output);
    assert!(
        run.output.contains("not a project directory"),
        "a developer reaching for the old --policy habit must be told which path is wrong, got: {}",
        run.output
    );
}

#[then("no connection is keyed by the decisions file")]
fn no_connection_keyed_by_the_decisions_file(world: &mut BehaviourWorld) {
    let file = loaded(world);
    let by_file: Vec<&str> = file
        .connected
        .iter()
        .map(|c| c.project.as_str())
        .filter(|p| p.ends_with("lns-local-mixin.yaml"))
        .collect();
    assert!(
        by_file.is_empty(),
        "keying a connection by the decisions file is the orphaned key this change exists to stop writing, got: {by_file:?}"
    );
}

#[then(regex = r#"^this project still connects "([^"]+)"$"#)]
fn project_still_connects(world: &mut BehaviourWorld, id: String) {
    let connected = JsonFileGrantStore::new(cwd(world).join(".lns/workload-grants.json"))
        .load()
        .expect("the sidecar reads back")
        .connected_in(&this_project(world));
    assert!(
        connected.contains(&id),
        "the connection and the grants under it are one write now, so a disconnect that could not land leaves {id} connected for a retry, got: {connected:?}"
    );
}

#[given(regex = r#"^the project "([^"]+)" granted "([^"]+)"$"#)]
fn other_project_granted(world: &mut BehaviourWorld, project: String, id: String) {
    seed(
        world,
        GrantRecord::allow(
            project,
            &WorkloadIdentity::definition("/work/other"),
            id,
            "SOME_TOKEN",
            vec!["api.some-provider.example".into()],
        ),
    );
}

#[then(regex = r#"^the listing shows "([^"]+)" holding "([^"]+)" for "([^"]+)"$"#)]
fn listing_shows(world: &mut BehaviourWorld, workload: String, verdict: String, id: String) {
    let out = output(world);
    let line = out
        .lines()
        .find(|l| l.starts_with(&workload))
        .unwrap_or_else(|| panic!("no listing line for {workload} in:\n{out}"));
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(
        fields,
        [workload.as_str(), id.as_str(), verdict.as_str()],
        "got line: {line}"
    );
}

#[then("the output reports no grants for this project")]
fn reports_no_grants(world: &mut BehaviourWorld) {
    let out = output(world);
    assert!(
        out.contains("No connector grants for this project"),
        "got: {out}"
    );
}

#[then(regex = r#"^the listing names the project "([^"]+)"$"#)]
fn listing_names_project(world: &mut BehaviourWorld, project: String) {
    let out = output(world);
    assert!(
        out.lines().any(|l| l.starts_with(&project)),
        "--all must carry a project column, got: {out}"
    );
}

#[then(regex = r#"^the output reports (\d+) grant forgotten$"#)]
fn reports_forgotten(world: &mut BehaviourWorld, count: usize) {
    let out = output(world);
    assert!(
        out.contains(&format!("Revoked {count} grant")),
        "got: {out}"
    );
}

#[then("the output reports the grants it forgot")]
fn reports_disconnect_forgot(world: &mut BehaviourWorld) {
    let out = output(world);
    assert!(
        out.contains("forgot 1 per-workload grant"),
        "a disconnect must say what it forgot, not silently drop it: {out}"
    );
}

#[then(regex = r#"^this project holds no grant for "([^"]+)"$"#)]
fn no_remaining_grant(world: &mut BehaviourWorld, id: String) {
    let project = this_project(world);
    let file = loaded(world);
    assert!(
        !file.for_project(&project).any(|g| g.connector == id),
        "expected no {id} grant left, got: {:?}",
        file.grants
    );
}

#[then(regex = r#"^the project "([^"]+)" still holds its grant for "([^"]+)"$"#)]
fn other_project_keeps_grant(world: &mut BehaviourWorld, project: String, id: String) {
    let file = loaded(world);
    assert!(
        file.for_project(&project).any(|g| g.connector == id),
        "revoking here must not reach another project, got: {:?}",
        file.grants
    );
}

#[then(regex = r#"^the output points at revoking the standing decline for "([^"]+)"$"#)]
fn points_at_revoking_the_decline(world: &mut BehaviourWorld, id: String) {
    let out = output(world);
    assert!(
        out.contains("declined") && out.contains(&format!("revoke {id}")),
        "binding the value cannot undo a workload's decline, so the connect that looks like it fixed things must name the command that does: {out}"
    );
}

#[then("the output says nothing about a standing decline")]
fn says_nothing_about_a_decline(world: &mut BehaviourWorld) {
    let out = output(world);
    assert!(
        !out.contains("declined"),
        "a project holding only allows has no decline to report: {out}"
    );
}

#[then("the command fails noting there is nothing to forget")]
fn fails_nothing_to_forget(world: &mut BehaviourWorld) {
    let run = world.result.as_ref().expect("a run must have happened");
    assert_ne!(run.exit_code, 0, "expected a non-zero exit");
    assert!(run.output.contains("no grants for"), "got: {}", run.output);
}
