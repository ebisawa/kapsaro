// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local state permission reporting.
//! Pins that group- or other-accessible local state is warned about, not refused.

#![cfg(unix)]

use super::{
    collect_local_state_ancestor_violations, collect_local_state_tree_violations,
    collect_open_permission_violations, inspect_entry_facts, judge_scanned_children,
    report_local_state_ancestor_safety, report_scoped_open_permission, report_violations,
    resolve_existing_parent, run_before_next_child_dir_open, EntryFacts, PermissionViolation,
    PermissionViolationKind, MAX_LOCAL_STATE_TREE_DEPTH, MAX_LOCAL_STATE_TREE_ENTRIES,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::relative::{
    open_regular_file_at, ChildName, ChildType, DirectoryFd, DirectoryScope, EntryIdentity,
    ScannedChild,
};
use crate::support::path::DisplayBase;
use crate::support::warning::{LocalStateWarningCode, LocalStateWarningGuard};
use crate::test_utils::{local_state_temp_dir, permission_denial_can_be_staged, with_temp_cwd};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_report_scoped_open_permission_accepts_owner_only_file_records_no_warning() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o700);
    write_file(&temp.path().join("secret"), 0o600);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let file = open_regular_file_at(&anchored, "secret").unwrap();

    let warnings = recorded_under(temp.path(), || {
        report_scoped_open_permission(&anchored, &file, &temp.path().join("secret"))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_report_scoped_open_permission_warns_about_group_readable_file() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o700);
    let path = temp.path().join("secret");
    write_file(&path, 0o644);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let file = open_regular_file_at(&anchored, "secret").unwrap();

    let guard = LocalStateWarningGuard::new();
    report_scoped_open_permission(&anchored, &file, &path);
    let warning = guard.take_single_reason_under(temp.path());

    assert!(warning.contains("Insecure permissions 0644"), "{warning}");
    assert!(warning.contains("expected 0600"), "{warning}");
    assert!(warning.contains("chmod 0600"), "{warning}");
}

#[test]
fn test_report_scoped_open_permission_warns_about_group_readable_directory_expects_0700() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();

    let guard = LocalStateWarningGuard::new();
    report_scoped_open_permission(&anchored, anchored.file(), anchored.path());
    let warning = guard.take_single_reason_under(temp.path());

    assert!(warning.contains("Insecure permissions 0755"), "{warning}");
    assert!(warning.contains("expected 0700"), "{warning}");
    assert!(warning.contains("chmod 0700"), "{warning}");
}

/// One command must name every permission that has to change. Reporting only
/// the first violation makes the operator fix and re-run once per level.
#[test]
fn test_report_violations_names_every_entry_of_an_open_chain() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);
    let child_path = temp.path().join("keys");
    fs::create_dir(&child_path).unwrap();
    set_mode(&child_path, 0o750);
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let child = root.open_child("keys").unwrap();

    let warnings = recorded_under(temp.path(), || {
        report_violations(collect_open_permission_violations(&[
            &root as &dyn DirectoryFd,
            &child,
        ]))
    });

    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0755"),
        "{warnings:?}"
    );
    assert!(
        warnings[1].contains("Insecure permissions 0750"),
        "{warnings:?}"
    );
}

/// The chain is reported outermost first so the operator repairs top down.
#[test]
fn test_collect_open_permission_violations_orders_from_the_outermost_entry() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);
    let child_path = temp.path().join("keys");
    fs::create_dir(&child_path).unwrap();
    set_mode(&child_path, 0o750);
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let child = root.open_child("keys").unwrap();

    let violations = collect_open_permission_violations(&[&root as &dyn DirectoryFd, &child]);

    assert_eq!(violations[0].path(), temp.path());
    assert_eq!(violations[1].path(), child_path.as_path());
    assert_eq!(violations[0].kind(), PermissionViolationKind::InsecureMode);
}

#[test]
fn test_report_violations_accepts_owner_only_entries_records_no_warning() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o700);
    let child_path = temp.path().join("keys");
    fs::create_dir(&child_path).unwrap();
    set_mode(&child_path, 0o700);
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let child = root.open_child("keys").unwrap();

    let warnings = recorded_under(temp.path(), || {
        report_violations(collect_open_permission_violations(&[
            &root as &dyn DirectoryFd,
            &child,
        ]))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

/// Workspace directories are shared through git, so their entries keep the
/// permissions the repository checkout produced.
#[test]
fn test_report_scoped_open_permission_skips_generic_scope_directories() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);
    write_file(&temp.path().join("members.json"), 0o644);

    let guard = LocalStateWarningGuard::new();
    with_locked_workspace_dir(temp.path(), |dir| {
        let file = open_regular_file_at(dir, "members.json")?;
        report_scoped_open_permission(dir, &file, &temp.path().join("members.json"));
        Ok(())
    })
    .unwrap();
    let warnings = guard.take_reasons();

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_report_scoped_open_permission_warns_about_local_state_directories() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o700);
    let path = temp.path().join("active");
    write_file(&path, 0o644);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let file = open_regular_file_at(&anchored, "active").unwrap();

    let guard = LocalStateWarningGuard::new();
    report_scoped_open_permission(&anchored, &file, &path);
    let warning = guard.take_single_reason_under(temp.path());

    assert!(warning.contains("Insecure permissions 0644"), "{warning}");
}

#[test]
fn test_collect_open_permission_violations_skips_generic_scope_entries() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);

    let violations = with_locked_workspace_dir(temp.path(), |dir| {
        Ok(collect_open_permission_violations(&[
            dir as &dyn DirectoryFd
        ]))
    })
    .unwrap();

    assert!(violations.is_empty());
}

#[test]
fn test_report_violations_accepts_an_empty_set_records_no_warning() {
    let warnings = recorded(|| report_violations(Vec::new()));

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_ancestor_safety_accepts_owner_only_ancestors_records_no_warning() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o700);

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&outer.join("home"))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

/// A shared parent stays readable and traversable. Only the write bits decide
/// whether another user can put their own tree in place of this one.
#[test]
fn test_ancestor_safety_accepts_group_readable_ancestor_records_no_warning() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o755);

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&outer.join("home"))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_ancestor_safety_warns_about_group_writable_ancestor() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o770);

    let guard = LocalStateWarningGuard::new();
    report_local_state_ancestor_safety(&outer.join("home"));
    let warning = guard.take_single_reason_under(&resolved_root(temp.path()));

    assert!(warning.contains("outer"), "{warning}");
    assert!(
        warning.contains("Insecure ancestor permissions"),
        "{warning}"
    );
}

#[test]
fn test_ancestor_safety_warns_about_other_writable_ancestor() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o707);

    let violations = collect_local_state_ancestor_violations(&outer.join("home"));

    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].kind(),
        PermissionViolationKind::InsecureAncestor
    );
}

/// A world-writable sticky directory such as `/tmp` cannot have its entries
/// renamed or deleted by a non-owner, so it is not a way in.
#[test]
fn test_ancestor_safety_accepts_world_writable_sticky_ancestor_records_no_warning() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o1777);
    assert_eq!(
        fs::metadata(&outer).unwrap().permissions().mode() & 0o7777,
        0o1777,
        "the platform must keep the sticky bit for this test to mean anything"
    );

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&outer.join("home"))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_ancestor_safety_reports_every_unsafe_ancestor_from_the_outermost() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o777);
    let inner = restricted_dir(&outer, "inner", 0o775);

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&inner.join("home"))
    });

    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("outer"), "{warnings:?}");
    assert!(warnings[1].contains("inner"), "{warnings:?}");
}

/// The repair has to name the directory the link resolves to, because that is
/// the one whose mode lets another user take over the path.
#[test]
fn test_ancestor_safety_names_the_resolved_directory_behind_a_symlink() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let real = restricted_dir(temp.path(), "real", 0o777);
    let alias = temp.path().join("alias");
    symlink(&real, &alias).unwrap();

    let guard = LocalStateWarningGuard::new();
    report_local_state_ancestor_safety(&alias.join("home"));
    let warning = guard.take_single_reason_under(&resolved_root(temp.path()));

    assert!(warning.contains("real"), "{warning}");
    assert!(!warning.contains("alias"), "{warning}");
}

/// Pointing the local state root at another volume through a symlink is a
/// supported layout, so the chain that has to be safe is the one leading to the
/// directory the link resolves to, not the one holding the link.
#[test]
fn test_ancestor_safety_names_the_resolved_parent_of_a_symlinked_root() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let shared = restricted_dir(temp.path(), "shared", 0o777);
    let real_home = restricted_dir(&shared, "real-home", 0o700);
    let safe = restricted_dir(temp.path(), "safe", 0o700);
    let selected = safe.join("home");
    symlink(&real_home, &selected).unwrap();

    let guard = LocalStateWarningGuard::new();
    report_local_state_ancestor_safety(&selected);
    let warning = guard.take_single_reason_under(&resolved_root(temp.path()));

    assert!(warning.contains("shared"), "{warning}");
}

/// Replacing the link is as good as replacing what it points at, so the chain
/// holding a symlinked root has to be safe too.
#[test]
fn test_ancestor_safety_names_the_directory_holding_a_symlinked_root() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let shared = restricted_dir(temp.path(), "shared", 0o700);
    let real_home = restricted_dir(&shared, "real-home", 0o700);
    let loose = restricted_dir(temp.path(), "loose", 0o777);
    let selected = loose.join("home");
    symlink(&real_home, &selected).unwrap();

    let guard = LocalStateWarningGuard::new();
    report_local_state_ancestor_safety(&selected);
    let warning = guard.take_single_reason_under(&resolved_root(temp.path()));

    assert!(warning.contains("loose"), "{warning}");
}

/// A symlinked root is reached through two chains, and each is walked from its
/// outermost directory inwards so the operator repairs one chain top down before
/// starting on the next. The chain holding the link comes first, because that is
/// the one the selected path is spelled with.
#[test]
fn test_ancestor_safety_walks_each_chain_of_a_symlinked_root_outermost_first() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let loose = restricted_dir(temp.path(), "loose", 0o777);
    let holder = restricted_dir(&loose, "holder", 0o775);
    let shared = restricted_dir(temp.path(), "shared", 0o777);
    let target_parent = restricted_dir(&shared, "target-parent", 0o775);
    let real_home = restricted_dir(&target_parent, "real-home", 0o700);
    let selected = holder.join("home");
    symlink(&real_home, &selected).unwrap();

    let violations = collect_local_state_ancestor_violations(&selected);

    assert_eq!(
        violation_names(&violations),
        vec!["loose", "holder", "shared", "target-parent"],
        "{violations:?}"
    );
}

/// The final component of each path a set of findings names, in the order the
/// findings arrived.
fn violation_names(violations: &[PermissionViolation]) -> Vec<String> {
    violations
        .iter()
        .map(|violation| {
            violation
                .path()
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// The root itself is covered by the owner-only rule, so the ancestor walk
/// leaves it alone and the two never report the same directory twice.
#[test]
fn test_ancestor_safety_leaves_the_local_state_root_to_the_owner_only_rule() {
    let temp = local_state_temp_dir();
    let home = restricted_dir(temp.path(), "home", 0o777);

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&home)
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

/// How long a walk that has to end on its own is given to end.
const BOUNDED_WALK_TIMEOUT: Duration = Duration::from_secs(5);

/// Run a call that must end on its own, failing the test when it does not.
///
/// A walk that never ends would otherwise take the whole test binary down with
/// it instead of reporting anything, so the answer is awaited from another
/// thread and its absence is what fails.
fn answer_within<T, F>(timeout: Duration, call: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (answer_tx, answer_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer_tx.send(call());
    });
    answer_rx
        .recv_timeout(timeout)
        .expect("the ancestor walk must end on its own")
}

/// A relative path is walked up from the working directory it is spelled
/// against, so the deepest directory that exists is the working directory
/// itself once none of the named components are there.
#[test]
fn test_resolve_existing_parent_reaches_the_working_directory_of_a_relative_path() {
    let temp = local_state_temp_dir();

    let (resolved, expected) = with_temp_cwd(temp.path(), || {
        let resolved = resolve_existing_parent(Path::new("missing/keys"))
            .expect("a relative ancestry resolves without failing");
        (resolved, std::env::current_dir().unwrap())
    });

    assert_eq!(resolved, Some(expected));
}

/// The walk climbs the components of the path it was given, so it ends whether
/// or not anything on the way resolves.
///
/// `Path::parent` answers a relative path's last component with an empty path,
/// the directory an empty path stands for is the working directory, and
/// `parent` answers that with an empty path again. A process whose working
/// directory has been removed resolves neither, so a walk that asked `parent`
/// for its next step would ask about those two forever.
#[test]
fn test_resolve_existing_parent_ends_when_nothing_on_the_way_resolves() {
    let temp = TempDir::new().unwrap();
    let removed = temp.path().join("removed");
    fs::create_dir(&removed).unwrap();

    let resolved: std::io::Result<Option<PathBuf>> = with_temp_cwd(&removed, || {
        fs::remove_dir(&removed).unwrap();
        answer_within(BOUNDED_WALK_TIMEOUT, || {
            resolve_existing_parent(Path::new("missing/keys"))
        })
    });

    assert!(
        matches!(resolved, Ok(None)),
        "an ancestry where nothing resolves names no base: {resolved:?}"
    );
}

/// A local state root is created on first use, so a path that does not exist
/// yet is walked from the deepest directory that does.
#[test]
fn test_ancestor_safety_accepts_a_local_state_root_that_does_not_exist_yet() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o700);

    let warnings = recorded_under(&resolved_root(temp.path()), || {
        report_local_state_ancestor_safety(&outer.join("missing").join("keys"))
    });

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn test_ancestor_safety_repair_hint_removes_only_the_write_bits() {
    let temp = local_state_temp_dir();
    let outer = restricted_dir(temp.path(), "outer", 0o777);

    let guard = LocalStateWarningGuard::new();
    report_local_state_ancestor_safety(&outer.join("home"));
    let warning = guard.take_single_reason_under(&resolved_root(temp.path()));

    assert!(warning.contains("chmod go-w"), "{warning}");
    assert!(warning.contains("KAPSARO_HOME"), "{warning}");
}

/// The walk starts at the opened root, so every level below it is inspected
/// without the caller naming the entries one by one.
#[test]
fn test_local_state_tree_violations_reach_every_level_below_the_root() {
    let temp = local_state_temp_dir();
    let member = restricted_dir(&restricted_dir(temp.path(), "keys", 0o700), "alice", 0o750);
    let key_dir = restricted_dir(&member, "kid", 0o700);
    let private_key = key_dir.join("private.json");
    write_file(&private_key, 0o644);
    write_file(&temp.path().join("config.toml"), 0o600);
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&root);

    let paths = violations
        .iter()
        .map(|violation| violation.path().to_path_buf())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2, "{violations:?}");
    assert!(paths.contains(&member), "{paths:?}");
    assert!(paths.contains(&private_key), "{paths:?}");
}

/// An entry the walk cannot open is reported rather than passed over, so an
/// unreadable directory never counts as an owner-only one.
#[test]
fn test_local_state_tree_violations_report_an_unreadable_directory() {
    let temp = local_state_temp_dir();
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();
    let closed = restricted_dir(temp.path(), "closed", 0o000);

    let violations = collect_local_state_tree_violations(&root);

    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].path(), closed);
    assert_eq!(violations[0].kind(), PermissionViolationKind::Unreadable);
}

/// A walk that runs out of entry budget leaves part of the tree uninspected,
/// and the entries it never read are exactly the ones it cannot vouch for.
#[test]
fn test_local_state_tree_violations_report_a_walk_stopped_by_the_entry_budget() {
    let temp = local_state_temp_dir();
    for index in 0..=MAX_LOCAL_STATE_TREE_ENTRIES {
        write_file(&temp.path().join(format!("entry-{index}")), 0o600);
    }
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&root);

    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].kind(),
        PermissionViolationKind::IncompleteScan
    );
    assert!(
        violations[0].message().contains("more than 1024 entries"),
        "{}",
        violations[0].message()
    );
}

/// The same holds for a tree deeper than the walk descends: the levels below
/// the bound are unread, so the walk says so instead of passing for complete.
#[test]
fn test_local_state_tree_violations_report_a_walk_stopped_by_the_depth_bound() {
    let temp = local_state_temp_dir();
    let mut nested = temp.path().to_path_buf();
    for level in 0..=MAX_LOCAL_STATE_TREE_DEPTH {
        nested = restricted_dir(&nested, &format!("level-{level}"), 0o700);
    }
    let root =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&root);

    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].kind(),
        PermissionViolationKind::IncompleteScan
    );
    assert_eq!(violations[0].path(), temp.path());
    assert!(
        violations[0].message().contains("more than 6 levels"),
        "{}",
        violations[0].message()
    );
}

/// A reported violation reaches the sink as its parts, so a caller that is not
/// a terminal can act on the entry the finding names.
#[test]
fn test_report_violations_records_the_path_beside_the_reason() {
    let guard = LocalStateWarningGuard::new();

    report_violations(vec![PermissionViolation::new(
        Path::new("local-state/config.toml"),
        PermissionViolationKind::InsecureMode,
        "Insecure permissions 0644".to_string(),
    )]);
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), 1);
    assert_eq!(batch.warnings[0].code(), LocalStateWarningCode::Permissions);
    assert_eq!(
        batch.warnings[0].path(),
        Path::new("local-state/config.toml")
    );
    assert_eq!(batch.warnings[0].reason(), "Insecure permissions 0644");
}

/// Run an action with an isolated warning sink and return what it recorded.
///
/// For an action that judges violations handed to it directly: nothing is read
/// off a filesystem, so every warning belongs to the case the test built.
fn recorded(action: impl FnOnce()) -> Vec<String> {
    let guard = LocalStateWarningGuard::new();
    action();
    guard.take_reasons()
}

/// Run an action that walks the filesystem and return what it recorded below
/// `root`.
///
/// The directories above a temporary root belong to whoever built the machine,
/// and one of them being group-writable is a finding like any other, so the
/// reading is confined to the tree the test staged.
fn recorded_under(root: &Path, action: impl FnOnce()) -> Vec<String> {
    let guard = LocalStateWarningGuard::new();
    action();
    guard.take_reasons_under(root)
}

/// The temporary root as an ancestor walk names it.
///
/// The walk resolves each chain before it inspects anything, so its findings
/// name the directory a temporary root resolves to rather than the path the
/// test was handed.
fn resolved_root(root: &Path) -> std::path::PathBuf {
    fs::canonicalize(root).unwrap()
}

/// Create a directory with an exact mode.
///
/// `create_dir` applies the process umask, so the mode is set afterwards to
/// keep these tests independent of the developer's umask.
fn restricted_dir(parent: &Path, name: &str, mode: u32) -> std::path::PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    set_mode(&path, mode);
    path
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_file(path: &Path, mode: u32) {
    fs::write(path, "content").unwrap();
    set_mode(path, mode);
}

/// A finding must not hand the operator a command it did not mean to write.
///
/// An entry name is chosen by whoever can write the directory, and a single
/// quote inside it closes the quoting the repair command relies on. Everything
/// after that point would run as its own command once the line is pasted.
#[test]
fn test_insecure_mode_finding_quotes_a_name_holding_a_single_quote() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();
    write_file(&temp.path().join("evil'; touch pwned; x"), 0o644);

    let violations = collect_local_state_tree_violations(&anchored);
    let message = single_violation_message(&violations);
    let argument = repair_argument(message);

    assert_eq!(
        shell_words(&argument),
        vec![temp
            .path()
            .join("evil'; touch pwned; x")
            .display()
            .to_string()],
        "the name must reach the shell as one word naming the entry: {message}"
    );
}

/// The quoted path a repair command hands to the shell.
fn repair_argument(message: &str) -> String {
    let repair = message
        .split("run: ")
        .nth(1)
        .unwrap_or_else(|| panic!("the finding must carry a repair command: {message}"));
    repair
        .split_once(" -- ")
        .unwrap_or_else(|| panic!("the repair must separate its options: {repair}"))
        .1
        .to_string()
}

/// What a POSIX shell makes of one quoted fragment.
///
/// Asking the shell itself is the only way to show that a name chosen by
/// somebody else stays a single argument instead of becoming further commands.
fn shell_words(argument: &str) -> Vec<String> {
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "for word in {argument}; do printf '%s\\0' \"$word\"; done"
        ))
        .output()
        .expect("run the quoted fragment through a shell");

    assert!(output.status.success(), "{output:?}");
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8(word.to_vec()).unwrap())
        .collect()
}

/// The repair names the entry from anywhere, not just the directory it ran in.
#[test]
fn test_insecure_mode_finding_names_an_absolute_path_in_the_repair_command() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();
    write_file(&temp.path().join("loose"), 0o644);

    let violations = collect_local_state_tree_violations(&anchored);
    let message = single_violation_message(&violations);
    let repair = message
        .split("run: ")
        .nth(1)
        .unwrap_or_else(|| panic!("the finding must carry a repair command: {message}"));

    assert!(
        repair.contains(&format!("'{}", temp.path().display())),
        "the repair must name an absolute path: {repair}"
    );
}

fn single_violation_message(violations: &[PermissionViolation]) -> &str {
    assert_eq!(violations.len(), 1, "{violations:?}");
    violations[0].message()
}

/// One entry the walk cannot decode must not hide the entries beside it.
///
/// A name kapsaro did not write is exactly what somebody else may have placed
/// there, and stopping at it would leave the rest of the directory uninspected.
#[test]
fn test_walk_reports_an_undecodable_name_and_still_judges_the_entry_beside_it() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let (violations, _) = judge_scanned_children(
        &anchored,
        vec![
            inspected_child(b"bad\xff", ChildType::RegularFile, 0o600),
            inspected_child(b"loose", ChildType::RegularFile, 0o644),
        ],
    );

    assert_eq!(
        violation_kinds(&violations),
        vec![
            PermissionViolationKind::UndecodableName,
            PermissionViolationKind::InsecureMode
        ],
        "{violations:?}"
    );
}

/// An entry the scan could not read is a finding of its own, and the entries
/// beside it are judged all the same: the ones a scan never reaches are exactly
/// the ones somebody else may have placed there.
#[test]
fn test_walk_reports_an_unreadable_entry_and_still_judges_the_entry_beside_it() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let (violations, _) = judge_scanned_children(
        &anchored,
        vec![
            ScannedChild::Unreadable {
                name: ChildName::from_raw_bytes(b"denied"),
                error: kapsaro_core::Error::build_io_error("Failed to inspect entry".to_string()),
            },
            inspected_child(b"loose", ChildType::RegularFile, 0o644),
        ],
    );

    assert_eq!(
        violation_kinds(&violations),
        vec![
            PermissionViolationKind::Unreadable,
            PermissionViolationKind::InsecureMode
        ],
        "{violations:?}"
    );
}

/// The most dangerous mode is the one the owner cannot open.
#[test]
fn test_local_state_tree_violations_report_a_file_the_owner_cannot_open() {
    if !permission_denial_can_be_staged(
        "test_local_state_tree_violations_report_a_file_the_owner_cannot_open",
    ) {
        return;
    }

    let temp = local_state_temp_dir();
    write_file(&temp.path().join("exposed"), 0o006);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&anchored);

    assert_eq!(
        violation_kinds(&violations),
        vec![PermissionViolationKind::InsecureMode],
        "{violations:?}"
    );
    assert!(
        violations[0]
            .message()
            .contains("Insecure permissions 0006"),
        "{:?}",
        violations[0].message()
    );
}

/// A file nobody can read is owner-only, whatever opening it would say.
#[test]
fn test_local_state_tree_violations_accept_a_file_with_no_permission_bits() {
    if !permission_denial_can_be_staged(
        "test_local_state_tree_violations_accept_a_file_with_no_permission_bits",
    ) {
        return;
    }

    let temp = local_state_temp_dir();
    write_file(&temp.path().join("sealed"), 0o000);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&anchored);

    assert!(violations.is_empty(), "{violations:?}");
}

/// A directory kapsaro cannot name still holds entries worth inspecting, so the
/// walk names it as one to go below rather than stopping at the name.
#[test]
fn test_walk_descends_into_a_directory_whose_name_is_not_utf8() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let (violations, descendable) = judge_scanned_children(
        &anchored,
        vec![inspected_child(b"dir\xff", ChildType::Directory, 0o700)],
    );

    assert_eq!(
        violation_kinds(&violations),
        vec![PermissionViolationKind::UndecodableName],
        "{violations:?}"
    );
    assert_eq!(
        descendable.len(),
        1,
        "the walk must still go below a name it cannot decode"
    );
}

/// Build one scan result the way the walk would have received it.
///
/// The owner is the account running the test, so the mode is what the entry is
/// judged on; a foreign owner is covered by the pure `inspect_entry_facts`
/// cases, which can name two distinct uids.
fn inspected_child(name: &[u8], child_type: ChildType, mode: u32) -> ScannedChild {
    ScannedChild::Inspected {
        name: ChildName::from_raw_bytes(name),
        child_type,
        mode,
        owner: rustix::process::geteuid().as_raw(),
        identity: EntryIdentity::from_parts(1, 1),
    }
}

/// Build one scan result for an entry a different account owns.
///
/// No test can create a file owned elsewhere, so the scan result the walk would
/// have received is handed over with an owner that is not the running account.
fn foreign_owned_child(name: &[u8], child_type: ChildType, mode: u32) -> ScannedChild {
    ScannedChild::Inspected {
        name: ChildName::from_raw_bytes(name),
        child_type,
        mode,
        owner: rustix::process::geteuid().as_raw() ^ 1,
        identity: EntryIdentity::from_parts(1, 1),
    }
}

/// A symlink and a special file carry no mode worth judging, but they do carry
/// an owner: an entry a third account placed in local state is theirs to
/// repoint whenever they like, and that is the finding the report has to carry.
#[test]
fn test_walk_reports_the_owner_of_an_entry_type_kapsaro_never_writes() {
    let temp = local_state_temp_dir();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let (violations, _) = judge_scanned_children(
        &anchored,
        vec![
            foreign_owned_child(b"link", ChildType::Symlink, 0o777),
            foreign_owned_child(b"pipe", ChildType::Other, 0o600),
        ],
    );

    assert_eq!(
        violation_kinds(&violations),
        vec![
            PermissionViolationKind::UnexpectedEntryType,
            PermissionViolationKind::ForeignOwner,
            PermissionViolationKind::UnexpectedEntryType,
            PermissionViolationKind::ForeignOwner,
        ],
        "{violations:?}"
    );
}

/// Judge one entry's own facts the way a walk judges them.
///
/// A walk reads the working directory once and names every finding against it,
/// so a single judgement is asked for against a directory read the same way.
fn judge_entry(
    facts: EntryFacts,
    effective_uid: u32,
    display_path: &Path,
) -> Option<PermissionViolation> {
    inspect_entry_facts(&DisplayBase::resolve(), facts, effective_uid, display_path)
}

#[test]
fn test_entry_facts_report_an_entry_a_different_user_owns() {
    let violation = judge_entry(
        EntryFacts::new(1234, 0o600, false),
        1000,
        Path::new("/local/state/secret"),
    )
    .expect("an entry owned elsewhere is a finding");

    assert_eq!(violation.kind(), PermissionViolationKind::ForeignOwner);
    assert!(violation.message().contains("uid 1234"), "{violation:?}");
}

/// The owner decides the verdict before the mode does: an owner who is somebody
/// else can put the mode back however they like.
#[test]
fn test_entry_facts_report_a_foreign_owner_even_when_the_mode_is_owner_only() {
    let violation = judge_entry(
        EntryFacts::new(1234, 0o700, true),
        1000,
        Path::new("/local/state/keys"),
    )
    .expect("an owner-only mode does not settle a foreign owner");

    assert_eq!(violation.kind(), PermissionViolationKind::ForeignOwner);
}

#[test]
fn test_entry_facts_accept_an_owner_only_file() {
    assert!(judge_entry(EntryFacts::new(1000, 0o600, false), 1000, Path::new("/x")).is_none());
}

#[test]
fn test_entry_facts_report_a_group_readable_directory_against_0700() {
    let violation = judge_entry(
        EntryFacts::new(1000, 0o750, true),
        1000,
        Path::new("/local/state/keys"),
    )
    .expect("a directory group can read is a finding");

    assert_eq!(violation.kind(), PermissionViolationKind::InsecureMode);
    assert!(
        violation.message().contains("expected 0700"),
        "{violation:?}"
    );
}

#[test]
fn test_entry_facts_report_a_mode_the_owner_cannot_open() {
    let violation = judge_entry(
        EntryFacts::new(1000, 0o006, false),
        1000,
        Path::new("/local/state/secret"),
    )
    .expect("a mode only others can use is a finding");

    assert_eq!(violation.kind(), PermissionViolationKind::InsecureMode);
}

#[test]
fn test_entry_facts_accept_a_file_with_no_permission_bits() {
    assert!(judge_entry(EntryFacts::new(1000, 0o000, false), 1000, Path::new("/x")).is_none());
}

fn violation_kinds(violations: &[PermissionViolation]) -> Vec<PermissionViolationKind> {
    violations.iter().map(PermissionViolation::kind).collect()
}

/// Every finding names a path whose entry name was chosen by whoever can write
/// the directory. A newline in one would forge a second warning line, so each
/// message that names a path goes through the escaping form.
#[test]
fn test_findings_that_name_a_path_escape_control_characters() {
    let hostile = Path::new("/local/state/first\nSecond forged line");

    let foreign_owner = judge_entry(EntryFacts::new(1234, 0o600, false), 1000, hostile)
        .expect("an entry owned elsewhere is a finding");
    assert!(
        !foreign_owner.message().contains('\n'),
        "{}",
        foreign_owner.message()
    );

    let insecure_mode = judge_entry(EntryFacts::new(1000, 0o644, false), 1000, hostile)
        .expect("a group-readable entry is a finding");
    assert!(
        !insecure_mode.message().contains('\n'),
        "{}",
        insecure_mode.message()
    );
}

/// A directory that cannot be read at all is a finding whose message names the
/// entry, and that name is escaped like every other.
#[test]
fn test_unreadable_finding_escapes_the_entry_name() {
    if !permission_denial_can_be_staged("test_unreadable_finding_escapes_the_entry_name") {
        return;
    }

    let temp = local_state_temp_dir();
    let closed = temp.path().join("closed\nforged");
    fs::create_dir(&closed).expect("filesystem must accept a directory name with a newline");
    set_mode(&closed, 0o000);
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&anchored);

    let message = single_violation_message(&violations);
    assert!(!message.contains('\n'), "{message}");
}

/// A symlink carries no permissions of its own and a FIFO carries nothing
/// kapsaro can use, so neither is judged on its mode. Passing over them in
/// silence would leave the one kind of foreign entry that produces no finding.
#[cfg(unix)]
#[test]
fn test_local_state_tree_violations_report_an_entry_type_kapsaro_never_writes() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    write_file(&temp.path().join("target"), 0o600);
    symlink(temp.path().join("target"), temp.path().join("link")).unwrap();
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&anchored);

    assert_eq!(
        violation_kinds(&violations),
        vec![PermissionViolationKind::UnexpectedEntryType],
        "{violations:?}"
    );
    assert!(
        violations[0].message().contains("symlink"),
        "{}",
        violations[0].message()
    );
}

#[cfg(unix)]
#[test]
fn test_local_state_tree_violations_report_a_special_file() {
    let temp = local_state_temp_dir();
    create_fifo(&temp.path().join("pipe"));
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let violations = collect_local_state_tree_violations(&anchored);

    assert_eq!(
        violation_kinds(&violations),
        vec![PermissionViolationKind::UnexpectedEntryType],
        "{violations:?}"
    );
    assert!(
        violations[0].message().contains("special file"),
        "{}",
        violations[0].message()
    );
}

#[cfg(unix)]
fn create_fifo(path: &Path) {
    use std::ffi::CString;

    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    // mkfifo has no safe wrapper. The path is a valid CString inside a
    // temporary directory this test owns.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
}

/// The scan and the open are two lookups of one name. When the entry changes in
/// between, the mode just recorded belongs to an inode the walk never opened,
/// so the walk says so rather than letting the verdict stand for what is there.
#[cfg(unix)]
#[test]
fn test_local_state_tree_violations_report_a_directory_replaced_during_the_walk() {
    let temp = local_state_temp_dir();
    let member = restricted_dir(temp.path(), "keys", 0o700);
    let moved = temp.path().join("keys.moved");
    let anchored =
        AnchoredDir::open(temp.path(), DirectoryScope::LocalState, "local state root").unwrap();

    let replacement = {
        let member = member.clone();
        let moved = moved.clone();
        move || {
            fs::rename(&member, &moved).unwrap();
            fs::create_dir(&member).unwrap();
            fs::set_permissions(&member, fs::Permissions::from_mode(0o700)).unwrap();
        }
    };
    run_before_next_child_dir_open(replacement);

    let violations = collect_local_state_tree_violations(&anchored);

    assert!(
        violation_kinds(&violations).contains(&PermissionViolationKind::ReplacedEntry),
        "{violations:?}"
    );
}
