use super::detect_workspace_path_excluding;
use super::{WorkspaceAccess, WorkspaceCreationTarget, WorkspaceKind, WorkspaceWriteDirectories};
use crate::io::workspace::setup::{ensure_workspace_structure_at, inspect_workspace_structure_at};
use crate::support::fs::relative::{save_text_at, DirectoryFd};
use crate::support::fs::test_umask::{isolated_umask_test, with_umask};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

isolated_umask_test! {
    #[cfg(unix)]
    fn regular_workspace_creation_preserves_umask_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let created = temp.path().join("shared");
        with_umask(0o022, || {
            let workspace = WorkspaceCreationTarget::open(&created, WorkspaceKind::Regular).unwrap().ensure().unwrap();
            ensure_workspace_structure_at(workspace.directory()).unwrap();
        });
        for path in [&created, &created.join("members"), &created.join("members/active"), &created.join("secrets")] {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o755);
        }
    }
}

#[cfg(unix)]
#[test]
fn workspace_creation_follows_and_retains_an_explicit_root_link() {
    let temp_dir = tempfile::tempdir().unwrap();
    let outside_dir = temp_dir.path().join("outside");
    let workspace_path = temp_dir.path().join(".kapsaro");
    fs::create_dir(&outside_dir).unwrap();
    symlink(&outside_dir, &workspace_path).unwrap();
    let target = WorkspaceCreationTarget::open(&workspace_path, WorkspaceKind::Regular).unwrap();
    fs::remove_file(&workspace_path).unwrap();
    fs::create_dir(&workspace_path).unwrap();
    let workspace = target.ensure().unwrap();
    assert!(ensure_workspace_structure_at(workspace.directory()).unwrap());
    assert!(outside_dir.join("members/active/.gitkeep").exists());
    assert_eq!(fs::read_dir(&workspace_path).unwrap().count(), 0);
}

#[test]
fn regular_workspace_accepts_read_layout_and_initialization_completes_incoming() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("members/active")).unwrap();
    fs::create_dir(temp.path().join("secrets")).unwrap();
    let access = WorkspaceAccess::open(temp.path(), WorkspaceKind::Regular).unwrap();
    access.validate().unwrap();
    assert!(ensure_workspace_structure_at(access.directory()).unwrap());
    assert!(temp.path().join("members/incoming").is_dir());
    assert!(!ensure_workspace_structure_at(access.directory()).unwrap());
}

#[test]
fn global_read_reports_root_and_intermediate_permissions_without_home_warning() {
    use crate::service::diagnostics::{take_local_state_warnings, DiagnosticCode};
    use crate::support::fs::relative::load_text_with_limit_at;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".kapsaro");
    fs::create_dir_all(root.join("members/active")).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("members"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        root.join("members/active"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(root.join("members/active/key.json"), "public key").unwrap();
    fs::set_permissions(
        root.join("members/active/key.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    take_local_state_warnings();
    let access = WorkspaceAccess::open(&root, WorkspaceKind::Global).unwrap();
    let active = access
        .directory()
        .open_child("members")
        .unwrap()
        .open_child("active")
        .unwrap();
    assert_eq!(
        load_text_with_limit_at(&active, "key.json", 100, "test key").unwrap(),
        "public key"
    );
    let batch = take_local_state_warnings();
    assert_eq!(batch.diagnostics().len(), 2);
    assert!(batch
        .diagnostics()
        .iter()
        .all(|finding| finding.code() == DiagnosticCode::GlobalWorkspacePermissions));
    assert!(batch
        .diagnostics()
        .iter()
        .any(|finding| finding.path() == root));
    assert!(batch
        .diagnostics()
        .iter()
        .any(|finding| finding.path() == root.join("members/active")));
}

#[test]
fn global_creation_retains_ancestor_and_restricts_files() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let target =
        WorkspaceCreationTarget::open(home.join(".kapsaro"), WorkspaceKind::Global).unwrap();
    fs::rename(&home, temp.path().join("original")).unwrap();
    fs::create_dir(&home).unwrap();
    let access = target.ensure().unwrap();
    let secrets = access.directory().ensure_child("secrets").unwrap();
    save_text_at(&secrets, "default.kvenc", "ciphertext").unwrap();
    assert_eq!(
        secrets.file().metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
    let original = temp.path().join("original/.kapsaro/secrets/default.kvenc");
    assert_eq!(
        fs::metadata(original).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::read_dir(home).unwrap().next().is_none());
}

#[test]
fn workspace_alias_and_cloned_writes_retain_directory_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    fs::create_dir_all(root.join("secrets")).unwrap();
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    let access = WorkspaceAccess::open(&root, WorkspaceKind::Global).unwrap();
    let other = WorkspaceAccess::open(alias, WorkspaceKind::Global).unwrap();
    assert!(access.same_directory(&other).unwrap());
    fs::rename(&root, temp.path().join("original")).unwrap();
    fs::create_dir_all(root.join("secrets")).unwrap();
    let write = WorkspaceWriteDirectories::open(&access.clone()).unwrap();
    save_text_at(write.secrets.as_ref(), "test", "fixed").unwrap();
    assert_eq!(
        fs::read_to_string(temp.path().join("original/secrets/test")).unwrap(),
        "fixed"
    );
}

#[test]
fn missing_targets_compare_aliased_ancestors_without_creating() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let alias = temp.path().join("alias");
    symlink(&home, &alias).unwrap();
    let global =
        WorkspaceCreationTarget::open(home.join(".kapsaro"), WorkspaceKind::Global).unwrap();
    let explicit =
        WorkspaceCreationTarget::open(alias.join(".kapsaro"), WorkspaceKind::Regular).unwrap();
    assert!(global.same_target(&explicit).unwrap());
    assert!(global.existing_access().is_none());
    assert_eq!(fs::read_dir(home).unwrap().count(), 0);
}

#[test]
fn detection_selects_repository_workspace_after_excluding_global_alias() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join(".git")).unwrap();
    let root = WorkspaceCreationTarget::open(temp.path().join(".kapsaro"), WorkspaceKind::Regular)
        .unwrap()
        .ensure()
        .unwrap();
    ensure_workspace_structure_at(root.directory()).unwrap();
    let nested = temp.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let global =
        WorkspaceCreationTarget::open(nested.join(".kapsaro"), WorkspaceKind::Global).unwrap();
    let access = global.ensure().unwrap();
    ensure_workspace_structure_at(access.directory()).unwrap();
    let global = WorkspaceCreationTarget::open(global.path(), WorkspaceKind::Global).unwrap();
    assert_eq!(
        detect_workspace_path_excluding(&nested, &global).unwrap(),
        root.path().canonicalize().unwrap()
    );
}

#[test]
fn structure_validation_retains_invalid_entries_before_creating_missing_directories() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("secrets"), "preserved").unwrap();
    let root = WorkspaceAccess::open(temp.path(), WorkspaceKind::Global).unwrap();
    assert!(inspect_workspace_structure_at(root.directory()).is_err());
    assert!(ensure_workspace_structure_at(root.directory()).is_err());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(temp.path().join("secrets")).unwrap(),
        "preserved"
    );
}
