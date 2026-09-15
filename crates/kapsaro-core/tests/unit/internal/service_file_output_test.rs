use super::FileOutputTarget;
use crate::service::workspace::{WorkspaceCreationTarget, WorkspaceKind};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn test_output_retains_explicit_link_ancestor_for_missing_parent() {
    for change in ["unchanged", "rename", "retarget"] {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let outside = temp.path().join("outside");
        let alias = temp.path().join("link");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&original, &alias).unwrap();
        let output = FileOutputTarget::open(alias.join("new/output"), None).unwrap();
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
        let retained = match change {
            "rename" => {
                let retained = temp.path().join("retained");
                fs::rename(&original, &retained).unwrap();
                fs::create_dir(&original).unwrap();
                retained
            }
            "retarget" => {
                fs::remove_file(&alias).unwrap();
                symlink(&outside, &alias).unwrap();
                original.clone()
            }
            _ => original.clone(),
        };
        output.save(b"ciphertext", false).unwrap();
        assert_eq!(
            fs::read(retained.join("new/output")).unwrap(),
            b"ciphertext"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        if change == "rename" {
            assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
        }
    }
}

#[test]
fn test_output_missing_parent_with_inserted_symlink_error() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("output"), b"original").unwrap();
    let output = FileOutputTarget::open(temp.path().join("new/output"), None).unwrap();
    symlink(&outside, temp.path().join("new")).unwrap();

    let error = output.save(b"ciphertext", false).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(fs::read(outside.join("output")).unwrap(), b"original");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
}

#[test]
fn output_retains_global_parent_after_path_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("global");
    fs::create_dir_all(root.join("secrets")).unwrap();
    let global = WorkspaceCreationTarget::open(&root, WorkspaceKind::Global).unwrap();
    let output = FileOutputTarget::open(root.join("secrets/test"), Some(&global)).unwrap();
    fs::rename(&root, temp.path().join("retained")).unwrap();
    fs::create_dir_all(root.join("secrets")).unwrap();
    output.save(b"ciphertext", false).unwrap();
    let saved = temp.path().join("retained/secrets/test");
    assert_eq!(fs::read(&saved).unwrap(), b"ciphertext");
    assert_eq!(
        fs::metadata(saved).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(root.join("secrets")).unwrap().count(), 0);
}

#[test]
fn output_creates_missing_global_parents_with_owner_only_modes() {
    let temp = tempfile::tempdir().unwrap();
    let global = WorkspaceCreationTarget::open(temp.path(), WorkspaceKind::Global).unwrap();
    let output =
        FileOutputTarget::open(temp.path().join("new/nested/output"), Some(&global)).unwrap();
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    output.save(b"ciphertext", false).unwrap();
    assert_eq!(
        fs::metadata(temp.path().join("new/nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(output.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn output_under_missing_global_root_retains_global_creation_policy() {
    let temp = tempfile::tempdir().unwrap();
    let global =
        WorkspaceCreationTarget::open(temp.path().join(".kapsaro"), WorkspaceKind::Global).unwrap();
    let output = FileOutputTarget::open(global.path().join("new/output"), Some(&global)).unwrap();
    output.save(b"ciphertext", false).unwrap();
    for directory in [global.path().to_path_buf(), global.path().join("new")] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(output.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
