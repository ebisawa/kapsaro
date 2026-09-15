use super::FileInputTarget;
use crate::service::diagnostics::{take_local_state_warnings, DiagnosticCode};
use crate::service::workspace::{WorkspaceCreationTarget, WorkspaceKind};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn file_input_enforces_read_limit_and_reports_utf8_errors_without_content() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input");
    fs::write(&path, b"private-value\xff").unwrap();
    let input = FileInputTarget::open(&path, None).unwrap();
    let error = input.load_text(4, "input").unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert!(error.to_string().contains("maximum size limit (4 bytes)"));
    let error = input.load_text(64, "input").unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert!(!format!("{error:?}").contains("private-value"));
    fs::write(&path, b"updated").unwrap();
    assert_eq!(input.load_text(64, "input").unwrap(), "updated");
}

#[test]
fn global_file_input_reports_file_permissions_and_retains_selected_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("global");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("input");
    fs::write(&path, "selected").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let global = WorkspaceCreationTarget::open(&root, WorkspaceKind::Global).unwrap();
    take_local_state_warnings();
    let input = FileInputTarget::open(&path, Some(&global)).unwrap();
    fs::rename(&path, root.join("retained")).unwrap();
    fs::write(&path, "replacement").unwrap();
    assert_eq!(input.load_plaintext().unwrap(), b"selected");
    assert_eq!(
        crate::service::kv::load_import_text(&input).unwrap(),
        "selected"
    );
    let warnings = take_local_state_warnings();
    assert_eq!(warnings.diagnostics().len(), 1);
    assert_eq!(warnings.diagnostics()[0].path(), path);
    assert_eq!(
        warnings.diagnostics()[0].code(),
        DiagnosticCode::GlobalWorkspacePermissions
    );
}
