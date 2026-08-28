// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use tempfile::{tempdir, TempDir};

use super::{
    is_encrypted_artifact_name, list_workspace_encrypted_artifacts_at, load_reviewed_artifact,
    ArtifactRef, WorkspaceArtifactListing,
};
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope, OpenDir};

/// The listing is addressed to a workspace descriptor, so a test binds the
/// workspace root the way a command does before asking what it holds.
fn open_workspace(temp_dir: &TempDir) -> OpenDir {
    open_dir_nofollow(temp_dir.path(), DirectoryScope::Generic).unwrap()
}

fn artifact_names(listing: &WorkspaceArtifactListing) -> Vec<String> {
    listing
        .artifacts
        .iter()
        .map(|artifact| artifact.name().to_string())
        .collect()
}

#[test]
fn list_workspace_encrypted_artifacts_returns_sorted_supported_files() {
    let temp_dir = tempdir().unwrap();
    let secrets = temp_dir.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::write(secrets.join("z.json"), "{}").unwrap();
    fs::write(secrets.join("a.env.encrypted"), "x").unwrap();
    fs::write(secrets.join("m.env.kvenc"), "x").unwrap();
    fs::write(secrets.join("plain.env"), "x").unwrap();
    fs::create_dir(secrets.join("nested.json")).unwrap();

    let listing = list_workspace_encrypted_artifacts_at(&open_workspace(&temp_dir)).unwrap();

    assert_eq!(
        artifact_names(&listing),
        ["a.env.encrypted", "m.env.kvenc", "z.json"]
    );
    assert_eq!(listing.warnings.len(), 1, "{:?}", listing.warnings);
    assert!(
        listing.warnings[0].contains("nested.json"),
        "{:?}",
        listing.warnings
    );
    assert!(
        listing.warnings[0].contains("entry is not a regular file"),
        "{:?}",
        listing.warnings
    );
}

#[test]
fn is_encrypted_artifact_name_accepts_only_supported_extensions() {
    assert!(is_encrypted_artifact_name("a.env.encrypted"));
    assert!(is_encrypted_artifact_name("m.env.kvenc"));
    assert!(is_encrypted_artifact_name("z.json"));
    assert!(!is_encrypted_artifact_name("plain.txt"));
    assert!(!is_encrypted_artifact_name("plain.env"));
}

/// A symlink named like an artifact is excluded from the listing and reported
/// as a warning, so a teammate reviewing the run can see it was not covered.
#[cfg(unix)]
#[test]
fn list_workspace_encrypted_artifacts_reports_a_symlinked_artifact_entry() {
    use std::os::unix::fs::symlink;

    let temp_dir = tempdir().unwrap();
    let secrets = temp_dir.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::write(temp_dir.path().join("outside.json"), "{}").unwrap();
    fs::write(secrets.join("real.json"), "{}").unwrap();
    symlink(
        temp_dir.path().join("outside.json"),
        secrets.join("link.json"),
    )
    .unwrap();

    let listing = list_workspace_encrypted_artifacts_at(&open_workspace(&temp_dir)).unwrap();

    assert_eq!(artifact_names(&listing), ["real.json"]);
    assert_eq!(listing.warnings.len(), 1, "{:?}", listing.warnings);
    assert!(
        listing.warnings[0].contains("link.json"),
        "{:?}",
        listing.warnings
    );
    assert!(
        listing.warnings[0].contains("entry is not a regular file"),
        "{:?}",
        listing.warnings
    );
}

/// A listed artifact keeps the directory it was found under, so the workspace
/// path being repointed at another tree between the listing and the read leaves
/// the read on the artifact the run actually saw.
///
/// This is what a rewrap rests on: the recipient set is planned from the tree
/// that was listed, and a read that followed the path instead would let one
/// tree's plaintext be rewrapped for another tree's members.
#[cfg(unix)]
#[test]
fn listed_artifacts_read_the_tree_they_were_listed_in() {
    let temp_dir = tempdir().unwrap();
    let reviewed = temp_dir.path().join("reviewed");
    let substitute = temp_dir.path().join("substitute");
    fs::create_dir_all(reviewed.join("secrets")).unwrap();
    fs::create_dir_all(substitute.join("secrets")).unwrap();
    fs::write(reviewed.join("secrets").join("a.json"), "reviewed tree").unwrap();
    fs::write(substitute.join("secrets").join("a.json"), "other tree").unwrap();

    let workspace = open_dir_nofollow(&reviewed, DirectoryScope::Generic).unwrap();
    let listing = list_workspace_encrypted_artifacts_at(&workspace).unwrap();
    let artifact = listing.artifacts.first().unwrap();

    fs::rename(&reviewed, temp_dir.path().join("moved-aside")).unwrap();
    fs::rename(&substitute, &reviewed).unwrap();

    let captured = load_reviewed_artifact(artifact).unwrap();
    assert_eq!(captured.content(), Some("reviewed tree"));
}

/// A target named without a directory is resolved against the working directory
/// the operator typed it in.
#[cfg(unix)]
#[test]
fn open_from_path_binds_a_bare_name_to_the_working_directory() {
    let temp_dir = tempdir().unwrap();
    fs::write(temp_dir.path().join("bare.json"), "{}").unwrap();

    let artifact = crate::test_utils::with_temp_cwd(temp_dir.path(), || {
        ArtifactRef::open_from_path(std::path::Path::new("bare.json")).unwrap()
    });

    assert_eq!(artifact.name(), "bare.json");
    assert_eq!(artifact.path(), std::path::Path::new("bare.json"));
}

#[test]
fn open_from_path_reports_a_target_that_is_not_there() {
    let temp_dir = tempdir().unwrap();

    let error = ArtifactRef::open_from_path(&temp_dir.path().join("missing.json")).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
}

#[test]
fn open_from_path_refuses_a_directory_named_as_a_target() {
    let temp_dir = tempdir().unwrap();
    let directory = temp_dir.path().join("nested.json");
    fs::create_dir(&directory).unwrap();

    let error = ArtifactRef::open_from_path(&directory).unwrap_err();

    assert!(
        error.format_user_message().contains("non-regular file"),
        "{}",
        error.format_user_message()
    );
}

/// A link in the final position sends the write somewhere the operator did not
/// name, and that is settled while the run is still planning.
#[cfg(unix)]
#[test]
fn open_from_path_refuses_a_symlinked_target() {
    use std::os::unix::fs::symlink;

    let temp_dir = tempdir().unwrap();
    let real = temp_dir.path().join("real.json");
    let link = temp_dir.path().join("link.json");
    fs::write(&real, "{}").unwrap();
    symlink(&real, &link).unwrap();

    let error = ArtifactRef::open_from_path(&link).unwrap_err();

    assert!(
        error.format_user_message().contains("non-regular file"),
        "{}",
        error.format_user_message()
    );
}

/// Entries a teammate committed are judged one at a time, so the cases below
/// hand over a scan result directly: a filesystem may refuse to create a name
/// that does not decode, and an entry nobody can inspect cannot be staged from
/// a test either.
#[cfg(unix)]
mod skipped_entries {
    use std::fs;
    use std::sync::Arc;

    use tempfile::{tempdir, TempDir};

    use super::super::{collect_scanned_artifact, WorkspaceArtifactListing};
    use crate::support::fs::relative::{
        open_dir_nofollow, ChildName, ChildType, DirectoryScope, EntryIdentity, OpenDir,
        ScannedChild,
    };
    use crate::Error;

    fn open_secrets_dir(temp_dir: &TempDir) -> Arc<OpenDir> {
        let secrets = temp_dir.path().join("secrets");
        fs::create_dir(&secrets).unwrap();
        Arc::new(open_dir_nofollow(&secrets, DirectoryScope::Generic).unwrap())
    }

    fn empty_listing() -> WorkspaceArtifactListing {
        WorkspaceArtifactListing {
            artifacts: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn inspected_child(name: &[u8]) -> ScannedChild {
        inspected_child_with_type(name, ChildType::RegularFile)
    }

    fn inspected_child_with_type(name: &[u8], child_type: ChildType) -> ScannedChild {
        ScannedChild::Inspected {
            name: ChildName::from_raw_bytes(name),
            child_type,
            mode: 0o600,
            owner: 0,
            identity: EntryIdentity::from_parts(1, 1),
        }
    }

    /// A name kapsaro cannot decode is left out of the listing and named as a
    /// warning, so the artifacts beside it stay in.
    #[test]
    fn test_undecodable_name_is_reported_rather_than_listed() {
        let temp_dir = tempdir().unwrap();
        let dir = open_secrets_dir(&temp_dir);
        let mut listing = empty_listing();

        collect_scanned_artifact(&dir, inspected_child(b"broken\xff.json"), &mut listing);

        assert!(listing.artifacts.is_empty(), "{:?}", listing.artifacts);
        assert_eq!(listing.warnings.len(), 1, "{:?}", listing.warnings);
        assert!(
            listing.warnings[0].contains("entry name is not valid UTF-8"),
            "{:?}",
            listing.warnings
        );
    }

    /// An entry the scan could not inspect is reported for the same reason: the
    /// operator needs to know which artifact this run is not covering.
    #[test]
    fn test_uninspectable_entry_is_reported_rather_than_listed() {
        let temp_dir = tempdir().unwrap();
        let dir = open_secrets_dir(&temp_dir);
        let mut listing = empty_listing();

        collect_scanned_artifact(
            &dir,
            ScannedChild::Unreadable {
                name: ChildName::from_raw_bytes(b"denied.json"),
                error: Error::build_io_error("Permission denied"),
            },
            &mut listing,
        );

        assert!(listing.artifacts.is_empty(), "{:?}", listing.artifacts);
        assert_eq!(listing.warnings.len(), 1, "{:?}", listing.warnings);
        assert!(
            listing.warnings[0].contains("denied.json"),
            "{:?}",
            listing.warnings
        );
        assert!(
            listing.warnings[0].contains("Permission denied"),
            "{:?}",
            listing.warnings
        );
    }

    /// An entry with an artifact-shaped name that is not a regular file is
    /// reported: the workspace declared it an artifact by naming it one, and a
    /// directory or symlink standing in for it must not vanish from the run
    /// without a trace.
    #[test]
    fn test_non_regular_artifact_named_entry_is_reported_rather_than_listed() {
        let temp_dir = tempdir().unwrap();
        let dir = open_secrets_dir(&temp_dir);
        let mut listing = empty_listing();

        collect_scanned_artifact(
            &dir,
            inspected_child_with_type(b"nested.json", ChildType::Directory),
            &mut listing,
        );

        assert!(listing.artifacts.is_empty(), "{:?}", listing.artifacts);
        assert_eq!(listing.warnings.len(), 1, "{:?}", listing.warnings);
        assert!(
            listing.warnings[0].contains("nested.json"),
            "{:?}",
            listing.warnings
        );
        assert!(
            listing.warnings[0].contains("entry is not a regular file"),
            "{:?}",
            listing.warnings
        );
    }

    /// A readable artifact goes into the listing with nothing to report.
    #[test]
    fn test_readable_artifact_is_listed_without_a_warning() {
        let temp_dir = tempdir().unwrap();
        let dir = open_secrets_dir(&temp_dir);
        let mut listing = empty_listing();

        collect_scanned_artifact(&dir, inspected_child(b"real.json"), &mut listing);

        assert_eq!(listing.artifacts.len(), 1, "{:?}", listing.artifacts);
        assert_eq!(listing.artifacts[0].name(), "real.json");
        assert!(listing.warnings.is_empty(), "{:?}", listing.warnings);
    }
}
