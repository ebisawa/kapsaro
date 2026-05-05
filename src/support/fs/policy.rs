// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub(crate) enum DirectoryPurpose {
    General,
    Workspace,
    LockFile,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DirectoryMode {
    Normal,
    Restricted,
}

pub(crate) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            let file_type = metadata.file_type();
            file_type.is_dir() && !file_type.is_symlink()
        })
        .unwrap_or(false)
}

pub(crate) fn ensure_real_directory_tree(
    path: &Path,
    purpose: DirectoryPurpose,
    mode: DirectoryMode,
) -> Result<()> {
    for missing_dir in collect_missing_directories(path, purpose)?
        .into_iter()
        .rev()
    {
        create_directory(&missing_dir, purpose, mode)?;
    }
    if matches!(mode, DirectoryMode::Restricted) && is_real_dir(path) {
        set_directory_permission_0700(path)?;
    }
    Ok(())
}

pub(crate) fn reject_symlink(path: &Path, message: impl FnOnce(String) -> String) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::InvalidOperation {
            message: message(format_path_relative_to_cwd(path)),
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::build_io_error_with_source(
            format!(
                "Failed to inspect {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )),
    }
}

fn collect_missing_directories(path: &Path, purpose: DirectoryPurpose) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();

    for ancestor in path.ancestors() {
        let candidate = normalize_empty_path(ancestor);
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                validate_real_directory(candidate, &metadata, purpose)?;
                return Ok(missing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
            }
            Err(e) => return Err(inspect_directory_error(candidate, purpose, e)),
        }
    }

    Err(resolve_directory_error(path, purpose))
}

fn normalize_empty_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

fn validate_real_directory(
    path: &Path,
    metadata: &fs::Metadata,
    purpose: DirectoryPurpose,
) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::InvalidOperation {
            message: symlink_directory_message(path, purpose),
        });
    }
    if !file_type.is_dir() {
        return Err(Error::build_io_error(non_directory_message(path, purpose)));
    }
    Ok(())
}

fn create_directory(path: &Path, purpose: DirectoryPurpose, mode: DirectoryMode) -> Result<()> {
    match mode {
        DirectoryMode::Normal => create_directory_normal(path, purpose),
        DirectoryMode::Restricted => create_directory_restricted(path, purpose),
    }
}

fn create_directory_normal(path: &Path, purpose: DirectoryPurpose) -> Result<()> {
    fs::create_dir(path).map_err(|e| create_directory_error(path, purpose, e))
}

#[cfg(unix)]
fn create_directory_restricted(path: &Path, purpose: DirectoryPurpose) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| create_directory_error(path, purpose, e))?;
    set_directory_permission_0700(path)
}

#[cfg(not(unix))]
fn create_directory_restricted(path: &Path, purpose: DirectoryPurpose) -> Result<()> {
    create_directory_normal(path, purpose)
}

#[cfg(unix)]
pub(crate) fn set_directory_permission_0700(path: &Path) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, Permissions::from_mode(0o700)).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to set permissions on {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

#[cfg(not(unix))]
pub(crate) fn set_directory_permission_0700(_path: &Path) -> Result<()> {
    Ok(())
}

fn inspect_directory_error(path: &Path, purpose: DirectoryPurpose, e: std::io::Error) -> Error {
    let path_display = format_path_relative_to_cwd(path);
    let message = match purpose {
        DirectoryPurpose::General | DirectoryPurpose::Workspace => {
            format!("Failed to inspect directory {}: {}", path_display, e)
        }
        DirectoryPurpose::LockFile => {
            format!(
                "Failed to inspect lock file directory {}: {}",
                path_display, e
            )
        }
    };
    Error::build_io_error_with_source(message, e)
}

fn resolve_directory_error(path: &Path, purpose: DirectoryPurpose) -> Error {
    let path_display = format_path_relative_to_cwd(path);
    let message = match purpose {
        DirectoryPurpose::General => {
            format!("Failed to resolve directory ancestry for {}", path_display)
        }
        DirectoryPurpose::Workspace => {
            format!(
                "Failed to resolve workspace directory ancestry for {}",
                path_display
            )
        }
        DirectoryPurpose::LockFile => {
            format!(
                "Failed to resolve parent directory for lock file: {}",
                path_display
            )
        }
    };
    Error::build_io_error(message)
}

fn create_directory_error(path: &Path, purpose: DirectoryPurpose, e: std::io::Error) -> Error {
    let path_display = format_path_relative_to_cwd(path);
    let message = match purpose {
        DirectoryPurpose::General | DirectoryPurpose::Workspace => {
            format!("Failed to create directory {}: {}", path_display, e)
        }
        DirectoryPurpose::LockFile => {
            format!(
                "Failed to create directory for lock file '{}': {}",
                path_display, e
            )
        }
    };
    Error::build_io_error_with_source(message, e)
}

fn symlink_directory_message(path: &Path, purpose: DirectoryPurpose) -> String {
    let path_display = format_path_relative_to_cwd(path);
    match purpose {
        DirectoryPurpose::General => {
            format!(
                "refusing to create directory through symlink: {}",
                path_display
            )
        }
        DirectoryPurpose::Workspace => {
            format!(
                "refusing to create workspace path through symlink: {}",
                path_display
            )
        }
        DirectoryPurpose::LockFile => {
            format!(
                "refusing to create lock file in symlinked directory: {}",
                path_display
            )
        }
    }
}

fn non_directory_message(path: &Path, purpose: DirectoryPurpose) -> String {
    let path_display = format_path_relative_to_cwd(path);
    match purpose {
        DirectoryPurpose::General | DirectoryPurpose::Workspace => {
            format!(
                "Failed to create directory {}: existing path is not a directory",
                path_display
            )
        }
        DirectoryPurpose::LockFile => {
            format!(
                "Failed to create directory for lock file '{}': existing path is not a directory",
                path_display
            )
        }
    }
}
