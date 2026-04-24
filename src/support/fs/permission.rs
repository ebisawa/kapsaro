// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to create directory {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

#[cfg(unix)]
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to create directory {}: {}",
                    format_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })?;

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
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    ensure_dir(path)
}

#[cfg(unix)]
pub fn set_file_permission_0600(path: &Path) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|e| {
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
pub fn set_file_permission_0600(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn check_permission(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Some(format!(
                "Cannot check permissions on {}: {}",
                format_path_relative_to_cwd(path),
                e
            ));
        }
    };
    let mode = metadata.permissions().mode();
    let extra_bits = mode & 0o077;
    if extra_bits == 0 {
        return None;
    }

    let expected = if metadata.is_dir() { "0700" } else { "0600" };
    Some(format!(
        "Insecure permissions {:04o} on {} (expected {})",
        mode & 0o777,
        format_path_relative_to_cwd(path),
        expected,
    ))
}

#[cfg(not(unix))]
pub fn check_permission(_path: &Path) -> Option<String> {
    None
}

#[cfg(unix)]
pub fn check_permission_chain(path: &Path, logical_root: &Path) -> Vec<String> {
    if !path.starts_with(logical_root) {
        return vec![format!(
            "Cannot check permissions on {}: path is outside logical root {}",
            format_path_relative_to_cwd(path),
            format_path_relative_to_cwd(logical_root)
        )];
    }

    let mut warnings = Vec::new();
    warnings.extend(check_permission(logical_root));

    let mut current = logical_root.to_path_buf();
    let Ok(relative_path) = path.strip_prefix(logical_root) else {
        return warnings;
    };

    for component in relative_path.components() {
        current.push(component.as_os_str());
        if let Some(warning) = check_permission(&current) {
            warnings.push(warning);
        }
    }

    warnings
}

#[cfg(not(unix))]
pub fn check_permission_chain(_path: &Path, _logical_root: &Path) -> Vec<String> {
    Vec::new()
}
