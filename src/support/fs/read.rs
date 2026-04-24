// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

pub fn load_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

pub fn load_bytes_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<Vec<u8>> {
    let mut file = open_regular_file(path)?;
    load_capped_bytes(&mut file, max_bytes, subject, path)
}

pub fn load_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

pub fn load_text_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<String> {
    let bytes = load_bytes_with_limit(path, max_bytes, subject)?;
    String::from_utf8(bytes).map_err(|e| Error::Parse {
        message: format!(
            "Failed to read file {}: {}",
            format_path_relative_to_cwd(path),
            e
        ),
        source: Some(Box::new(e)),
    })
}

fn open_regular_file(path: &Path) -> Result<File> {
    let pre_meta = fs::symlink_metadata(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    validate_pre_open_file_type(path, &pre_meta)?;

    let file = open_no_follow(path)?;
    validate_post_open_file_type(path, &file)?;
    Ok(file)
}

fn validate_pre_open_file_type(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to read symlink: {}",
                format_path_relative_to_cwd(path)
            ),
        });
    }
    validate_regular_file_type(path, file_type)
}

fn validate_post_open_file_type(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    validate_regular_file_type(path, metadata.file_type())
}

fn validate_regular_file_type(path: &Path, file_type: fs::FileType) -> Result<()> {
    if file_type.is_file() {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: format!(
            "refusing to read non-regular file: {}",
            format_path_relative_to_cwd(path)
        ),
    })
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to read file {}: {}",
                    format_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File> {
    fs::File::open(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

fn load_capped_bytes(
    file: &mut File,
    max_bytes: usize,
    subject: &str,
    path: &Path,
) -> Result<Vec<u8>> {
    let initial = std::cmp::min(max_bytes.saturating_add(1), 64 * 1024);
    let mut buf = Vec::with_capacity(initial);
    let cap = (max_bytes as u64).saturating_add(1);
    file.take(cap).read_to_end(&mut buf).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    validate_loaded_size(path, buf.len(), max_bytes, subject)?;
    Ok(buf)
}

fn validate_loaded_size(path: &Path, size: usize, max_bytes: usize, subject: &str) -> Result<()> {
    if size <= max_bytes {
        return Ok(());
    }

    Err(Error::Parse {
        message: format!(
            "{} exceeds maximum size limit ({} bytes > {} bytes): {}",
            subject,
            size,
            max_bytes,
            format_path_relative_to_cwd(path)
        ),
        source: None,
    })
}
