// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Directory-fd-relative filesystem operations.
//! Keeps workspace I/O bound to a verified directory inode.

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};

pub(crate) trait DirectoryFd {
    fn file(&self) -> &File;
    fn path(&self) -> &Path;
}

#[derive(Debug)]
pub(crate) struct OpenDir {
    file: File,
    path: PathBuf,
}

impl DirectoryFd for OpenDir {
    fn file(&self) -> &File {
        &self.file
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
pub(crate) fn open_child_dir<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    let fd = rfs::openat(
        parent.file(),
        child.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        io_error(
            format!("Failed to open directory: {}", child_path(parent, name)),
            e,
        )
    })?;
    Ok(OpenDir {
        file: fd.into(),
        path: parent.path().join(name),
    })
}

#[cfg(unix)]
pub(crate) fn load_text_with_limit_at<D>(
    dir: &D,
    name: &str,
    max_bytes: usize,
    subject: &str,
) -> Result<String>
where
    D: DirectoryFd,
{
    let mut file = open_regular_file_at(dir, name)?;
    let path = child_path(dir, name);
    let bytes = load_capped_bytes(&mut file, max_bytes, subject, &path)?;
    String::from_utf8(bytes).map_err(|e| {
        Error::build_parse_error_with_source(format!("Failed to read file {}: {}", path, e), e)
    })
}

#[cfg(unix)]
pub(crate) fn file_exists_at<D>(dir: &D, name: &str) -> Result<bool>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    match rfs::statat(dir.file(), child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(
            format!("Failed to inspect file: {}", child_path(dir, name)),
            e,
        )),
    }
}

#[cfg(unix)]
pub(crate) fn list_child_names_at<D>(dir: &D) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    let stream = rfs::Dir::read_from(dir.file()).map_err(|e| {
        io_error(
            format!(
                "Failed to read directory: {}",
                format_path_relative_to_cwd(dir.path())
            ),
            e,
        )
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|e| {
            io_error(
                format!(
                    "Failed to read directory entry in {}",
                    format_path_relative_to_cwd(dir.path())
                ),
                e,
            )
        })?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_string());
    }
    names.sort();
    Ok(names)
}

#[cfg(unix)]
pub(crate) fn ensure_text_file_matches_snapshot_with_limit_at<D>(
    dir: &D,
    name: &str,
    reviewed_content: Option<&str>,
    subject_display: &str,
    max_bytes: usize,
) -> Result<()>
where
    D: DirectoryFd,
{
    match reviewed_content {
        Some(reviewed_content) => {
            let current =
                load_text_with_limit_at(dir, name, max_bytes, subject_display).map_err(|e| {
                    Error::build_invalid_operation_error(format!(
                        "{} changed since review: failed to read current file ({})",
                        subject_display, e
                    ))
                })?;
            if current == reviewed_content {
                return Ok(());
            }
        }
        None => {
            if !file_exists_at(dir, name)? {
                return Ok(());
            }
        }
    }

    Err(Error::build_invalid_operation_error(format!(
        "{} changed since review and must be reviewed again.",
        subject_display
    )))
}

#[cfg(unix)]
pub(crate) fn save_text_at<D>(dir: &D, name: &str, content: &str) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at(dir, name, content.as_bytes())
}

#[cfg(unix)]
pub(crate) fn save_text_restricted_at<D>(dir: &D, name: &str, content: &str) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at_with_mode(dir, name, content.as_bytes(), Some(Mode::from(0o600)))
}

#[cfg(unix)]
pub(crate) fn save_bytes_at<D>(dir: &D, name: &str, data: &[u8]) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at_with_mode(dir, name, data, None)
}

#[cfg(unix)]
fn save_bytes_at_with_mode<D>(dir: &D, name: &str, data: &[u8], mode: Option<Mode>) -> Result<()>
where
    D: DirectoryFd,
{
    let target = checked_child_name(name)?;
    reject_symlink_target(dir, name)?;
    let temp_name = unique_temp_name(name);
    let temp = checked_child_name(&temp_name)?;
    let mut temp_file = create_temp_file(dir, temp.as_c_str(), &temp_name)?;
    if let Some(mode) = mode {
        if let Err(error) = set_open_file_mode(dir, &temp_file, &temp_name, mode) {
            drop(temp_file);
            let _ = unlink_child(dir, &temp_name);
            return Err(error);
        }
    }
    let write_result = write_and_flush(&mut temp_file, data);
    drop(temp_file);
    if let Err(error) = write_result {
        let _ = unlink_child(dir, &temp_name);
        return Err(error);
    }
    rfs::renameat(dir.file(), temp.as_c_str(), dir.file(), target.as_c_str()).map_err(|e| {
        let _ = unlink_child(dir, &temp_name);
        io_error(format!("Persist to {} failed", child_path(dir, name)), e)
    })?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn remove_file_at<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    unlink_child(dir, name)
}

#[cfg(unix)]
fn open_regular_file_at<D>(dir: &D, name: &str) -> Result<File>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    validate_pre_open_file_type(dir, name, child.as_c_str())?;
    let fd = rfs::openat(
        dir.file(),
        child.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        io_error(
            format!("Failed to read file {}: {}", child_path(dir, name), e),
            e,
        )
    })?;
    let file: File = fd.into();
    validate_regular_file(&file, &child_path(dir, name))?;
    Ok(file)
}

#[cfg(unix)]
fn validate_pre_open_file_type<D>(dir: &D, name: &str, child: &std::ffi::CStr) -> Result<()>
where
    D: DirectoryFd,
{
    let path = child_path(dir, name);
    let stat = rfs::statat(dir.file(), child, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| io_error(format!("Failed to read file {}: {}", path, e), e))?;
    validate_raw_file_type(FileType::from_raw_mode(stat.st_mode), &path)
}

#[cfg(unix)]
fn validate_regular_file(file: &File, path: &str) -> Result<()> {
    let metadata = file.metadata().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to read file {path}: {e}"), e)
    })?;
    if metadata.file_type().is_file() {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(format!(
        "refusing to read non-regular file: {path}"
    )))
}

#[cfg(unix)]
fn validate_raw_file_type(file_type: FileType, path: &str) -> Result<()> {
    if file_type == FileType::Symlink {
        return Err(Error::build_invalid_operation_error(format!(
            "refusing to read symlink: {path}"
        )));
    }
    if file_type == FileType::RegularFile {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(format!(
        "refusing to read non-regular file: {path}"
    )))
}

#[cfg(unix)]
fn reject_symlink_target<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    match rfs::statat(dir.file(), child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
            Err(Error::build_invalid_operation_error(format!(
                "refusing to write: target is a symlink: {}",
                child_path(dir, name)
            )))
        }
        Ok(_) => Ok(()),
        Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error(
            format!("Failed to inspect file: {}", child_path(dir, name)),
            e,
        )),
    }
}

#[cfg(unix)]
fn create_temp_file<D>(dir: &D, temp: &std::ffi::CStr, temp_name: &str) -> Result<File>
where
    D: DirectoryFd,
{
    let fd = rfs::openat(
        dir.file(),
        temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from(0o600),
    )
    .map_err(|e| {
        io_error(
            format!("Failed to create temp file: {}", child_path(dir, temp_name)),
            e,
        )
    })?;
    Ok(fd.into())
}

#[cfg(unix)]
fn set_open_file_mode<D>(dir: &D, file: &File, name: &str, mode: Mode) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::fchmod(file, mode).map_err(|e| {
        io_error(
            format!("Failed to set file permissions: {}", child_path(dir, name)),
            e,
        )
    })
}

fn write_and_flush(file: &mut File, data: &[u8]) -> Result<()> {
    file.write_all(data)
        .map_err(|e| Error::build_io_error_with_source(format!("Write failed: {}", e), e))?;
    file.flush()
        .map_err(|e| Error::build_io_error_with_source(format!("Flush failed: {}", e), e))
}

#[cfg(unix)]
fn unlink_child<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    rfs::unlinkat(dir.file(), child.as_c_str(), AtFlags::empty()).map_err(|e| {
        Error::build_io_error_with_source(
            format!("Failed to remove file {}: {}", child_path(dir, name), e),
            std::io::Error::from(e),
        )
    })
}

fn load_capped_bytes(
    file: &mut File,
    max_bytes: usize,
    subject: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let initial = std::cmp::min(max_bytes.saturating_add(1), 64 * 1024);
    let mut buf = Vec::with_capacity(initial);
    let cap = (max_bytes as u64).saturating_add(1);
    file.take(cap).read_to_end(&mut buf).map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to read file {}: {}", path, e), e)
    })?;
    if buf.len() <= max_bytes {
        return Ok(buf);
    }
    Err(Error::build_parse_error(format!(
        "{} exceeds maximum size limit ({} bytes > {} bytes): {}",
        subject,
        buf.len(),
        max_bytes,
        path
    )))
}

fn checked_child_name(name: &str) -> Result<CString> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(invalid_child_name(name));
    }
    if name
        .as_bytes()
        .iter()
        .any(|&byte| byte == b'/' || byte == b'\\')
    {
        return Err(invalid_child_name(name));
    }
    CString::new(name).map_err(|_| invalid_child_name(name))
}

fn invalid_child_name(name: &str) -> Error {
    Error::build_invalid_argument_error(format!(
        "invalid relative file name '{}': only a single path component is allowed",
        name
    ))
}

fn unique_temp_name(target: &str) -> String {
    format!(".{target}.tmp.{}", uuid::Uuid::new_v4())
}

fn child_path<D>(dir: &D, name: &str) -> String
where
    D: DirectoryFd,
{
    format_path_relative_to_cwd(&dir.path().join(name))
}

#[cfg(unix)]
fn io_error(message: String, error: rustix::io::Errno) -> Error {
    Error::build_io_error_with_source(message, std::io::Error::from(error))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_relative_test.rs"]
mod support_fs_relative_test;
