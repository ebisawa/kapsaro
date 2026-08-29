// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Path-addressed file reads, with and without a size cap.
//! Rejects anything but a regular file on the descriptor it opened.

use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::support::limits::MAX_PLAINTEXT_INPUT_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use zeroize::Zeroize;

/// Read a plaintext input file the operator named on the command line.
///
/// The path comes from an argument, so the entry standing there may be a FIFO
/// that never ends or a file far larger than anything kapsaro can encrypt. The
/// read is bound to a regular file and to the input size limit, which is what
/// keeps an unbounded path from deciding how much memory the process takes.
pub fn load_bytes(path: &Path) -> Result<Vec<u8>> {
    load_bytes_with_limit(path, MAX_PLAINTEXT_INPUT_SIZE, "Input file")
}

pub fn load_bytes_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<Vec<u8>> {
    let mut file = open_regular_file(path)?;
    load_capped_bytes(
        &mut file,
        max_bytes,
        subject,
        &format_path_relative_to_cwd(path),
    )
}

pub fn load_text_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<String> {
    let bytes = load_bytes_with_limit(path, max_bytes, subject)?;
    decode_loaded_text(bytes, &format_path_relative_to_cwd(path))
}

/// Open a regular file named by path, refusing any other entry type.
///
/// Shared with the snapshot capture, which keeps the descriptor rather than
/// reading and dropping it: one open is what settles both the type and the
/// inode a caller is allowed to act on.
pub(crate) fn open_regular_file(path: &Path) -> Result<File> {
    let file = open_without_blocking(path)?;
    validate_post_open_file_type(path, &file)?;
    Ok(file)
}

/// Reject anything but a regular file, on the descriptor that will be read.
///
/// Inspecting the open descriptor rather than the name settles the type of the
/// file the read actually gets, so a path swapped after the open cannot change
/// what was approved.
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

    Err(Error::build_invalid_operation_error(format!(
        "refusing to read non-regular file: {}",
        format_path_relative_to_cwd(path)
    )))
}

/// Open a file for reading without waiting on it.
///
/// `O_NONBLOCK` keeps a FIFO named where a file was expected from hanging the
/// open; the descriptor is rejected right afterwards for not being a regular
/// file.
#[cfg(unix)]
fn open_without_blocking(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
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

/// Read a whole file into memory, refusing one larger than `max_bytes`.
///
/// `display_path` is the path already rendered for messages rather than a
/// `&Path`. The directory-relative reader renders its path once and uses that
/// same rendering for the decode failure below, so rendering it again here
/// would repeat the work and let the two spellings of one path drift apart.
///
/// The cap is applied to the read itself, not to the size the metadata claims,
/// so a file that grows between the two still stops at the bound.
///
/// The read stops one byte past the limit, so all this function ever learns
/// about an oversized file is that it went over; the failure names the limit
/// rather than a byte count that would always be the limit plus one.
///
/// Whichever way the read ends short of a value the caller receives, the buffer
/// is wiped before the failure leaves. Private keys are read through here, and a
/// read that stopped partway or a file one byte over the limit has just as much
/// of one in memory as a read that succeeded.
pub(crate) fn load_capped_bytes(
    file: &mut File,
    max_bytes: usize,
    subject: &str,
    display_path: &str,
) -> Result<Vec<u8>> {
    let initial = std::cmp::min(max_bytes.saturating_add(1), 64 * 1024);
    let mut buf = Vec::with_capacity(initial);
    let cap = (max_bytes as u64).saturating_add(1);
    if let Err(error) = file.take(cap).read_to_end(&mut buf) {
        let message = format!("Failed to read file {}: {}", display_path, error);
        buf.zeroize();
        return Err(Error::build_io_error_with_source(message, error));
    }
    if buf.len() <= max_bytes {
        return Ok(buf);
    }
    let message = format!(
        "{} exceeds maximum size limit ({} bytes): {}",
        subject, max_bytes, display_path
    );
    buf.zeroize();
    Err(Error::build_parse_error(message))
}

/// Decode a file that was read into memory, keeping its bytes out of the error.
///
/// `String::from_utf8` hands the whole buffer back inside `FromUtf8Error`, and
/// an error holding that as its source prints the file when it is formatted
/// with `{:?}`. Private keys are read through here, so the bytes are borrowed
/// for the check and wiped before the failure leaves this function.
pub(crate) fn decode_loaded_text(mut bytes: Vec<u8>, display_path: &str) -> Result<String> {
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text.to_string(),
        Err(error) => {
            let message = format!("Failed to read file {}: {}", display_path, error);
            bytes.zeroize();
            return Err(Error::build_parse_error(message));
        }
    };
    bytes.zeroize();
    Ok(text)
}
