// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::support::fs::atomic;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

pub(crate) fn resolve_encrypted_output_path(
    explicit_out: Option<&PathBuf>,
    write_stdout: bool,
    input_path: Option<&Path>,
    from_stdin: bool,
) -> Result<Option<PathBuf>> {
    if write_stdout {
        return Ok(None);
    }

    if let Some(out) = explicit_out {
        return Ok(Some(out.clone()));
    }

    if from_stdin {
        return Err(Error::build_invalid_argument_error(
            "--stdin requires either --out or --stdout",
        ));
    }

    let input_path = input_path.ok_or_else(|| {
        Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
    })?;

    let input_filename = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::InvalidArgument {
            message: format!(
                "Cannot derive filename from input path: {}",
                format_path_relative_to_cwd(input_path)
            ),
        })?;

    if input_filename.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidArgument {
            message: format!("E_NAME_INVALID: invalid input filename: {}", input_filename),
        });
    }

    let current_dir = std::env::current_dir().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to get current directory: {}", e), e)
    })?;
    Ok(Some(
        current_dir.join(format!("{}.encrypted", input_filename)),
    ))
}

pub(crate) fn save_encrypted_output(
    output_path: Option<&PathBuf>,
    content: &str,
    quiet: bool,
) -> Result<()> {
    match output_path {
        Some(path) => {
            atomic::save_text(path, content)?;
            print_output_notice("Encrypted to", path, quiet);
        }
        None => print!("{}", content),
    }
    Ok(())
}

pub(crate) fn save_decrypted_output(
    output_path: Option<&Path>,
    plaintext_bytes: &[u8],
    quiet: bool,
) -> Result<()> {
    match output_path {
        Some(path) => {
            atomic::save_bytes(path, plaintext_bytes)?;
            print_output_notice("Decrypted to", path, quiet);
        }
        None => {
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            writer.write_all(plaintext_bytes)?;
            writer.flush()?;
        }
    }
    Ok(())
}

pub(crate) fn resolve_decrypted_output_path(
    explicit_out: Option<&PathBuf>,
    write_stdout: bool,
) -> Result<Option<PathBuf>> {
    if write_stdout {
        return Ok(None);
    }

    explicit_out
        .cloned()
        .map(Some)
        .ok_or_else(|| Error::build_invalid_argument_error("requires either --out or --stdout"))
}

fn print_output_notice(label: &str, output_path: &Path, quiet: bool) {
    if quiet {
        return;
    }
    eprintln!("{}: {}", label, format_path_relative_to_cwd(output_path));
}
