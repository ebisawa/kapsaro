// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::support::fs::atomic;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};

pub(crate) fn resolve_encrypted_output_path(
    explicit_out: Option<&PathBuf>,
    input_path: &Path,
) -> Result<Option<PathBuf>> {
    if let Some(out) = explicit_out {
        return Ok(Some(out.clone()));
    }

    let input_filename = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::InvalidArgument {
            message: format!(
                "Cannot derive filename from input path: {}",
                display_path_relative_to_cwd(input_path)
            ),
        })?;

    if input_filename.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidArgument {
            message: format!("E_NAME_INVALID: invalid input filename: {}", input_filename),
        });
    }

    let current_dir = std::env::current_dir()
        .map_err(|e| Error::io_with_source(format!("Failed to get current directory: {}", e), e))?;
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
    output_path: &Path,
    plaintext_bytes: &[u8],
    quiet: bool,
) -> Result<()> {
    atomic::save_bytes(output_path, plaintext_bytes)?;
    print_output_notice("Decrypted to", output_path, quiet);
    Ok(())
}

fn print_output_notice(label: &str, output_path: &Path, quiet: bool) {
    if quiet {
        return;
    }
    eprintln!("{}: {}", label, display_path_relative_to_cwd(output_path));
}
