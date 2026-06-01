// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! OpenSSH config file parser (minimal subset for IdentityAgent)
//!
//! This module provides a minimal parser for `~/.ssh/config` to extract
//! `IdentityAgent` directives. It supports:
//! - Case-insensitive key matching
//! - Quoted values (single and double quotes)
//! - Tilde expansion (~)
//! - `Host *` block matching (for global settings)
//! - Comments and empty lines

use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_SSH_CONFIG_FILE_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::PathBuf;

/// Parse `~/.ssh/config` and extract `IdentityAgent` value
///
/// # Priority
///
/// 1. `Host *` block (if present)
/// 2. Global scope (outside any Host block)
///
/// # Returns
///
/// - `Ok(Some(path))` if `IdentityAgent` is found and not "none"
/// - `Ok(None)` if not found or file doesn't exist
/// - `Err` if file exists but parsing fails
///
/// # Examples
///
/// ```text
/// Host *
///     IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
/// ```
pub fn find_identity_agent() -> Result<Option<PathBuf>> {
    let home = std::env::var("HOME")
        .map_err(|_| Error::build_config_error("HOME environment variable not set".to_string()))?;

    let config_path = PathBuf::from(home).join(".ssh").join("config");
    if !config_path.exists() {
        return Ok(None);
    }

    let content = load_text_with_limit(&config_path, MAX_SSH_CONFIG_FILE_SIZE, "SSH config file")
        .map_err(|e| {
        Error::build_io_error(format!(
            "Failed to read SSH config file {}: {}",
            format_path_relative_to_cwd(&config_path),
            e
        ))
    })?;

    parse_identity_agent(&content)
}

/// Extract IdentityAgent values (global and Host *) from parsed SSH config lines.
fn extract_identity_agent_values(content: &str) -> (Option<String>, Option<String>) {
    let mut in_host_star = false;
    let mut global_identity_agent: Option<String> = None;
    let mut host_star_identity_agent: Option<String> = None;

    for line in content.lines() {
        let line = extract_config_line_before_comment(line);
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if let Some(host_pattern) = line.strip_prefix("Host") {
            let patterns: Vec<&str> = host_pattern.split_whitespace().collect();
            in_host_star = patterns.iter().any(|p| p.eq_ignore_ascii_case("*"));
            continue;
        }

        let line_lower = line.to_ascii_lowercase();
        if let Some(value) = line_lower
            .strip_prefix("identityagent")
            .map(|suffix| &line[line.len() - suffix.len()..])
        {
            let unquoted = parse_quoted_value(value.trim());
            if in_host_star {
                host_star_identity_agent = Some(unquoted);
            } else if global_identity_agent.is_none() {
                global_identity_agent = Some(unquoted);
            }
        }
    }

    (global_identity_agent, host_star_identity_agent)
}

/// Resolve an IdentityAgent string value to a PathBuf, expanding tilde/env vars.
fn resolve_identity_agent_path(val: String) -> Result<Option<PathBuf>> {
    if val.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let expanded = shellexpand::full(&val).map_err(|e| {
        Error::build_config_error(format!(
            "Failed to expand IdentityAgent path '{}': {}",
            val, e
        ))
    })?;
    Ok(Some(PathBuf::from(expanded.as_ref())))
}

/// Parse SSH config content and extract `IdentityAgent`
pub fn parse_identity_agent(content: &str) -> Result<Option<PathBuf>> {
    let (global, host_star) = extract_identity_agent_values(content);

    // Priority: Host * block > global scope
    match host_star.or(global) {
        Some(val) => resolve_identity_agent_path(val),
        None => Ok(None),
    }
}

/// Remove comment from line (everything after #, but not inside quotes)
pub fn extract_config_line_before_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;

    for (i, ch) in line.char_indices() {
        match ch {
            '#' if !in_single && !in_double => {
                return &line[..i];
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            _ => {}
        }
    }
    line
}

/// Remove surrounding quotes from value
pub fn parse_quoted_value(value: &str) -> String {
    let trimmed = value.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        if trimmed.len() >= 2 {
            trimmed[1..trimmed.len() - 1].to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    }
}
