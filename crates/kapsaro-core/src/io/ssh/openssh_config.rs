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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Parse the explicit home directory's SSH config and extract `IdentityAgent`.
/// Path expansion uses only the caller-supplied home and variable values.
///
/// # Priority
///
/// 1. `Host *` block (if present)
/// 2. Global scope (outside any Host block)
///
/// A block naming particular hosts is skipped: the agent it names is chosen for
/// connections to those hosts and says nothing about signing here.
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
pub fn find_identity_agent(
    home: &Path,
    expansion_values: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    let config_path = home.join(".ssh").join("config");
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

    parse_identity_agent(&content, home, expansion_values)
}

/// Which part of the file the reader stands in.
///
/// A directive applies to the hosts of the block it stands in, so the three are
/// kept apart: an agent named outside every block, one named in the block that
/// matches every host, and one named in a block for particular hosts, which
/// says nothing about the hosts kapsaro signs for. A `Match` block is read as
/// a block for particular hosts, since its conditions are not evaluated here.
enum HostScope {
    Global,
    HostStar,
    OtherHost,
}

impl HostScope {
    fn from_host_patterns(patterns: &str) -> Self {
        if patterns.split_whitespace().any(|pattern| pattern == "*") {
            Self::HostStar
        } else {
            Self::OtherHost
        }
    }
}

/// Extract IdentityAgent values (global and Host *) from parsed SSH config lines.
fn extract_identity_agent_values(content: &str) -> (Option<String>, Option<String>) {
    let mut scope = HostScope::Global;
    let mut global_identity_agent: Option<String> = None;
    let mut host_star_identity_agent: Option<String> = None;

    for line in content.lines() {
        let line = extract_config_line_before_comment(line).trim();
        if line.is_empty() {
            continue;
        }

        let (keyword, value) = split_config_keyword(line);
        if keyword.eq_ignore_ascii_case("host") {
            scope = HostScope::from_host_patterns(value);
            continue;
        }
        if keyword.eq_ignore_ascii_case("match") {
            scope = HostScope::OtherHost;
            continue;
        }
        if !keyword.eq_ignore_ascii_case("identityagent") {
            continue;
        }

        let unquoted = parse_quoted_value(value);
        match scope {
            HostScope::HostStar => host_star_identity_agent = Some(unquoted),
            HostScope::Global if global_identity_agent.is_none() => {
                global_identity_agent = Some(unquoted);
            }
            HostScope::Global | HostScope::OtherHost => {}
        }
    }

    (global_identity_agent, host_star_identity_agent)
}

/// Split a config line into its keyword and the rest of the line.
///
/// The keyword ends at the first whitespace or `=`, which is what separates it
/// from its value in an OpenSSH config. Matching a bare prefix instead would
/// read `HostName` and `HostKeyAlias` as the start of a `Host` block and end
/// the block they actually stand in.
fn split_config_keyword(line: &str) -> (&str, &str) {
    let keyword_end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(keyword_end);
    let rest = rest.trim_start();
    (keyword, rest.strip_prefix('=').unwrap_or(rest).trim())
}

/// Resolve an IdentityAgent value using only caller-supplied expansion inputs.
fn resolve_identity_agent_path(
    val: String,
    home: &Path,
    expansion_values: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    if val.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let home = home.to_str().ok_or_else(|| {
        Error::build_config_error("IdentityAgent home path contains invalid UTF-8")
    })?;
    let expanded = shellexpand::full_with_context(
        &val,
        || Some(home),
        |name| match expansion_values.get(name) {
            Some(value) => Ok(Some(value.as_str())),
            None => Err(format!(
                "environment variable {name} is not available in fixed inputs"
            )),
        },
    )
    .map_err(|e| {
        Error::build_config_error(format!(
            "Failed to expand IdentityAgent path '{}': {}",
            val, e
        ))
    })?;
    Ok(Some(PathBuf::from(expanded.as_ref())))
}

/// Parse SSH config content and extract `IdentityAgent`
pub fn parse_identity_agent(
    content: &str,
    home: &Path,
    expansion_values: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    let (global, host_star) = extract_identity_agent_values(content);

    // Priority: Host * block > global scope
    match host_star.or(global) {
        Some(val) => resolve_identity_agent_path(val, home, expansion_values),
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_ssh_openssh_config_integration_test.rs"]
mod io_ssh_openssh_config_integration_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_ssh_openssh_config_test.rs"]
mod io_ssh_openssh_config_test;
