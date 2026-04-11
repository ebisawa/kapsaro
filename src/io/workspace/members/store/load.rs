// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::{find_member_path, members_dir, MemberStatus};
use crate::format::schema::document::parse_public_key_file;
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::kid::kid_display_lossy;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) fn load_json_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = list_dir(dir)?;
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| -> Result<Option<PathBuf>> {
            let entry = entry.map_err(|e| {
                Error::io_with_source(
                    format!(
                        "Failed to read directory entry in {}: {}",
                        display_path_relative_to_cwd(dir),
                        e
                    ),
                    e,
                )
            })?;
            let path = entry.path();
            Ok(
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    Some(path)
                } else {
                    None
                },
            )
        })
        .filter_map(|result| result.transpose())
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn load_sorted_members_from_dir(dir: &Path) -> Result<Vec<PublicKey>> {
    let paths = load_json_files_in_dir(dir)?;
    let mut members = paths
        .into_iter()
        .map(|path| load_member_file_from_path(&path))
        .collect::<Result<Vec<_>>>()?;
    members.sort_by(|a, b| a.protected.member_id.cmp(&b.protected.member_id));
    Ok(members)
}

pub fn load_active_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members_from_dir(&members_dir(workspace_path, MemberStatus::Active))
}

pub fn load_incoming_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members_from_dir(&members_dir(workspace_path, MemberStatus::Incoming))
}

pub fn list_active_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Active))
}

pub fn list_incoming_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Incoming))
}

pub fn list_active_member_ids(workspace_root: &Path) -> Result<Vec<String>> {
    let paths = load_json_files_in_dir(&members_dir(workspace_root, MemberStatus::Active))?;
    let mut member_ids: Vec<String> = paths
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(String::from)
        })
        .collect();

    if member_ids.is_empty() {
        return Err(Error::NotFound {
            message: "No members found in workspace".to_string(),
        });
    }

    member_ids.sort();
    Ok(member_ids)
}

pub fn load_member_files(workspace_path: &Path, member_ids: &[String]) -> Result<Vec<PublicKey>> {
    let mut members = Vec::with_capacity(member_ids.len());

    for member_id in member_ids {
        let (public_key, _status) = load_member_file(workspace_path, member_id)?;
        if public_key.protected.member_id != *member_id {
            return Err(Error::InvalidArgument {
                message: format!(
                    "Member ID mismatch: file '{}' contains ID '{}'",
                    member_id, public_key.protected.member_id
                ),
            });
        }
        members.push(public_key);
    }

    Ok(members)
}

pub fn load_active_member_index_by_kid(
    workspace_path: &Path,
) -> Result<BTreeMap<String, PublicKey>> {
    let mut index = BTreeMap::new();

    for member in load_active_member_files(workspace_path)? {
        let kid = member.protected.kid.clone();
        if index.insert(kid.clone(), member).is_some() {
            return Err(Error::Config {
                message: format!(
                    "Ambiguous key: kid '{}' found in multiple members",
                    kid_display_lossy(&kid)
                ),
            });
        }
    }

    Ok(index)
}

pub fn find_active_member_by_kid(workspace_path: &Path, kid: &str) -> Result<Option<PublicKey>> {
    Ok(load_active_member_index_by_kid(workspace_path)?.remove(kid))
}

pub fn load_member_file(
    workspace_path: &Path,
    member_id: &str,
) -> Result<(PublicKey, MemberStatus)> {
    if let Some((path, status)) = find_member_path(workspace_path, member_id) {
        let key = load_member_file_from_path(&path)?;
        return Ok((key, status));
    }

    Err(Error::NotFound {
        message: format!("Member '{}' not found in workspace", member_id),
    })
}

pub fn list_member_file_paths(
    workspace_path: &Path,
    member_ids: &[String],
) -> Result<Vec<PathBuf>> {
    if member_ids.is_empty() {
        let mut paths = load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Active))?;
        paths.extend(load_json_files_in_dir(&members_dir(
            workspace_path,
            MemberStatus::Incoming,
        ))?);
        return Ok(paths);
    }

    member_ids
        .iter()
        .map(|member_id| {
            find_member_path(workspace_path, member_id)
                .map(|(path, _)| path)
                .ok_or_else(|| Error::NotFound {
                    message: format!("Member '{}' not found in workspace", member_id),
                })
        })
        .collect()
}

pub fn load_member_file_from_path(path: &Path) -> Result<PublicKey> {
    parse_public_key_file(path)
}
