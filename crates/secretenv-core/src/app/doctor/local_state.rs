// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use time::OffsetDateTime;

use crate::app::context::member::resolve_required_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_existing_trust_store;
use crate::feature::context::env_key::is_env_key_mode;
use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::paths::{
    get_private_key_file_path_from_root, get_public_key_file_path_from_root,
};
use crate::io::keystore::storage::{load_private_key, load_public_key};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::load_active_member_files;
use crate::support::kid::format_kid_half_display_lossy;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;
use tracing::debug;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

use crate::support::fs::policy::is_real_dir;

pub struct LocalStateDiagnostics {
    pub checks: Vec<DoctorCheck>,
}

pub fn check_local_state(
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
) -> Result<LocalStateDiagnostics> {
    let base_dir = options.resolve_base_dir()?;
    let keystore_root = options.resolve_keystore_root()?;
    if options.debug {
        debug!(
            "[DOCTOR] local state: start home={}, keystore_root={}",
            format_path_relative_to_cwd(&base_dir),
            format_path_relative_to_cwd(&keystore_root)
        );
    }
    let mut checks = vec![DoctorCheck::ok(
        "config.paths",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(&keystore_root)),
        "Local state paths resolved",
    )];

    if !is_real_dir(&keystore_root) {
        checks.push(
            DoctorCheck::warn(
                "keystore.root",
                DoctorCategory::LocalKeystore,
                DoctorSubject::Path(format_path_relative_to_cwd(&keystore_root)),
                "Keystore root does not exist",
            )
            .with_next_action("create or import a local key"),
        );
        return Ok(LocalStateDiagnostics { checks });
    }
    checks.push(DoctorCheck::ok(
        "keystore.root",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(&keystore_root)),
        "Keystore root is present",
    ));

    let owner = resolve_owner(options, member_handle);
    let Some(owner) = owner else {
        if options.debug {
            debug!("[DOCTOR] local state: member owner unresolved");
        }
        checks.push(
            DoctorCheck::warn(
                "keystore.member",
                DoctorCategory::LocalKeystore,
                DoctorSubject::Path(format_path_relative_to_cwd(&base_dir)),
                "Member handle could not be resolved",
            )
            .with_next_action("specify --member-handle"),
        );
        return Ok(LocalStateDiagnostics { checks });
    };
    if options.debug {
        debug!("[DOCTOR] local state: member owner={owner}");
    }

    checks.extend(check_member_keystore(&keystore_root, &owner, options.debug));
    Ok(LocalStateDiagnostics { checks })
}

pub fn check_trust_store(
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
    workspace: &WorkspaceRoot,
) -> Result<Vec<DoctorCheck>> {
    let base_dir = options.resolve_base_dir()?;
    let keystore_root = options.resolve_keystore_root()?;
    let Some(owner) = resolve_owner(options, member_handle) else {
        return Ok(vec![DoctorCheck::warn(
            "trust_store.present",
            DoctorCategory::LocalTrustStore,
            DoctorSubject::Path(format_path_relative_to_cwd(&base_dir.join("trust"))),
            "Local trust store owner could not be resolved",
        )
        .with_next_action("specify --member-handle")]);
    };

    let path = get_trust_store_file_path(&base_dir, &owner);
    if options.debug {
        debug!(
            "[DOCTOR] trust store: inspect path={}, owner={}",
            format_path_relative_to_cwd(&path),
            owner
        );
    }
    if !path.exists() {
        return Ok(vec![DoctorCheck::warn(
            "trust_store.present",
            DoctorCategory::LocalTrustStore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Local trust store is missing",
        )
        .with_next_action("run secretenv member verify --approve")]);
    }

    let state = match load_existing_trust_store(&path, &base_dir, &keystore_root, &owner) {
        Ok(state) => state,
        Err(error) => {
            return Ok(vec![DoctorCheck::fail(
                "trust_store.signature",
                DoctorCategory::LocalTrustStore,
                DoctorSubject::Path(format_path_relative_to_cwd(&path)),
                "Local trust store is invalid",
            )
            .with_reason(error.format_user_message())
            .with_next_action("follow the trust store recovery procedure")]);
        }
    };
    if options.debug {
        debug!(
            "[DOCTOR] trust store: loaded known_keys={}, recipient_sets={}",
            state.protected.known_keys.len(),
            state.protected.recipient_sets.len()
        );
    }

    let mut checks = vec![DoctorCheck::ok(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(&path)),
        "Local trust store is present and verified",
    )];
    checks.extend(state.warnings.into_iter().map(|warning| {
        DoctorCheck::warn(
            "trust_store.permissions",
            DoctorCategory::LocalTrustStore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Local trust store permission warning",
        )
        .with_reason(warning)
        .with_next_action("fix local trust directory permissions")
    }));
    checks.extend(check_active_member_approvals(
        workspace.root_path.as_path(),
        &owner,
        &state.protected.known_keys,
    )?);
    Ok(checks)
}

fn resolve_owner(options: &CommonCommandOptions, member_handle: Option<&str>) -> Option<String> {
    if let Some(member_handle) = member_handle {
        return Some(member_handle.to_string());
    }
    if is_env_key_mode() {
        return None;
    }
    resolve_required_member(options, None).ok()
}

fn check_member_keystore(
    keystore_root: &Path,
    member_handle: &str,
    debug_enabled: bool,
) -> Vec<DoctorCheck> {
    let member_dir = keystore_root.join(member_handle);
    let mut checks = Vec::new();
    if !is_real_dir(&member_dir) {
        checks.push(
            DoctorCheck::warn(
                "keystore.member",
                DoctorCategory::LocalKeystore,
                DoctorSubject::Member(member_handle.to_string()),
                "No key directory exists for member handle",
            )
            .with_next_action("create or import a local key"),
        );
        return checks;
    }
    checks.push(DoctorCheck::ok(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Member(member_handle.to_string()),
        "Member key directory exists",
    ));

    let active_kid = match load_active_kid(member_handle, keystore_root) {
        Ok(Some(kid)) => kid,
        Ok(None) => {
            checks.push(
                DoctorCheck::warn(
                    "keystore.active_key",
                    DoctorCategory::LocalKeystore,
                    DoctorSubject::Member(member_handle.to_string()),
                    "No active key is configured",
                )
                .with_next_action("run secretenv key activate or secretenv key new"),
            );
            return checks;
        }
        Err(error) => {
            checks.push(
                DoctorCheck::fail(
                    "keystore.active_key",
                    DoctorCategory::LocalKeystore,
                    DoctorSubject::Member(member_handle.to_string()),
                    "Active key could not be read",
                )
                .with_reason(error.format_user_message()),
            );
            return checks;
        }
    };
    if debug_enabled {
        debug!(
            "[DOCTOR] local state: inspect active key member_handle={}, kid={}",
            member_handle,
            format_kid_half_display_lossy(&active_kid)
        );
    }

    checks.push(DoctorCheck::ok(
        "keystore.active_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::General(active_kid.clone()),
        "Active key is configured",
    ));
    checks.push(check_private_key(keystore_root, member_handle, &active_kid));
    checks.push(check_public_key_expiry(
        keystore_root,
        member_handle,
        &active_kid,
    ));
    checks
}

fn check_private_key(keystore_root: &Path, member_handle: &str, kid: &str) -> DoctorCheck {
    let path = get_private_key_file_path_from_root(keystore_root, member_handle, kid);
    match load_private_key(keystore_root, member_handle, kid) {
        Ok(_) => DoctorCheck::ok(
            "keystore.private_key",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active private key can be loaded",
        ),
        Err(error) => DoctorCheck::fail(
            "keystore.private_key",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active private key cannot be loaded",
        )
        .with_reason(error.format_user_message())
        .with_next_action("check key backup or restore"),
    }
}

fn check_public_key_expiry(keystore_root: &Path, member_handle: &str, kid: &str) -> DoctorCheck {
    let path = get_public_key_file_path_from_root(keystore_root, member_handle, kid);
    match load_public_key(keystore_root, member_handle, kid).and_then(|public_key| {
        check_key_expiry(&public_key.protected.expires_at, OffsetDateTime::now_utc())
    }) {
        Ok(KeyExpiryStatus::Valid) => DoctorCheck::ok(
            "keystore.expiry",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active local key has sufficient validity",
        ),
        Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        }) => DoctorCheck::warn(
            "keystore.expiry",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active local key expiry is near",
        )
        .with_reason(format!(
            "expires_at: {}; days remaining: {}",
            expires_at, days_remaining
        ))
        .with_next_action("plan key rotation"),
        Ok(KeyExpiryStatus::Expired { expires_at }) => DoctorCheck::fail(
            "keystore.expiry",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active local key is expired",
        )
        .with_reason(format!("expires_at: {}", expires_at))
        .with_next_action("rotate the key before write-path commands"),
        Err(error) => DoctorCheck::fail(
            "keystore.expiry",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active local key expiry could not be checked",
        )
        .with_reason(error.format_user_message()),
    }
}

fn check_active_member_approvals(
    workspace_root: &Path,
    owner: &str,
    known_keys: &[crate::model::trust_store::KnownKey],
) -> Result<Vec<DoctorCheck>> {
    let mut checks = Vec::new();
    for member in load_active_member_files(workspace_root)? {
        if member.protected.subject_handle == owner {
            continue;
        }
        let known = known_keys.iter().any(|known| {
            known.kid == member.protected.kid
                && known.subject_handle == member.protected.subject_handle
        });
        if known {
            checks.push(DoctorCheck::ok(
                "trust_store.active_approval",
                DoctorCategory::LocalTrustStore,
                DoctorSubject::Member(member.protected.subject_handle),
                "Active member key is approved",
            ));
        } else {
            checks.push(
                DoctorCheck::warn(
                    "trust_store.active_approval",
                    DoctorCategory::LocalTrustStore,
                    DoctorSubject::Member(member.protected.subject_handle),
                    "Active member key is not in local approval cache",
                )
                .with_next_action("run secretenv member verify --approve"),
            );
        }
    }
    Ok(checks)
}
