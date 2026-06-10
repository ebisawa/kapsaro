// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use time::OffsetDateTime;

use crate::app::context::member::resolve_required_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{load_existing_trust_store, TrustStoreState};
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

use super::types::{DoctorCategory, DoctorCheck, DoctorStatus, DoctorSubject};

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
    log_local_state_start(&base_dir, &keystore_root, options.debug);

    let mut checks = vec![build_paths_resolved_check(&keystore_root)];
    let root_check = check_keystore_root(&keystore_root);
    let root_present = root_check.status == DoctorStatus::Ok;
    checks.push(root_check);
    if !root_present {
        return Ok(LocalStateDiagnostics { checks });
    }

    let owner = resolve_owner(options, member_handle);
    let Some(owner) = owner else {
        log_unresolved_owner(options.debug);
        checks.push(check_unresolved_keystore_owner(&base_dir));
        return Ok(LocalStateDiagnostics { checks });
    };
    log_resolved_owner(&owner, options.debug);

    checks.extend(check_member_keystore(&keystore_root, &owner, options.debug));
    Ok(LocalStateDiagnostics { checks })
}

fn log_local_state_start(base_dir: &Path, keystore_root: &Path, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[DOCTOR] local state: start home={}, keystore_root={}",
            format_path_relative_to_cwd(base_dir),
            format_path_relative_to_cwd(keystore_root)
        );
    }
}

fn build_paths_resolved_check(keystore_root: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "config.paths",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(keystore_root)),
        "Local state paths resolved",
    )
}

fn check_keystore_root(keystore_root: &Path) -> DoctorCheck {
    let subject = DoctorSubject::Path(format_path_relative_to_cwd(keystore_root));
    if is_real_dir(keystore_root) {
        return DoctorCheck::ok(
            "keystore.root",
            DoctorCategory::LocalKeystore,
            subject,
            "Keystore root is present",
        );
    }
    DoctorCheck::warn_with_next_action(
        "keystore.root",
        DoctorCategory::LocalKeystore,
        subject,
        "Keystore root does not exist",
        "create or import a local key",
    )
}

fn check_unresolved_keystore_owner(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        "Member handle could not be resolved",
        "specify --member-handle",
    )
}

fn log_unresolved_owner(debug_enabled: bool) {
    if debug_enabled {
        debug!("[DOCTOR] local state: member owner unresolved");
    }
}

fn log_resolved_owner(owner: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!("[DOCTOR] local state: member owner={owner}");
    }
}

pub fn check_trust_store(
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
    workspace: &WorkspaceRoot,
) -> Result<Vec<DoctorCheck>> {
    let base_dir = options.resolve_base_dir()?;
    let keystore_root = options.resolve_keystore_root()?;
    let Some(owner) = resolve_owner(options, member_handle) else {
        return Ok(vec![check_unresolved_trust_store_owner(&base_dir)]);
    };

    let path = get_trust_store_file_path(&base_dir, &owner);
    log_trust_store_path(&path, &owner, options.debug);
    if !path.exists() {
        return Ok(vec![check_missing_trust_store(&path)]);
    }

    let state = match load_trust_store_state(&path, &base_dir, &keystore_root, &owner) {
        TrustStoreCheck::Loaded(state) => state,
        TrustStoreCheck::Finding(check) => return Ok(vec![check]),
    };
    log_trust_store_state(&state, options.debug);

    let mut checks = vec![check_verified_trust_store(&path)];
    checks.extend(check_trust_store_permissions(&path, state.warnings));
    checks.extend(check_active_member_approvals(
        workspace.root_path.as_path(),
        &owner,
        &state.protected.known_keys,
    )?);
    Ok(checks)
}

fn check_unresolved_trust_store_owner(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(&base_dir.join("trust"))),
        "Local trust store owner could not be resolved",
        "specify --member-handle",
    )
}

fn log_trust_store_path(path: &Path, owner: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[DOCTOR] trust store: inspect path={}, owner={}",
            format_path_relative_to_cwd(path),
            owner
        );
    }
}

fn check_missing_trust_store(path: &Path) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store is missing",
        "run kapsaro member verify --approve",
    )
}

enum TrustStoreCheck {
    Loaded(TrustStoreState),
    Finding(DoctorCheck),
}

fn load_trust_store_state(
    path: &Path,
    base_dir: &Path,
    keystore_root: &Path,
    owner: &str,
) -> TrustStoreCheck {
    match load_existing_trust_store(path, base_dir, keystore_root, owner) {
        Ok(state) => TrustStoreCheck::Loaded(state),
        Err(error) => TrustStoreCheck::Finding(DoctorCheck::fail_with_reason_and_next_action(
            "trust_store.signature",
            DoctorCategory::LocalTrustStore,
            DoctorSubject::Path(format_path_relative_to_cwd(path)),
            "Local trust store is invalid",
            error.format_user_message(),
            "follow the trust store recovery procedure",
        )),
    }
}

fn log_trust_store_state(state: &TrustStoreState, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[DOCTOR] trust store: loaded known_keys={}, recipient_sets={}",
            state.protected.known_keys.len(),
            state.protected.recipient_sets.len()
        );
    }
}

fn check_verified_trust_store(path: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store is present and verified",
    )
}

fn check_trust_store_permissions(path: &Path, warnings: Vec<String>) -> Vec<DoctorCheck> {
    warnings
        .into_iter()
        .map(|warning| {
            DoctorCheck::warn_with_reason_and_next_action(
                "trust_store.permissions",
                DoctorCategory::LocalTrustStore,
                DoctorSubject::Path(format_path_relative_to_cwd(path)),
                "Local trust store permission warning",
                warning,
                "fix local trust directory permissions",
            )
        })
        .collect()
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
        checks.push(check_missing_member_keystore(member_handle));
        return checks;
    }
    checks.push(check_existing_member_keystore(member_handle));

    let active_kid = match check_active_kid(keystore_root, member_handle) {
        ActiveKidCheck::Configured(kid) => kid,
        ActiveKidCheck::Finding(check) => {
            checks.push(check);
            return checks;
        }
    };
    log_active_kid(member_handle, &active_kid, debug_enabled);

    checks.push(check_configured_active_kid(&active_kid));
    checks.push(check_private_key(keystore_root, member_handle, &active_kid));
    checks.push(check_public_key_expiry(
        keystore_root,
        member_handle,
        &active_kid,
    ));
    checks
}

enum ActiveKidCheck {
    Configured(String),
    Finding(DoctorCheck),
}

fn check_missing_member_keystore(member_handle: &str) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Member(member_handle.to_string()),
        "No key directory exists for member handle",
        "create or import a local key",
    )
}

fn check_existing_member_keystore(member_handle: &str) -> DoctorCheck {
    DoctorCheck::ok(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Member(member_handle.to_string()),
        "Member key directory exists",
    )
}

fn check_active_kid(keystore_root: &Path, member_handle: &str) -> ActiveKidCheck {
    match load_active_kid(member_handle, keystore_root) {
        Ok(Some(kid)) => ActiveKidCheck::Configured(kid),
        Ok(None) => ActiveKidCheck::Finding(check_missing_active_kid(member_handle)),
        Err(error) => ActiveKidCheck::Finding(check_unreadable_active_kid(
            member_handle,
            error.format_user_message(),
        )),
    }
}

fn check_missing_active_kid(member_handle: &str) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "keystore.active_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Member(member_handle.to_string()),
        "No active key is configured",
        "run kapsaro key activate or kapsaro key new",
    )
}

fn check_unreadable_active_kid(member_handle: &str, reason: impl Into<String>) -> DoctorCheck {
    DoctorCheck::fail_with_reason(
        "keystore.active_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Member(member_handle.to_string()),
        "Active key could not be read",
        reason,
    )
}

fn log_active_kid(member_handle: &str, active_kid: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[DOCTOR] local state: inspect active key member_handle={}, kid={}",
            member_handle,
            format_kid_half_display_lossy(active_kid)
        );
    }
}

fn check_configured_active_kid(active_kid: &str) -> DoctorCheck {
    DoctorCheck::ok(
        "keystore.active_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::General(active_kid.to_string()),
        "Active key is configured",
    )
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
        Err(error) => DoctorCheck::fail_with_reason_and_next_action(
            "keystore.private_key",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active private key cannot be loaded",
            error.format_user_message(),
            "check key backup or restore",
        ),
    }
}

fn check_public_key_expiry(keystore_root: &Path, member_handle: &str, kid: &str) -> DoctorCheck {
    let path = get_public_key_file_path_from_root(keystore_root, member_handle, kid);
    let result = load_public_key(keystore_root, member_handle, kid).and_then(|public_key| {
        check_key_expiry(&public_key.protected.expires_at, OffsetDateTime::now_utc())
    });
    build_public_key_expiry_check(&path, result)
}

fn build_public_key_expiry_check(path: &Path, result: Result<KeyExpiryStatus>) -> DoctorCheck {
    match result {
        Ok(KeyExpiryStatus::Valid) => build_valid_public_key_expiry_check(path),
        Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        }) => build_expiring_public_key_check(path, expires_at, days_remaining),
        Ok(KeyExpiryStatus::Expired { expires_at }) => {
            build_expired_public_key_check(path, expires_at)
        }
        Err(error) => DoctorCheck::fail_with_reason(
            "keystore.expiry",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(path)),
            "Active local key expiry could not be checked",
            error.format_user_message(),
        ),
    }
}

fn build_valid_public_key_expiry_check(path: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "keystore.expiry",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Active local key has sufficient validity",
    )
}

fn build_expiring_public_key_check(
    path: &Path,
    expires_at: String,
    days_remaining: i64,
) -> DoctorCheck {
    DoctorCheck::warn_with_reason_and_next_action(
        "keystore.expiry",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Active local key expiry is near",
        format!(
            "expires_at: {}; days remaining: {}",
            expires_at, days_remaining
        ),
        "plan key rotation",
    )
}

fn build_expired_public_key_check(path: &Path, expires_at: String) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "keystore.expiry",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Active local key is expired",
        format!("expires_at: {}", expires_at),
        "rotate the key before write-path commands",
    )
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
        checks.push(check_active_member_approval(&member, known_keys));
    }
    Ok(checks)
}

fn check_active_member_approval(
    member: &crate::model::public_key::PublicKey,
    known_keys: &[crate::model::trust_store::KnownKey],
) -> DoctorCheck {
    let known = known_keys.iter().any(|known| {
        known.kid == member.protected.kid && known.subject_handle == member.protected.subject_handle
    });
    if known {
        return DoctorCheck::ok(
            "trust_store.active_approval",
            DoctorCategory::LocalTrustStore,
            DoctorSubject::Member(member.protected.subject_handle.clone()),
            "Active member key is approved",
        );
    }
    DoctorCheck::warn_with_next_action(
        "trust_store.active_approval",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Member(member.protected.subject_handle.clone()),
        "Active member key is not in local approval cache",
        "run kapsaro member verify --approve",
    )
}
