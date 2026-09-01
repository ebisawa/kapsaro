// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local keystore and trust store diagnostics for the doctor command.
//! Opens local state once and reuses that capability across every check.

mod permissions;
mod staging;

use std::path::Path;

use time::OffsetDateTime;

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::resolution::member_handle::MemberHandleResolver;
use crate::error::{
    LOCAL_KEYSTORE_MISSING_RECOVERY, LOCAL_STATE_PATH_UNSAFE_RECOVERY,
    LOCAL_STATE_PRIVATE_KEY_EXPOSED_RECOVERY, TRUST_SIGNER_KEY_MISSING_RECOVERY,
};
use crate::feature::context::env_key::is_env_key_mode;
use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::derive_member_handle_from_path;
use crate::feature::trust::store_mutation::TrustStoreState;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::paths::{
    get_private_key_file_path_from_root, get_public_key_file_path_from_root,
};
use crate::io::trust::paths::{get_trust_store_dir, get_trust_store_file_path, TRUST_DIR_NAME};
use crate::io::workspace::members::{open_member_documents_at, MemberDocuments, MemberStatus};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::KnownKey;
use crate::support::display::format_path_for_message;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope};
use crate::support::kid::format_kid_half_display_lossy;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::shell::append_repair_command;
use crate::{Error, ErrorKind, Result};
use tracing::debug;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject, LocalStateHome};

pub(super) struct LocalStateDiagnostics {
    pub(super) checks: Vec<DoctorCheck>,
    pub(super) owner: Option<MemberHandle>,
    pub(super) keystore: Option<KeystoreAccess>,
    pub(super) home: LocalStateHome,
}

impl LocalStateDiagnostics {
    /// Diagnostics that stopped before an owner could be named.
    fn without_owner(
        checks: Vec<DoctorCheck>,
        keystore: Option<KeystoreAccess>,
        home: LocalStateHome,
    ) -> Self {
        Self {
            checks,
            owner: None,
            keystore,
            home,
        }
    }
}

/// Open the keystore root and report what the opening itself found.
///
/// Splitting this out keeps the resolution of the owner, which can end the
/// diagnosis early, separate from the checks that always run.
fn check_keystore_layout(
    base_dir: &Path,
    keystore_root: &Path,
) -> (Vec<DoctorCheck>, Option<KeystoreAccess>, LocalStateHome) {
    let mut checks = vec![build_paths_resolved_check(keystore_root)];
    let (root_check, access, home) = check_keystore_root(base_dir, keystore_root);
    checks.push(root_check);
    run_post_keystore_open_hook(access.as_ref());
    checks.extend(
        access
            .as_ref()
            .and_then(|access| check_ignored_keystore_root_entries(keystore_root, access)),
    );
    (checks, access, home)
}

pub(super) fn check_local_state(
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
) -> Result<LocalStateDiagnostics> {
    let base_dir = options.resolve_base_dir()?;
    let keystore_root = options.resolve_keystore_root()?;
    log_local_state_start(&base_dir, &keystore_root);

    let (mut checks, access, home) = check_keystore_layout(&base_dir, &keystore_root);
    checks.extend(collect_home_scoped_checks(&base_dir, &home));

    let owner = match resolve_diagnostic_owner(
        &base_dir,
        &keystore_root,
        member_handle,
        &home,
        access.as_ref(),
    ) {
        OwnerResolution::Resolved(owner) => owner,
        OwnerResolution::Unavailable(check) => {
            checks.push(check);
            return Ok(LocalStateDiagnostics::without_owner(checks, access, home));
        }
    };
    log_resolved_owner(owner.as_str());
    extend_with_member_keystore_checks(&mut checks, access.as_ref(), &owner, &keystore_root);
    Ok(LocalStateDiagnostics {
        checks,
        owner: Some(owner),
        keystore: access,
        home,
    })
}

/// Everything the local state root can be judged on without an owner, which
/// holds whether or not one turns out to be resolvable, so it is collected
/// before the owner is looked for.
fn collect_home_scoped_checks(base_dir: &Path, home: &LocalStateHome) -> Vec<DoctorCheck> {
    // The permission verdict and the ancestor-ownership finding are two
    // readings of the same directories, so the chain is walked once here and
    // handed to both.
    let ancestry = permissions::LocalStateAncestry::walk(base_dir);
    let mut checks = permissions::check_local_state_permissions(base_dir, home, &ancestry);
    checks.extend(permissions::check_local_state_ancestor_owner(
        base_dir, &ancestry,
    ));
    checks.extend(staging::check_local_state_write_residue(home));
    checks
}

/// Add the checks that need both a keystore and an owner, when there is one.
fn extend_with_member_keystore_checks(
    checks: &mut Vec<DoctorCheck>,
    access: Option<&KeystoreAccess>,
    owner: &MemberHandle,
    keystore_root: &Path,
) {
    if let Some(access) = access {
        checks.extend(collect_member_keystore_checks(access, owner, keystore_root));
    }
}

/// Owner resolution result, where every failure becomes a reported check so the
/// remaining diagnostics still run.
enum OwnerResolution {
    Resolved(MemberHandle),
    Unavailable(DoctorCheck),
}

fn resolve_diagnostic_owner(
    base_dir: &Path,
    keystore_root: &Path,
    member_handle: Option<&str>,
    home: &LocalStateHome,
    access: Option<&KeystoreAccess>,
) -> OwnerResolution {
    match resolve_owner(home.opened(), member_handle, access) {
        Ok(Some(owner)) => OwnerResolution::Resolved(owner),
        Ok(None) => {
            log_unresolved_owner();
            OwnerResolution::Unavailable(check_unresolved_keystore_owner(base_dir))
        }
        Err(error) if is_unsafe_local_state_error(&error) => OwnerResolution::Unavailable(
            build_uninspectable_keystore_member_check(keystore_root, None, &error),
        ),
        Err(error) => {
            OwnerResolution::Unavailable(build_owner_resolution_failure_check(base_dir, &error))
        }
    }
}

/// Report a member namespace the doctor could not inspect as a check and keep
/// going, so the checks after it still run.
///
/// Only the namespace being absent is left to [`check_member_keystore`] to
/// report as its own WARN. Every other failure — an unreadable member
/// directory, a lock the doctor could not take, any I/O error opening what is
/// there — is turned into a FAIL here rather than ending the whole diagnosis,
/// because a keystore doctor cannot inspect is exactly the condition it exists
/// to report.
fn collect_member_keystore_checks(
    access: &KeystoreAccess,
    owner: &MemberHandle,
    keystore_root: &Path,
) -> Vec<DoctorCheck> {
    match check_member_keystore(access, owner) {
        Ok(checks) => checks,
        Err(error) => vec![build_uninspectable_keystore_member_check(
            keystore_root,
            Some(owner),
            &error,
        )],
    }
}

// Test-only seam: runs right after the keystore is opened so a test can swap
// paths underneath and prove the checks stay bound to the opened directory.
// Compiled out of production builds.
#[cfg(test)]
thread_local! {
    static POST_KEYSTORE_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_keystore_open_hook(access: Option<&KeystoreAccess>) {
    if access.is_some() {
        POST_KEYSTORE_OPEN_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }
}

#[cfg(not(test))]
fn run_post_keystore_open_hook(_access: Option<&KeystoreAccess>) {}

#[cfg(test)]
pub(crate) fn set_post_keystore_open_hook(hook: impl FnOnce() + 'static) {
    POST_KEYSTORE_OPEN_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

fn log_local_state_start(base_dir: &Path, keystore_root: &Path) {
    debug!(
        "[DOCTOR] local state: start home={}, keystore_root={}",
        format_path_relative_to_cwd(base_dir),
        format_path_relative_to_cwd(keystore_root)
    );
}

fn build_paths_resolved_check(keystore_root: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "config.paths",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(keystore_root)),
        "Local state paths resolved",
    )
}

/// Outcome of opening the local state root, before the keystore under it.
enum LocalStateHomeProbe {
    Opened(AnchoredDir),
    Reported(DoctorCheck, LocalStateHome),
}

/// Open the local state root, reporting a root that cannot be opened at all.
fn probe_local_state_home(base_dir: &Path, subject: DoctorSubject) -> LocalStateHomeProbe {
    let home = match AnchoredDir::open(base_dir, DirectoryScope::LocalState, "local state root") {
        Ok(home) => home,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return LocalStateHomeProbe::Reported(
                build_missing_keystore_root_check(subject),
                LocalStateHome::Missing,
            );
        }
        Err(error) => {
            let reason = error.format_user_message().to_string();
            return LocalStateHomeProbe::Reported(
                build_unsafe_keystore_root_check(subject, &reason),
                LocalStateHome::Unavailable { reason },
            );
        }
    };
    LocalStateHomeProbe::Opened(home)
}

fn check_keystore_root(
    base_dir: &Path,
    keystore_root: &Path,
) -> (DoctorCheck, Option<KeystoreAccess>, LocalStateHome) {
    // The probe opens the local state root, so a root that cannot be opened is
    // named by its own path rather than by the keystore under it.
    let home_subject = DoctorSubject::Path(format_path_relative_to_cwd(base_dir));
    let home = match probe_local_state_home(base_dir, home_subject) {
        LocalStateHomeProbe::Opened(home) => home,
        LocalStateHomeProbe::Reported(check, home) => return (check, None, home),
    };
    let subject = DoctorSubject::Path(format_path_relative_to_cwd(keystore_root));
    let (check, access) = check_opened_keystore_root(&home, subject);
    (check, access, LocalStateHome::Opened(home))
}

/// Open the keystore under an already verified local state root.
fn check_opened_keystore_root(
    home: &AnchoredDir,
    subject: DoctorSubject,
) -> (DoctorCheck, Option<KeystoreAccess>) {
    match KeystoreAccess::open_from_anchored_home(home) {
        Ok(access) => (
            DoctorCheck::ok(
                "keystore.root",
                DoctorCategory::LocalKeystore,
                subject,
                "Keystore root is present",
            ),
            Some(access),
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            (build_missing_keystore_root_check(subject), None)
        }
        Err(error) => (
            build_unsafe_keystore_root_check(subject, error.format_user_message()),
            None,
        ),
    }
}

fn build_missing_keystore_root_check(subject: DoctorSubject) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "keystore.root",
        DoctorCategory::LocalKeystore,
        subject,
        "Keystore root does not exist",
        "create or import a local key",
    )
}

/// Report entries that member enumeration ignores.
/// An unsafe entry is the condition most worth reporting, so a failure to
/// enumerate becomes a check of its own rather than being dropped.
fn check_ignored_keystore_root_entries(
    keystore_root: &Path,
    access: &KeystoreAccess,
) -> Option<DoctorCheck> {
    let entries = match access.list_ignored_root_entries() {
        Ok(entries) => entries,
        Err(error) => {
            return Some(build_uninspectable_keystore_member_check(
                keystore_root,
                None,
                &error,
            ));
        }
    };
    if entries.is_empty() {
        return None;
    }
    Some(
        DoctorCheck::warn(
            "keystore.member",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(access.root())),
            "Unexpected entries in the keystore directory",
        )
        .with_reason_names(escape_ignored_entry_names(&entries))
        .with_next_action("remove or move the entry out of the keystore directory"),
    )
}

/// Prepare the ignored entry names for display.
///
/// An entry name comes from the filesystem, so whoever can write the keystore
/// directory chooses it. Each name is escaped on its own, which keeps a newline
/// or a bidirectional override inside one name instead of letting it forge or
/// reorder the reported line. The names are kept apart from here on, so a name
/// holding the separator a reader sees is still one name to a consumer.
fn escape_ignored_entry_names(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| format_path_for_message(entry))
        .collect()
}

fn build_unsafe_keystore_root_check(
    subject: DoctorSubject,
    reason: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "keystore.root",
        DoctorCategory::LocalKeystore,
        subject,
        "Keystore root cannot be opened safely",
        reason,
        "inspect the local state path and permissions",
    )
    .with_rule(Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY))
}

fn is_unsafe_local_state_error(error: &Error) -> bool {
    error.recovery() == Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY)
}

/// The one code a check reports for a failure that may carry two.
///
/// A check exists to be acted on, so the route out of the failure is what it
/// names when there is one. A failure with no route named falls back to the
/// rule it was refused under, which at least says what was checked.
fn reportable_code(error: &Error) -> Option<&str> {
    error.recovery().or_else(|| error.rule())
}

/// Report a member namespace that could not be inspected, whatever the cause.
///
/// This covers every failure the keystore member namespace can turn up, not
/// just an unsafe path: a missing owner name falls back to the keystore root
/// as the subject, and the reason and rule are always read back from `error`
/// rather than assumed from why the caller reached here.
fn build_uninspectable_keystore_member_check(
    keystore_root: &Path,
    owner: Option<&MemberHandle>,
    error: &Error,
) -> DoctorCheck {
    let subject = owner.map_or_else(
        || DoctorSubject::Path(format_path_relative_to_cwd(keystore_root)),
        |owner| DoctorSubject::Member(owner.to_string()),
    );
    DoctorCheck::fail_with_reason_and_next_action(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        subject,
        "Keystore member namespace cannot be inspected safely",
        error.format_user_message(),
        "inspect the local keystore entries",
    )
    .with_rule(reportable_code(error))
}

fn build_owner_resolution_failure_check(base_dir: &Path, error: &Error) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "keystore.member",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        "Member handle could not be resolved",
        error.format_user_message(),
        "fix the member handle configuration or specify --member-handle",
    )
    .with_rule(reportable_code(error))
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

fn log_unresolved_owner() {
    debug!("[DOCTOR] local state: member owner unresolved");
}

fn log_resolved_owner(owner: &str) {
    debug!("[DOCTOR] local state: member owner={owner}");
}

pub(super) fn check_trust_store(
    options: &CommonCommandOptions,
    owner: Option<&MemberHandle>,
    workspace: &AnchoredDir,
    keystore: Option<&KeystoreAccess>,
    home: &LocalStateHome,
) -> Result<Vec<DoctorCheck>> {
    let base_dir = options.resolve_base_dir()?;
    let Some(owner) = owner else {
        return Ok(vec![check_unresolved_trust_store_owner(&base_dir)]);
    };

    let path = get_trust_store_file_path(&base_dir, owner);
    log_trust_store_path(&path, owner.as_str());
    let state = match load_trust_store_state(&path, home, keystore, owner.as_str()) {
        TrustStoreCheck::Loaded(state) => state,
        TrustStoreCheck::Missing => return Ok(vec![check_missing_trust_store(&path)]),
        TrustStoreCheck::Finding(check) => return Ok(vec![check]),
    };
    log_trust_store_state(&state);

    let mut checks = vec![check_verified_trust_store(&path)];
    checks.extend(check_active_member_approvals(
        workspace,
        owner.as_str(),
        &state.protected.known_keys,
    )?);
    Ok(checks)
}

fn check_unresolved_trust_store_owner(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(&get_trust_store_dir(base_dir))),
        "Local trust store owner could not be resolved",
        "specify --member-handle",
    )
}

fn log_trust_store_path(path: &Path, owner: &str) {
    debug!(
        "[DOCTOR] trust store: inspect path={}, owner={}",
        format_path_relative_to_cwd(path),
        owner
    );
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
    Missing,
    Finding(DoctorCheck),
}

fn load_trust_store_state(
    path: &Path,
    home: &LocalStateHome,
    keystore: Option<&KeystoreAccess>,
    owner: &str,
) -> TrustStoreCheck {
    let base = match home {
        LocalStateHome::Opened(base) => base,
        LocalStateHome::Missing => return TrustStoreCheck::Missing,
        LocalStateHome::Unavailable { reason } => {
            return TrustStoreCheck::Finding(build_unavailable_trust_store_check(path, reason));
        }
    };
    let loaded = MemberHandle::try_from(owner).and_then(|owner| {
        let trust_dir = open_optional_child_dir(base, TRUST_DIR_NAME)?;
        load_optional_trust_store(base, trust_dir.as_ref(), &owner, keystore)
    });
    match loaded {
        Ok(Some(state)) => TrustStoreCheck::Loaded(state),
        Ok(None) => TrustStoreCheck::Missing,
        Err(error) => TrustStoreCheck::Finding(classify_trust_store_failure(path, &error)),
    }
}

/// Turn a trust store load failure into the check that names its cause.
///
/// The recovery route is what each condition is recognised by. It is a
/// namespace of its own, so a code read here was attached as the route out of
/// this failure and cannot be a validation rule that happens to share its name.
fn classify_trust_store_failure(path: &Path, error: &Error) -> DoctorCheck {
    if error.recovery() == Some(LOCAL_KEYSTORE_MISSING_RECOVERY) {
        return build_missing_trust_store_keystore_check(path, error);
    }
    if error.recovery() == Some(TRUST_SIGNER_KEY_MISSING_RECOVERY) {
        return build_missing_trust_signer_key_check(path, error);
    }
    if is_unsafe_local_state_error(error) {
        return build_unavailable_trust_store_check(path, error.format_user_message());
    }
    DoctorCheck::fail_with_reason_and_next_action(
        "trust_store.integrity",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store is invalid",
        error.format_user_message(),
        "follow the trust store recovery procedure",
    )
    .with_rule(reportable_code(error))
}

fn build_missing_trust_store_keystore_check(path: &Path, error: &Error) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "trust_store.integrity",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store cannot be verified without the local keystore",
        error.format_user_message(),
        "restore the local keystore or select the correct home",
    )
    .with_rule(reportable_code(error))
}

fn build_missing_trust_signer_key_check(path: &Path, error: &Error) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "trust_store.integrity",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store signer key is unavailable",
        error.format_user_message(),
        "restore the signer public key or follow the trust store recovery procedure",
    )
    .with_rule(reportable_code(error))
}

fn build_unavailable_trust_store_check(path: &Path, reason: &str) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "trust_store.integrity",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store state is unavailable",
        reason,
        "inspect the local state path and permissions",
    )
    .with_rule(Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY))
}

fn log_trust_store_state(state: &TrustStoreState) {
    debug!(
        "[DOCTOR] trust store: loaded known_keys={}, recipient_sets={}",
        state.protected.known_keys.len(),
        state.protected.recipient_sets.len()
    );
}

fn check_verified_trust_store(path: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Local trust store is present and verified",
    )
}

fn resolve_owner(
    home: Option<&AnchoredDir>,
    member_handle: Option<&str>,
    keystore: Option<&KeystoreAccess>,
) -> Result<Option<MemberHandle>> {
    if let Some(member_handle) = member_handle {
        return MemberHandle::try_from(member_handle).map(Some);
    }
    if is_env_key_mode() {
        return Ok(None);
    }
    MemberHandleResolver::fixed(&GlobalConfigSnapshot::for_home(home), keystore).resolve(None)
}

fn check_member_keystore(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
) -> Result<Vec<DoctorCheck>> {
    let mut checks = Vec::new();
    // The namespace is opened under the handle rather than looked for in a
    // listing of the keystore root. The open refuses a symlink or a file
    // standing where the member directory belongs and says so, while a listing
    // that keeps directories alone answers that the member is simply absent and
    // leaves the entry somebody else placed there unreported.
    if access.open_member(member_handle)?.is_none() {
        checks.push(check_missing_member_keystore(member_handle.as_str()));
        return Ok(checks);
    }
    checks.push(check_existing_member_keystore(member_handle.as_str()));

    let active_kid = match check_active_kid(access, member_handle)? {
        ActiveKidCheck::Configured(kid) => kid,
        ActiveKidCheck::Finding(check) => {
            checks.push(check);
            return Ok(checks);
        }
    };
    log_active_kid(member_handle.as_str(), active_kid.as_str());

    checks.push(check_configured_active_kid(active_kid.as_str()));
    checks.push(check_private_key(access, member_handle, &active_kid));
    checks.push(check_public_key_expiry(access, member_handle, &active_kid));
    Ok(checks)
}

enum ActiveKidCheck {
    Configured(Kid),
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

fn check_active_kid(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
) -> Result<ActiveKidCheck> {
    match access.load_active_kid(member_handle) {
        Ok(Some(kid)) => Ok(ActiveKidCheck::Configured(kid)),
        Ok(None) => Ok(ActiveKidCheck::Finding(check_missing_active_kid(
            member_handle.as_str(),
        ))),
        Err(error) if is_unsafe_local_state_error(&error) => Err(error),
        Err(error) => Ok(ActiveKidCheck::Finding(check_unreadable_active_kid(
            member_handle.as_str(),
            error.format_user_message(),
        ))),
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

fn log_active_kid(member_handle: &str, active_kid: &str) {
    debug!(
        "[DOCTOR] local state: inspect active key member_handle={}, kid={}",
        member_handle,
        format_kid_half_display_lossy(active_kid)
    );
}

fn check_configured_active_kid(active_kid: &str) -> DoctorCheck {
    DoctorCheck::ok(
        "keystore.active_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::General(active_kid.to_string()),
        "Active key is configured",
    )
}

fn check_private_key(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: &Kid,
) -> DoctorCheck {
    let path = get_private_key_file_path_from_root(access.root(), member_handle, kid);
    match access.load_private_key(member_handle, kid) {
        Ok(_) => DoctorCheck::ok(
            "keystore.private_key",
            DoctorCategory::LocalKeystore,
            DoctorSubject::Path(format_path_relative_to_cwd(&path)),
            "Active private key can be loaded",
        ),
        Err(error) => build_unloadable_private_key_check(&path, &error),
    }
}

/// Report a private key the command could not read, naming the right repair.
///
/// A key others can reach is refused rather than handed out, and the operator
/// repairs that with one `chmod`. The key itself is present and intact, so
/// sending them to a backup would have them restore over a file that is fine.
/// Every other failure leaves the stored key in doubt and keeps that route.
fn build_unloadable_private_key_check(path: &Path, error: &Error) -> DoctorCheck {
    let (message, next_action) = if is_exposed_private_key_error(error) {
        (
            "Active private key is reachable by other users and was not read",
            append_repair_command(
                "restrict the private key file to owner-only access",
                "chmod 0600",
                path,
            ),
        )
    } else {
        (
            "Active private key cannot be loaded",
            "check key backup or restore".to_string(),
        )
    };
    DoctorCheck::fail_with_reason_and_next_action(
        "keystore.private_key",
        DoctorCategory::LocalKeystore,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        message,
        error.format_user_message(),
        next_action,
    )
    .with_rule(reportable_code(error))
}

/// Whether the mode of the key file itself is what stopped the read.
///
/// The refusal carries a rule of its own, so the two failures are told apart by
/// what the read reported rather than by inspecting the entry a second time. A
/// link standing where the key document belongs is an unsafe path and keeps its
/// own rule, which is what stops it being offered a `chmod` that repairs
/// nothing.
fn is_exposed_private_key_error(error: &Error) -> bool {
    error.recovery() == Some(LOCAL_STATE_PRIVATE_KEY_EXPOSED_RECOVERY)
}

fn check_public_key_expiry(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: &Kid,
) -> DoctorCheck {
    let path = get_public_key_file_path_from_root(access.root(), member_handle, kid);
    let result = access
        .load_public_key(member_handle, kid)
        .and_then(|public_key| {
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
        )
        .with_rule(reportable_code(&error)),
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

/// Report which active members the local trust store has approved.
///
/// The member set is read through the descriptor this run bound to, so the
/// members judged here are the ones the diagnosis started with even if the
/// workspace path is repointed while it runs.
///
/// Every document is read on its own. Reading the whole set at once would end
/// the diagnosis at the first document that will not parse, and the report
/// gathered up to that point — the keystore, the permissions, the members —
/// would be dropped for a single error naming one file.
fn check_active_member_approvals(
    workspace: &AnchoredDir,
    owner: &str,
    known_keys: &[KnownKey],
) -> Result<Vec<DoctorCheck>> {
    let documents = open_member_documents_at(workspace, MemberStatus::Active)?;
    let mut checks = Vec::new();
    for name in documents.names() {
        checks.extend(check_member_document_approval(
            &documents, name, owner, known_keys,
        ));
    }
    Ok(checks)
}

/// Judge one active member document against the approval cache.
///
/// A document that will not load is reported as an approval that went
/// unchecked. The document itself is already a failure of the member file
/// checks, so naming it a second time would say one broken file twice.
fn check_member_document_approval(
    documents: &MemberDocuments,
    name: &str,
    owner: &str,
    known_keys: &[KnownKey],
) -> Option<DoctorCheck> {
    let path = documents.document_path(name);
    let member = match documents.load(name) {
        Ok(member) => member,
        Err(error) => {
            return Some(build_unchecked_member_approval(&path, &error));
        }
    };
    if member.protected.subject_handle == owner {
        return None;
    }
    Some(check_active_member_approval(&member, known_keys))
}

fn build_unchecked_member_approval(path: &Path, error: &Error) -> DoctorCheck {
    DoctorCheck::skip(
        "trust_store.active_approval",
        DoctorCategory::LocalTrustStore,
        DoctorSubject::Member(derive_member_handle_from_path(path)),
        "Active member approval was not checked",
    )
    .with_reason(error.format_user_message())
    .with_next_action("repair the member file, then run kapsaro doctor again")
}

fn check_active_member_approval(member: &PublicKey, known_keys: &[KnownKey]) -> DoctorCheck {
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
