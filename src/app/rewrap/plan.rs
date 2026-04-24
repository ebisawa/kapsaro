// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::trust::{derive_self_sig_x, load_read_trust_context};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_INCOMING_MEMBER_CONTEXT,
};
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::io::workspace::members::{
    ensure_workspace_member_kid_uniqueness, list_incoming_member_paths,
    load_verified_member_file_from_path,
};
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport, RewrapBatchPlan,
};

/// Resolve workspace inputs, incoming promotion candidates, and target files.
pub(crate) fn build_rewrap_batch_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    explicit_targets: &[PathBuf],
) -> Result<RewrapBatchPlan> {
    let workspace = require_workspace(options, "rewrap")?;
    ensure_workspace_member_kid_uniqueness(&workspace.root_path)?;
    let incoming_index = load_incoming_index(&workspace.root_path)?;
    let artifact_paths = collect_rewrap_target_paths(&workspace.root_path, explicit_targets)?;
    let pre_promotion_trust = load_read_trust_context(
        options,
        &workspace.root_path,
        &execution.member_id,
        Some(derive_self_sig_x(&execution.key_ctx.signing_key)),
        options.verbose,
    )?
    .trust_ctx;
    let incoming_report = build_incoming_report(&incoming_index, options.verbose)?;
    if artifact_paths.is_empty() {
        return Err(Error::NotFound {
            message:
                "No encrypted files found in workspace secrets/ and no explicit rewrap targets were provided"
                    .to_string(),
        });
    }

    Ok(RewrapBatchPlan {
        workspace_root: workspace.root_path,
        pre_promotion_trust,
        incoming_report,
        artifact_paths,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/app_rewrap_plan_test.rs"]
mod tests;

fn find_encrypted_files_in_workspace(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)
        .map_err(|e| Error::build_io_error(format!("Failed to read secrets directory: {}", e)))?;

    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_encrypted_file(path))
        .collect();
    files.sort();
    Ok(files)
}

fn is_encrypted_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(KV_ENC_EXTENSION) || name.ends_with(".json") || name.ends_with(".encrypted")
}

fn collect_rewrap_target_paths(
    workspace_root: &Path,
    explicit_targets: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeMap::new();
    let candidate_paths = if explicit_targets.is_empty() {
        find_encrypted_files_in_workspace(workspace_root)?
    } else {
        explicit_targets.to_vec()
    };
    for path in candidate_paths {
        insert_rewrap_target_path(&mut paths, path)?;
    }
    Ok(paths.into_values().collect())
}

fn insert_rewrap_target_path(paths: &mut BTreeMap<PathBuf, PathBuf>, path: PathBuf) -> Result<()> {
    let canonical = path.canonicalize().map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to resolve rewrap target {}: {}",
                format_path_relative_to_cwd(&path),
                e
            ),
            e,
        )
    })?;
    if !canonical.is_file() {
        return Err(Error::build_invalid_argument_error(format!(
            "Rewrap target must be a file: {}",
            format_path_relative_to_cwd(&path)
        )));
    }
    paths.entry(canonical).or_insert(path);
    Ok(())
}

fn build_incoming_report(
    incoming_index: &BTreeMap<String, IncomingSnapshot>,
    debug: bool,
) -> Result<Option<IncomingVerificationReport>> {
    if incoming_index.is_empty() {
        return Ok(None);
    }

    let mut report = IncomingVerificationReport::default();
    for snapshot in incoming_index.values() {
        let candidate = build_incoming_candidate(snapshot, debug)?;
        match candidate.review.category {
            IncomingVerificationCategory::BindingConfigured => {
                report.binding_configured.push(candidate);
            }
            IncomingVerificationCategory::Failed => report.failed.push(candidate),
            IncomingVerificationCategory::NotConfigured => report.not_configured.push(candidate),
            IncomingVerificationCategory::Verified => unreachable!(),
        }
    }

    Ok(Some(report))
}

fn build_incoming_candidate(
    snapshot: &IncomingSnapshot,
    debug: bool,
) -> Result<IncomingPromotionCandidate> {
    let review = match verify_public_key_for_verification_context(
        &snapshot.public_key,
        debug,
        WORKSPACE_INCOMING_MEMBER_CONTEXT,
    ) {
        Ok(_) => build_pending_review(snapshot),
        Err(error) => IncomingVerificationItem {
            member_id: snapshot.public_key.protected.member_id.clone(),
            kid: snapshot.public_key.protected.kid.clone(),
            category: IncomingVerificationCategory::Failed,
            message: format!(
                "Offline verification failed: {}",
                error.format_user_message()
            ),
            fingerprint: None,
            verified_github: None,
            github_binding_configured: github_binding_configured(&snapshot.public_key),
            attestor_pub: None,
        },
    };

    Ok(IncomingPromotionCandidate {
        review,
        source_path: snapshot.source_path.clone(),
        source_content: snapshot.source_content.clone(),
        public_key: snapshot.public_key.clone(),
    })
}

fn build_pending_review(snapshot: &IncomingSnapshot) -> IncomingVerificationItem {
    let binding_configured = github_binding_configured(&snapshot.public_key);
    let (category, message) = build_pending_review_category(binding_configured);
    let attestor_pub = snapshot
        .public_key
        .protected
        .identity
        .attestation
        .pub_
        .clone();
    let fingerprint = build_sha256_fingerprint(&attestor_pub).ok();

    IncomingVerificationItem {
        member_id: snapshot.public_key.protected.member_id.clone(),
        kid: snapshot.public_key.protected.kid.clone(),
        category,
        message,
        fingerprint,
        verified_github: None,
        github_binding_configured: binding_configured,
        attestor_pub: Some(attestor_pub),
    }
}

fn github_binding_configured(public_key: &PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

fn build_pending_review_category(
    binding_configured: bool,
) -> (IncomingVerificationCategory, String) {
    if binding_configured {
        (
            IncomingVerificationCategory::BindingConfigured,
            "GitHub binding configured; online verification will run if trust update is required"
                .to_string(),
        )
    } else {
        (
            IncomingVerificationCategory::NotConfigured,
            "No binding_claims.github_account configured".to_string(),
        )
    }
}

#[derive(Debug, Clone)]
struct IncomingSnapshot {
    source_path: PathBuf,
    source_content: String,
    public_key: PublicKey,
}

fn load_incoming_index(workspace_root: &Path) -> Result<BTreeMap<String, IncomingSnapshot>> {
    let mut index = BTreeMap::new();
    for source_path in list_incoming_member_paths(workspace_root)? {
        let public_key = load_verified_member_file_from_path(&source_path)?;
        let source_content =
            load_text_with_limit(&source_path, MAX_JSON_DOCUMENT_READ_SIZE, "PublicKey file")?;
        index.insert(
            public_key.protected.member_id.clone(),
            IncomingSnapshot {
                source_path,
                source_content,
                public_key,
            },
        );
    }
    Ok(index)
}
