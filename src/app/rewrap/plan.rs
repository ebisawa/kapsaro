// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::trust::RewrapInputPolicy;
use crate::app::trust::{current_self_sig_x, CommandTrustSnapshot, WorkspaceMemberSnapshot};
use crate::feature::verify::public_key::verify_public_key_for_verification;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::io::workspace::members::{
    ensure_workspace_member_kid_uniqueness, list_incoming_member_paths, load_member_file_from_path,
};
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::{encrypted_file_read_limit, MAX_JSON_DOCUMENT_READ_SIZE};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport, RewrapArtifactSnapshot, RewrapBatchPlan,
};

/// Resolve workspace inputs, incoming promotion candidates, and target files.
pub(crate) fn build_rewrap_batch_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
) -> Result<RewrapBatchPlan> {
    let workspace = require_workspace(options, "rewrap")?;
    ensure_workspace_member_kid_uniqueness(&workspace.root_path)?;
    let incoming_index = load_incoming_index(&workspace.root_path)?;
    let artifact_snapshots = load_encrypted_file_snapshots(&workspace.root_path)?;
    let workspace_members = WorkspaceMemberSnapshot::load(&workspace.root_path, options.verbose)?;
    let pre_promotion_trust = CommandTrustSnapshot::<RewrapInputPolicy>::from_workspace_members(
        options,
        workspace_members,
        &execution.member_id,
        Some(current_self_sig_x(&execution.key_ctx.signing_key)),
    )?
    .trust_context()
    .clone();
    let incoming_report = build_incoming_report(&incoming_index, options.verbose)?;
    if artifact_snapshots.is_empty() {
        return Err(Error::NotFound {
            message: "No encrypted files found in workspace secrets/".to_string(),
        });
    }

    Ok(RewrapBatchPlan {
        workspace_root: workspace.root_path,
        pre_promotion_trust,
        incoming_report,
        artifact_snapshots,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/app_rewrap_plan_test.rs"]
mod tests;

fn find_encrypted_files_in_workspace(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)
        .map_err(|e| Error::io(format!("Failed to read secrets directory: {}", e)))?;

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

fn load_encrypted_file_snapshots(workspace_root: &Path) -> Result<Vec<RewrapArtifactSnapshot>> {
    find_encrypted_files_in_workspace(workspace_root)?
        .into_iter()
        .map(|file_path| {
            let content = load_text_with_limit(
                &file_path,
                encrypted_file_read_limit(&file_path),
                "encrypted artifact",
            )?;
            Ok(RewrapArtifactSnapshot { file_path, content })
        })
        .collect()
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
    let review = match verify_public_key_for_verification(&snapshot.public_key, debug) {
        Ok(_) => build_pending_review(snapshot),
        Err(error) => IncomingVerificationItem {
            member_id: snapshot.public_key.protected.member_id.clone(),
            kid: snapshot.public_key.protected.kid.clone(),
            category: IncomingVerificationCategory::Failed,
            message: format!("Offline verification failed: {}", error.user_message()),
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
    let (category, message) = classify_pending_review(binding_configured);
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

fn classify_pending_review(binding_configured: bool) -> (IncomingVerificationCategory, String) {
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
        let public_key = load_member_file_from_path(&source_path)?;
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
