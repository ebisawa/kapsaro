// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::feature::trust::recipient_sets::{
    encrypted_content_recipient_evidence, find_recipient_handle_mismatch,
};
use crate::feature::verify::file::verify_file_content;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::EncContent;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::load_active_member_files;
use crate::model::common::RemovedRecipient;
use crate::model::public_key::PublicKey;
use crate::model::verification::SignatureVerificationProof;
use crate::support::fs::{list_dir, load_text_with_limit};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

pub fn check_artifacts(
    options: &CommonCommandOptions,
    _member_handle: Option<&str>,
    workspace: &WorkspaceRoot,
) -> Result<Vec<DoctorCheck>> {
    let artifact_paths = find_encrypted_files_in_workspace(&workspace.root_path)?;
    if artifact_paths.is_empty() {
        return Ok(vec![DoctorCheck::warn(
            "artifacts.discovered",
            DoctorCategory::Artifacts,
            DoctorSubject::Path(format_path_relative_to_cwd(&workspace.secrets_dir())),
            "No encrypted artifacts found",
        )
        .with_next_action(
            "add a secret if this workspace should contain secrets",
        )]);
    }

    let active_members_by_kid = load_active_member_index(&workspace.root_path).unwrap_or_default();
    let mut checks = vec![DoctorCheck::ok(
        "artifacts.discovered",
        DoctorCategory::Artifacts,
        DoctorSubject::Path(format_path_relative_to_cwd(&workspace.secrets_dir())),
        format!("{} encrypted artifact(s) found", artifact_paths.len()),
    )];
    for path in artifact_paths {
        checks.extend(check_artifact(&path, &active_members_by_kid, options.debug));
    }
    Ok(checks)
}

fn find_encrypted_files_in_workspace(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)?;
    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_encrypted_file(path))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
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

fn check_artifact(
    path: &Path,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    verbose: bool,
) -> Vec<DoctorCheck> {
    let subject = DoctorSubject::Artifact(format_path_relative_to_cwd(path));
    let content = match load_artifact_content(path) {
        Ok(content) => content,
        Err(error) => {
            return vec![DoctorCheck::fail(
                "artifacts.read",
                DoctorCategory::Artifacts,
                subject,
                "Artifact could not be read or parsed",
            )
            .with_reason(error.format_user_message())
            .with_next_action("check path, permissions, and file size")];
        }
    };

    let mut checks = vec![DoctorCheck::ok(
        "artifacts.format",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact format was detected",
    )];

    let proof = match verify_signature(&content, verbose) {
        Ok(proof) => {
            checks.push(DoctorCheck::ok(
                "artifact.signature",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signature is valid",
            ));
            proof
        }
        Err(error) => {
            checks.push(
                DoctorCheck::fail(
                    "artifact.signature",
                    DoctorCategory::Artifacts,
                    subject.clone(),
                    "Artifact signature verification failed",
                )
                .with_reason(error.format_user_message())
                .with_next_action("restore the artifact from a trusted version"),
            );
            return checks;
        }
    };

    checks.extend(check_signer(&proof, active_members_by_kid, &subject));
    checks.extend(check_recipients(&content, active_members_by_kid, &subject));
    checks.extend(check_disclosure_history(&content, &subject));
    checks
}

fn load_artifact_content(path: &Path) -> Result<EncContent> {
    let display = format_path_relative_to_cwd(path);
    let content = load_text_with_limit(
        path,
        resolve_encrypted_artifact_read_limit(path),
        "encrypted artifact",
    )?;
    EncContent::detect_with_source(content, display)
}

fn verify_signature(content: &EncContent, verbose: bool) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(content) => Ok(verify_file_content(content, verbose)?.proof),
        EncContent::KvEnc(content) => Ok(verify_kv_content(content, verbose)?.proof),
    }
}

fn check_signer(
    proof: &SignatureVerificationProof,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    match active_members_by_kid.get(&proof.kid) {
        Some(public_key) if public_key.protected.subject_handle == proof.member_handle => {
            checks.push(DoctorCheck::ok(
                "artifact.signer_active",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signer is an active member",
            ));
        }
        Some(public_key) => checks.push(
            DoctorCheck::fail(
                "artifact.signer_active",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signer kid belongs to another active member",
            )
            .with_reason(format!(
                "signer: {}; active member: {}",
                proof.member_handle, public_key.protected.subject_handle
            ))
            .with_next_action("investigate the artifact before using it"),
        ),
        None => checks.push(
            DoctorCheck::fail(
                "artifact.signer_active",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signer is not in current members/active",
            )
            .with_reason(format!(
                "signer: {}; kid: {}",
                proof.member_handle, proof.kid
            ))
            .with_next_action("run secretenv rewrap"),
        ),
    }
    for warning in &proof.warnings {
        checks.push(
            DoctorCheck::warn(
                "key.expiry",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signer key has an expiry warning",
            )
            .with_reason(warning)
            .with_next_action("run secretenv rewrap"),
        );
    }
    checks
}

fn check_recipients(
    content: &EncContent,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    let evidence = match encrypted_content_recipient_evidence(content) {
        Ok(evidence) => evidence,
        Err(error) => {
            return vec![DoctorCheck::fail(
                "artifact.recipients_active",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact recipients could not be inspected",
            )
            .with_reason(error.format_user_message())];
        }
    };

    let mut checks = Vec::new();
    if let Some(mismatch) =
        find_recipient_handle_mismatch(&evidence.recipient_set, active_members_by_kid)
    {
        checks.push(
            DoctorCheck::fail(
                "artifact.recipient_handle",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact recipient handle label conflicts with members/active",
            )
            .with_reason(format!(
                "kid {} is labeled {} in artifact but {} in members/active",
                mismatch.kid, mismatch.artifact_recipient_handle, mismatch.active_member_handle
            ))
            .with_next_action("investigate the artifact before using it"),
        );
    }

    let active_kids = active_members_by_kid
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let artifact_kids = evidence
        .recipient_set
        .recipient_kids()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if artifact_kids == active_kids {
        checks.push(DoctorCheck::ok(
            "artifact.recipients_active",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact recipients match current active members",
        ));
    } else {
        checks.push(
            DoctorCheck::warn(
                "artifact.recipients_active",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact recipients differ from current active members",
            )
            .with_reason(format_recipient_diff(&active_kids, &artifact_kids))
            .with_next_action("run secretenv rewrap"),
        );
    }
    checks
}

fn format_recipient_diff(active: &BTreeSet<String>, artifact: &BTreeSet<String>) -> String {
    let missing = active.difference(artifact).cloned().collect::<Vec<_>>();
    let stale = artifact.difference(active).cloned().collect::<Vec<_>>();
    format!(
        "missing active kids: {:?}; stale kids: {:?}",
        missing, stale
    )
}

fn check_disclosure_history(content: &EncContent, subject: &DoctorSubject) -> Vec<DoctorCheck> {
    let removed = match removed_recipients(content) {
        Ok(removed) => removed,
        Err(error) => {
            return vec![DoctorCheck::fail(
                "disclosure_history.present",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Disclosure history could not be inspected",
            )
            .with_reason(error.format_user_message())];
        }
    };
    if removed.is_empty() {
        return vec![DoctorCheck::ok(
            "disclosure_history.empty",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Disclosure history is empty",
        )];
    }
    vec![DoctorCheck::warn(
        "disclosure_history.present",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Disclosure history is present",
    )
    .with_reason(format!("{} removed recipient record(s)", removed.len()))
    .with_next_action("review disclosure history and rotate secret values if needed")]
}

fn removed_recipients(content: &EncContent) -> Result<Vec<RemovedRecipient>> {
    Ok(match content {
        EncContent::FileEnc(content) => content
            .parse()?
            .protected
            .removed_recipients
            .unwrap_or_default(),
        EncContent::KvEnc(content) => content.parse()?.wrap.removed_recipients.unwrap_or_default(),
    })
}

fn load_active_member_index(workspace_root: &Path) -> Result<BTreeMap<String, PublicKey>> {
    let mut index = BTreeMap::new();
    for member in load_active_member_files(workspace_root)? {
        index.insert(member.protected.kid.clone(), member);
    }
    Ok(index)
}
