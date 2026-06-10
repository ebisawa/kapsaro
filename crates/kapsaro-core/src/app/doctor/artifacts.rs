// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::app::artifact::{list_workspace_encrypted_artifacts, load_artifact_content};
use crate::app::context::options::CommonCommandOptions;
use crate::feature::artifact::{artifact_recipient_evidence, verify_artifact_signature};
use crate::feature::trust::recipient_sets::{
    find_recipient_handle_mismatch, ArtifactRecipientEvidence, RecipientHandleMismatch,
};
use crate::format::content::EncContent;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::load_active_member_files;
use crate::model::common::RemovedRecipient;
use crate::model::public_key::PublicKey;
use crate::model::verification::SignatureVerificationProof;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

pub fn check_artifacts(
    options: &CommonCommandOptions,
    _member_handle: Option<&str>,
    workspace: &WorkspaceRoot,
) -> Result<Vec<DoctorCheck>> {
    let artifact_paths = list_workspace_encrypted_artifacts(&workspace.root_path)?;
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

fn check_artifact(
    path: &Path,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    verbose: bool,
) -> Vec<DoctorCheck> {
    let subject = DoctorSubject::Artifact(format_path_relative_to_cwd(path));
    let content = match load_artifact_for_doctor(path, &subject) {
        ArtifactContentCheck::Loaded(content) => content,
        ArtifactContentCheck::Finding(check) => return vec![check],
    };

    let mut checks = vec![check_artifact_format(&subject)];
    let proof = match check_artifact_signature(&content, &subject, verbose) {
        ArtifactSignatureCheck::Verified(proof) => *proof,
        ArtifactSignatureCheck::Finding(check) => {
            checks.push(check);
            return checks;
        }
    };
    checks.push(check_valid_artifact_signature(&subject));

    checks.extend(check_signer(&proof, active_members_by_kid, &subject));
    checks.extend(check_recipients(&content, active_members_by_kid, &subject));
    checks.extend(check_disclosure_history(&content, &subject));
    checks
}

enum ArtifactContentCheck {
    Loaded(EncContent),
    Finding(DoctorCheck),
}

fn load_artifact_for_doctor(path: &Path, subject: &DoctorSubject) -> ArtifactContentCheck {
    match load_artifact_content(path) {
        Ok(content) => ArtifactContentCheck::Loaded(content),
        Err(error) => ArtifactContentCheck::Finding(DoctorCheck::fail_with_reason_and_next_action(
            "artifacts.read",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact could not be read or parsed",
            error.format_user_message(),
            "check path, permissions, and file size",
        )),
    }
}

fn check_artifact_format(subject: &DoctorSubject) -> DoctorCheck {
    DoctorCheck::ok(
        "artifacts.format",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact format was detected",
    )
}

enum ArtifactSignatureCheck {
    Verified(Box<SignatureVerificationProof>),
    Finding(DoctorCheck),
}

fn check_artifact_signature(
    content: &EncContent,
    subject: &DoctorSubject,
    verbose: bool,
) -> ArtifactSignatureCheck {
    match verify_artifact_signature(content, verbose) {
        Ok(proof) => ArtifactSignatureCheck::Verified(Box::new(proof)),
        Err(error) => {
            ArtifactSignatureCheck::Finding(DoctorCheck::fail_with_reason_and_next_action(
                "artifact.signature",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signature verification failed",
                error.format_user_message(),
                "restore the artifact from a trusted version",
            ))
        }
    }
}

fn check_valid_artifact_signature(subject: &DoctorSubject) -> DoctorCheck {
    DoctorCheck::ok(
        "artifact.signature",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact signature is valid",
    )
}

fn check_signer(
    proof: &SignatureVerificationProof,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    let mut checks = vec![check_active_signer(proof, active_members_by_kid, subject)];
    checks.extend(check_signer_warnings(proof, subject));
    checks
}

fn check_active_signer(
    proof: &SignatureVerificationProof,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> DoctorCheck {
    match active_members_by_kid.get(&proof.kid) {
        Some(public_key) => check_known_active_signer(proof, public_key, subject),
        None => check_missing_active_signer(proof, subject),
    }
}

fn check_known_active_signer(
    proof: &SignatureVerificationProof,
    public_key: &PublicKey,
    subject: &DoctorSubject,
) -> DoctorCheck {
    if public_key.protected.subject_handle == proof.member_handle {
        return DoctorCheck::ok(
            "artifact.signer_active",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact signer is an active member",
        );
    }
    DoctorCheck::fail_with_reason_and_next_action(
        "artifact.signer_active",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact signer kid belongs to another active member",
        format!(
            "signer: {}; active member: {}",
            proof.member_handle, public_key.protected.subject_handle
        ),
        "investigate the artifact before using it",
    )
}

fn check_missing_active_signer(
    proof: &SignatureVerificationProof,
    subject: &DoctorSubject,
) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "artifact.signer_active",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact signer is not in current members/active",
        format!("signer: {}; kid: {}", proof.member_handle, proof.kid),
        "run kapsaro rewrap",
    )
}

fn check_signer_warnings(
    proof: &SignatureVerificationProof,
    subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    proof
        .warnings
        .iter()
        .map(|warning| {
            DoctorCheck::warn_with_reason_and_next_action(
                "key.expiry",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Artifact signer key has an expiry warning",
                warning,
                "run kapsaro rewrap",
            )
        })
        .collect()
}

fn check_recipients(
    content: &EncContent,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    let evidence = match check_recipient_evidence(content, subject) {
        RecipientEvidenceCheck::Loaded(evidence) => evidence,
        RecipientEvidenceCheck::Finding(check) => return vec![check],
    };

    let mut checks = Vec::new();
    if let Some(check) = check_recipient_handle_mismatch(&evidence, active_members_by_kid, subject)
    {
        checks.push(check);
    }

    let (active_kids, artifact_kids) = collect_recipient_kid_sets(&evidence, active_members_by_kid);
    checks.push(check_active_recipient_set(
        &active_kids,
        &artifact_kids,
        subject,
    ));
    checks
}

fn collect_recipient_kid_sets(
    evidence: &ArtifactRecipientEvidence,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
) -> (BTreeSet<String>, BTreeSet<String>) {
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
    (active_kids, artifact_kids)
}

enum RecipientEvidenceCheck {
    Loaded(ArtifactRecipientEvidence),
    Finding(DoctorCheck),
}

fn check_recipient_evidence(
    content: &EncContent,
    subject: &DoctorSubject,
) -> RecipientEvidenceCheck {
    match artifact_recipient_evidence(content) {
        Ok(evidence) => RecipientEvidenceCheck::Loaded(evidence),
        Err(error) => RecipientEvidenceCheck::Finding(DoctorCheck::fail_with_reason(
            "artifact.recipients_active",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact recipients could not be inspected",
            error.format_user_message(),
        )),
    }
}

fn check_recipient_handle_mismatch(
    evidence: &ArtifactRecipientEvidence,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    subject: &DoctorSubject,
) -> Option<DoctorCheck> {
    find_recipient_handle_mismatch(&evidence.recipient_set, active_members_by_kid)
        .map(|mismatch| build_recipient_handle_mismatch_check(&mismatch, subject))
}

fn build_recipient_handle_mismatch_check(
    mismatch: &RecipientHandleMismatch,
    subject: &DoctorSubject,
) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "artifact.recipient_handle",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Artifact recipient handle label conflicts with members/active",
        format!(
            "kid {} is labeled {} in artifact but {} in members/active",
            mismatch.kid, mismatch.artifact_recipient_handle, mismatch.active_member_handle
        ),
        "investigate the artifact before using it",
    )
}

fn check_active_recipient_set(
    active_kids: &BTreeSet<String>,
    artifact_kids: &BTreeSet<String>,
    subject: &DoctorSubject,
) -> DoctorCheck {
    if artifact_kids == active_kids {
        DoctorCheck::ok(
            "artifact.recipients_active",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact recipients match current active members",
        )
    } else {
        DoctorCheck::warn_with_reason_and_next_action(
            "artifact.recipients_active",
            DoctorCategory::Artifacts,
            subject.clone(),
            "Artifact recipients differ from current active members",
            format_recipient_diff(active_kids, artifact_kids),
            "run kapsaro rewrap",
        )
    }
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
            return vec![DoctorCheck::fail_with_reason(
                "disclosure_history.present",
                DoctorCategory::Artifacts,
                subject.clone(),
                "Disclosure history could not be inspected",
                error.format_user_message(),
            )];
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
    vec![DoctorCheck::warn_with_reason_and_next_action(
        "disclosure_history.present",
        DoctorCategory::Artifacts,
        subject.clone(),
        "Disclosure history is present",
        format!("{} removed recipient record(s)", removed.len()),
        "review disclosure history and rotate secret values if needed",
    )]
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
