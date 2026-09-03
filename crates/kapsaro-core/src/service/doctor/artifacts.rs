// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Doctor checks for encrypted artifacts found in the workspace.
//! Verifies format, signature, signer and recipient membership, and disclosure history for each artifact.

use std::collections::{BTreeMap, BTreeSet};

use crate::feature::artifact::{artifact_recipient_evidence, verify_artifact_signature};
use crate::feature::trust::recipient_sets::{
    find_recipient_handle_mismatch, ArtifactRecipientEvidence, RecipientHandleMismatch,
};
use crate::format::content::EncContent;
use crate::io::workspace::members::{
    load_active_member_files_at, ACTIVE_DIR_NAME, MEMBERS_DIR_NAME,
};
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::model::common::RemovedRecipient;
use crate::model::public_key::PublicKey;
use crate::model::verification::SignatureVerificationProof;
use crate::service::artifact::{
    list_workspace_encrypted_artifacts_at, load_artifact_content, ArtifactRef,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryFd;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

/// Diagnose every artifact the workspace holds.
///
/// The artifacts and the member set they are judged against are both read
/// through the descriptor the diagnosis bound to, so the whole check speaks
/// about the tree the run started in even if the workspace path is repointed
/// while it runs.
pub fn check_artifacts(workspace_dir: &AnchoredDir) -> Result<Vec<DoctorCheck>> {
    let listing = list_workspace_encrypted_artifacts_at(workspace_dir)?;
    let secrets_dir = workspace_dir.path().join(SECRETS_DIR_NAME);
    let secrets_subject = DoctorSubject::Path(format_path_relative_to_cwd(&secrets_dir));
    let mut checks = check_skipped_secrets_entries(&listing.warnings, &secrets_subject);
    if listing.artifacts.is_empty() {
        checks.push(
            DoctorCheck::warn(
                "artifacts.discovered",
                DoctorCategory::Artifacts,
                secrets_subject,
                "No encrypted artifacts found",
            )
            .with_next_action("add a secret if this workspace should contain secrets"),
        );
        return Ok(checks);
    }

    let active_members = resolve_active_member_index(workspace_dir, &mut checks);
    checks.push(DoctorCheck::ok(
        "artifacts.discovered",
        DoctorCategory::Artifacts,
        secrets_subject,
        format!("{} encrypted artifact(s) found", listing.artifacts.len()),
    ));
    for artifact in listing.artifacts {
        checks.extend(check_artifact(&artifact, &active_members));
    }
    Ok(checks)
}

/// The active member set the signer and recipient judgments are made against.
///
/// A set that could not be read is kept apart from an empty one. Judging on an
/// empty set would mark every artifact as signed by somebody who is no longer a
/// member and send the operator to rewrap, which repairs nothing when the real
/// fault is that members/active cannot be read.
enum ActiveMemberIndex {
    Loaded(BTreeMap<String, PublicKey>),
    Unreadable,
}

impl ActiveMemberIndex {
    /// The member set to judge against, absent when it could not be read.
    fn judged(&self) -> Option<&BTreeMap<String, PublicKey>> {
        match self {
            Self::Loaded(index) => Some(index),
            Self::Unreadable => None,
        }
    }
}

/// Read the member set once, reporting a failure as a finding of its own.
fn resolve_active_member_index(
    workspace_dir: &AnchoredDir,
    checks: &mut Vec<DoctorCheck>,
) -> ActiveMemberIndex {
    match load_active_member_index(workspace_dir) {
        Ok(index) => ActiveMemberIndex::Loaded(index),
        Err(error) => {
            checks.push(build_unreadable_active_members_check(
                workspace_dir,
                error.format_user_message(),
            ));
            ActiveMemberIndex::Unreadable
        }
    }
}

fn build_unreadable_active_members_check(workspace_dir: &AnchoredDir, reason: &str) -> DoctorCheck {
    let active_dir = workspace_dir
        .path()
        .join(MEMBERS_DIR_NAME)
        .join(ACTIVE_DIR_NAME);
    DoctorCheck::fail_with_reason_and_next_action(
        "artifacts.active_members",
        DoctorCategory::Artifacts,
        DoctorSubject::Path(format_path_relative_to_cwd(&active_dir)),
        "Active members could not be read, so artifact signers and recipients were not judged",
        reason,
        "repair members/active, then run the diagnosis again",
    )
}

/// Report the entries the artifact listing had to leave out.
///
/// An entry nobody can inspect is exactly the one worth naming, so it becomes a
/// finding of its own rather than disappearing behind the artifacts that were
/// readable.
fn check_skipped_secrets_entries(
    warnings: &[String],
    secrets_subject: &DoctorSubject,
) -> Vec<DoctorCheck> {
    warnings
        .iter()
        .map(|warning| {
            DoctorCheck::warn_with_reason_and_next_action(
                "artifacts.entry",
                DoctorCategory::Artifacts,
                secrets_subject.clone(),
                "Secrets entry could not be inspected",
                warning.as_str(),
                "make the entry readable, then run the diagnosis again",
            )
        })
        .collect()
}

/// Diagnose one artifact.
///
/// The format, signature and disclosure history are judged on the artifact
/// alone, so they still run when the member set is unavailable. Only the two
/// judgments that need that set are left out, and the reason they were is
/// already reported once for the whole run.
fn check_artifact(artifact: &ArtifactRef, active_members: &ActiveMemberIndex) -> Vec<DoctorCheck> {
    let subject = DoctorSubject::Artifact(format_path_relative_to_cwd(artifact.path()));
    let content = match load_artifact_for_doctor(artifact, &subject) {
        ArtifactContentCheck::Loaded(content) => content,
        ArtifactContentCheck::Finding(check) => return vec![check],
    };

    let mut checks = vec![check_artifact_format(&subject)];
    let proof = match check_artifact_signature(&content, &subject) {
        ArtifactSignatureCheck::Verified(proof) => *proof,
        ArtifactSignatureCheck::Finding(check) => {
            checks.push(check);
            return checks;
        }
    };
    checks.push(check_valid_artifact_signature(&subject));

    if let Some(active_members_by_kid) = active_members.judged() {
        checks.extend(check_signer(&proof, active_members_by_kid, &subject));
        checks.extend(check_recipients(&content, active_members_by_kid, &subject));
    }
    checks.extend(check_disclosure_history(&content, &subject));
    checks
}

enum ArtifactContentCheck {
    Loaded(EncContent),
    Finding(DoctorCheck),
}

fn load_artifact_for_doctor(
    artifact: &ArtifactRef,
    subject: &DoctorSubject,
) -> ArtifactContentCheck {
    match load_artifact_content(artifact) {
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
) -> ArtifactSignatureCheck {
    match verify_artifact_signature(content) {
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

fn load_active_member_index(workspace: &AnchoredDir) -> Result<BTreeMap<String, PublicKey>> {
    let mut index = BTreeMap::new();
    for member in load_active_member_files_at(workspace)? {
        index.insert(member.protected.kid.clone(), member);
    }
    Ok(index)
}
