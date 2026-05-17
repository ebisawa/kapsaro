use secretenv_core::api::file::VerifiedFileEncArtifact;
use secretenv_core::api::key::RecipientKeys;
use secretenv_core::api::kv::VerifiedKvEncArtifact;
use secretenv_core::api::trust::{
    KnownKeyApproval, RecipientSetApproval, TrustApproval, TrustApprovalKind,
};

fn inspect_verified_file(artifact: VerifiedFileEncArtifact) {
    let _ = artifact.inner;
    let _ = VerifiedFileEncArtifact::from_inner;
}

fn inspect_verified_kv(artifact: VerifiedKvEncArtifact) {
    let _ = artifact.content;
    let _ = artifact.inner;
    let _ = VerifiedKvEncArtifact::from_inner;
}

fn inspect_recipients(recipients: RecipientKeys) {
    let _ = recipients.keys();
}

fn inspect_trust_approval(approval: TrustApproval) {
    let _ = approval.kind;
    let _ = std::any::type_name::<TrustApprovalKind>();
    let _ = std::any::type_name::<KnownKeyApproval>();
    let _ = std::any::type_name::<RecipientSetApproval>();
}

fn main() {}
