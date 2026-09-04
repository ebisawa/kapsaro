// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON view construction for semantic inspect metadata.
//! Keeps the command's wire-facing JSON shape in the CLI presentation layer.

use kapsaro_core::api::inspect::{
    ArtifactSignatureMetadata, BindingClaimsMetadata, FileEncInspectMetadata, FilePayloadMetadata,
    IdentityKeysMetadata, InspectMetadata, KvEncInspectMetadata, KvEntryMetadata,
    OnlineVerificationMetadata, SignatureVerificationMetadata, SignerPublicKeyMetadata,
    SignerPublicKeyProtectedMetadata, WrapDataMetadata,
};
use serde_json::{json, Value};

pub(crate) fn build_inspect_view(metadata: &InspectMetadata) -> Value {
    match metadata {
        InspectMetadata::FileEnc(file) => build_file_enc_view(file),
        InspectMetadata::KvEnc(kv) => build_kv_enc_view(kv),
    }
}

fn build_file_enc_view(file: &FileEncInspectMetadata) -> Value {
    json!({
        "format": "file-enc",
        "version": file.version,
        "header": {
            "format": file.header.format,
            "sid": file.header.sid,
            "created_at": file.header.created_at,
            "updated_at": file.header.updated_at,
        },
        "wrap_data": build_wrap_data_view(&file.wrap_data),
        "payload": build_file_payload_view(&file.payload),
        "signature": build_signature_view(&file.signature),
        "signature_verification": build_signature_verification_view(&file.signature_verification),
        "online_verification": file.online_verification.as_ref().map(build_online_view),
    })
}

fn build_file_payload_view(payload: &FilePayloadMetadata) -> Value {
    json!({
        "protected": {
            "format": payload.protected.format,
            "sid": payload.protected.sid,
            "alg": { "aead": payload.protected.alg.aead },
        },
        "encrypted": {
            "nonce": payload.encrypted.nonce,
            "ct": payload.encrypted.ct,
        },
    })
}

fn build_kv_enc_view(kv: &KvEncInspectMetadata) -> Value {
    json!({
        "format": "kv-enc",
        "version": kv.version,
        "header": {
            "sid": kv.header.sid,
            "alg": { "aead": kv.header.alg.aead },
            "created_at": kv.header.created_at,
            "updated_at": kv.header.updated_at,
        },
        "wrap_data": build_wrap_data_view(&kv.wrap_data),
        "entries": kv.entries.iter().map(build_kv_entry_view).collect::<Vec<_>>(),
        "signature": build_signature_view(&kv.signature),
        "summary": { "total_entries": kv.summary.total_entries },
        "signature_verification": build_signature_verification_view(&kv.signature_verification),
        "online_verification": kv.online_verification.as_ref().map(build_online_view),
    })
}

fn build_kv_entry_view(entry: &KvEntryMetadata) -> Value {
    json!({
        "key": entry.key,
        "nonce": entry.nonce,
        "ct": entry.ct,
        "disclosed": entry.disclosed,
    })
}

fn build_wrap_data_view(wrap: &WrapDataMetadata) -> Value {
    json!({
        "recipients": wrap.recipients,
        "wrap_items": wrap.wrap_items.iter().map(|item| json!({
            "recipient_handle": item.recipient_handle,
            "kid": item.kid,
            "alg": item.alg,
            "enc": item.enc,
            "ct": item.ct,
        })).collect::<Vec<_>>(),
        "removed_recipients": wrap.removed_recipients.iter().map(|removed| json!({
            "recipient_handle": removed.recipient_handle,
            "kid": removed.kid,
            "removed_at": removed.removed_at,
        })).collect::<Vec<_>>(),
    })
}

fn build_signature_view(signature: &ArtifactSignatureMetadata) -> Value {
    json!({
        "alg": signature.alg,
        "kid": signature.kid,
        "mac": signature.mac,
        "signer_pub": build_signer_public_key_view(&signature.signer_public_key),
        "sig": signature.sig,
    })
}

fn build_signer_public_key_view(key: &SignerPublicKeyMetadata) -> Value {
    json!({
        "protected": build_signer_protected_view(&key.protected),
        "signature": key.signature,
    })
}

fn build_signer_protected_view(protected: &SignerPublicKeyProtectedMetadata) -> Value {
    let mut protected_json = json!({
        "format": protected.format,
        "subject_handle": protected.subject_handle,
        "kid": protected.kid,
        "keys": build_identity_keys_view(&protected.keys),
        "attestation": {
            "method": protected.attestation.method,
            "pub": protected.attestation.public_key,
            "sig": protected.attestation.signature,
        },
        "expires_at": protected.expires_at,
    });
    let object = protected_json
        .as_object_mut()
        .expect("protected public-key JSON must be an object");
    if let Some(claims) = &protected.binding_claims {
        object.insert(
            "binding_claims".to_string(),
            build_binding_claims_view(claims),
        );
    }
    if let Some(created_at) = &protected.created_at {
        object.insert("created_at".to_string(), json!(created_at));
    }
    protected_json
}

fn build_identity_keys_view(keys: &IdentityKeysMetadata) -> Value {
    json!({
        "kem": {
            "kty": keys.kem.kty,
            "crv": keys.kem.crv,
            "x": keys.kem.x,
        },
        "sig": {
            "kty": keys.sig.kty,
            "crv": keys.sig.crv,
            "x": keys.sig.x,
        },
    })
}

fn build_binding_claims_view(claims: &BindingClaimsMetadata) -> Value {
    let mut claims_json = json!({});
    if let Some(account) = &claims.github_account {
        claims_json["github_account"] = json!({
            "id": account.id,
            "login": account.login,
        });
    }
    claims_json
}

fn build_signature_verification_view(verification: &SignatureVerificationMetadata) -> Value {
    json!({
        "verified": verification.verified,
        "status": verification.status,
        "signer_handle": verification.signer_handle,
        "source": verification.source,
        "warnings": verification.warnings,
        "message": verification.message,
    })
}

fn build_online_view(online: &OnlineVerificationMetadata) -> Value {
    json!({
        "provider": online.provider,
        "status": online.status,
        "message": online.message,
        "member_handle": online.member_handle,
        "account": online.account.as_ref().map(|account| json!({
            "login": account.login,
            "id": account.id,
        })),
        "fingerprint": online.fingerprint,
        "matched_key_id": online.matched_key_id,
    })
}
