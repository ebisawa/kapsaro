// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON rendering for semantic inspect metadata.
//! Keeps the command's wire-facing JSON shape in the CLI presentation layer.

use kapsaro_core::api::inspect::{
    ArtifactSignatureMetadata, InspectMetadata, OnlineVerificationMetadata,
    SignatureVerificationMetadata, SignerPublicKeyMetadata, WrapDataMetadata,
};
use serde_json::{json, Value};

pub(crate) fn render_inspect_json(metadata: &InspectMetadata) -> Value {
    match metadata {
        InspectMetadata::FileEnc(file) => json!({
            "format": "file-enc",
            "version": file.version,
            "header": {
                "format": file.header.format,
                "sid": file.header.sid,
                "created_at": file.header.created_at,
                "updated_at": file.header.updated_at,
            },
            "wrap_data": render_wrap_data(&file.wrap_data),
            "payload": {
                "protected": {
                    "format": file.payload.protected.format,
                    "sid": file.payload.protected.sid,
                    "alg": { "aead": file.payload.protected.alg.aead },
                },
                "encrypted": {
                    "nonce": file.payload.encrypted.nonce,
                    "ct": file.payload.encrypted.ct,
                },
            },
            "signature": render_signature(&file.signature),
            "signature_verification": render_signature_verification(
                &file.signature_verification
            ),
            "online_verification": file.online_verification.as_ref().map(render_online),
        }),
        InspectMetadata::KvEnc(kv) => json!({
            "format": "kv-enc",
            "version": kv.version,
            "header": {
                "sid": kv.header.sid,
                "alg": { "aead": kv.header.alg.aead },
                "created_at": kv.header.created_at,
                "updated_at": kv.header.updated_at,
            },
            "wrap_data": render_wrap_data(&kv.wrap_data),
            "entries": kv.entries.iter().map(|entry| json!({
                "key": entry.key,
                "nonce": entry.nonce,
                "ct": entry.ct,
                "disclosed": entry.disclosed,
            })).collect::<Vec<_>>(),
            "signature": render_signature(&kv.signature),
            "summary": { "total_entries": kv.summary.total_entries },
            "signature_verification": render_signature_verification(
                &kv.signature_verification
            ),
            "online_verification": kv.online_verification.as_ref().map(render_online),
        }),
    }
}

fn render_wrap_data(wrap: &WrapDataMetadata) -> Value {
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

fn render_signature(signature: &ArtifactSignatureMetadata) -> Value {
    json!({
        "alg": signature.alg,
        "kid": signature.kid,
        "mac": signature.mac,
        "signer_pub": render_signer_public_key(&signature.signer_public_key),
        "sig": signature.sig,
    })
}

fn render_signer_public_key(key: &SignerPublicKeyMetadata) -> Value {
    let protected = &key.protected;
    let mut protected_json = json!({
        "format": protected.format,
        "subject_handle": protected.subject_handle,
        "kid": protected.kid,
        "keys": {
            "kem": {
                "kty": protected.keys.kem.kty,
                "crv": protected.keys.kem.crv,
                "x": protected.keys.kem.x,
            },
            "sig": {
                "kty": protected.keys.sig.kty,
                "crv": protected.keys.sig.crv,
                "x": protected.keys.sig.x,
            },
        },
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
        let mut claims_json = json!({});
        if let Some(account) = &claims.github_account {
            claims_json["github_account"] = json!({
                "id": account.id,
                "login": account.login,
            });
        }
        object.insert("binding_claims".to_string(), claims_json);
    }
    if let Some(created_at) = &protected.created_at {
        object.insert("created_at".to_string(), json!(created_at));
    }
    json!({
        "protected": protected_json,
        "signature": key.signature,
    })
}

fn render_signature_verification(verification: &SignatureVerificationMetadata) -> Value {
    json!({
        "verified": verification.verified,
        "status": verification.status,
        "signer_handle": verification.signer_handle,
        "source": verification.source,
        "warnings": verification.warnings,
        "message": verification.message,
    })
}

fn render_online(online: &OnlineVerificationMetadata) -> Value {
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
