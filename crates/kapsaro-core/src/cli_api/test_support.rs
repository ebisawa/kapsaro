// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Hidden first-party test support allow-list.
//! This module exposes narrow helpers used by repository tests.

pub mod settings {
    pub mod types {
        pub use crate::config::types::SshSigningMethod;
    }
}
pub mod primitives {
    pub mod kem {
        pub use crate::crypto::kem::generate_keypair;
    }
}
pub mod operations {
    pub mod config {
        pub use crate::config::resolution::global::{
            resolve_config_value, validate_key, ConfigScope,
        };
    }
    pub mod context {
        pub mod crypto {
            pub use crate::feature::context::crypto::{
                load_crypto_context_from_keystore, CryptoContext, SigningContext,
            };
        }
    }
    pub mod encrypt {
        pub use crate::feature::encrypt::encrypt_file_content;
    }
    pub mod inspect {
        pub use crate::feature::inspect::{build_inspect_view, InspectOutput};
    }
    pub mod key {
        pub mod generate {
            pub use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
        }
        pub mod material {
            pub use crate::feature::key::material::generate_keypairs;
        }
        pub mod portable_export {
            pub use crate::feature::key::portable_export::{
                export_private_key_portable, ExportPasswordPolicy, PortableExportOptions,
            };
        }
        pub mod protection {
            pub mod encryption {
                pub use crate::feature::key::protection::encryption::{
                    decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
                };
            }
        }
        pub mod public_key_document {
            pub use crate::feature::key::public_key_document::{
                build_attestation, build_public_key, PublicKeyDocumentParams,
            };
        }
        pub mod ssh_binding {
            pub use crate::feature::key::ssh_binding::SshBindingContext;
        }
    }
    pub mod member {
        pub mod add {
            use std::path::Path;

            use crate::feature::member::add::build_member_addition_from_content;
            use crate::io::workspace::members::{save_member_content, MemberStatus};
            use crate::support::fs::load_text_with_limit;
            use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
            use crate::support::path::format_path_relative_to_cwd;
            use crate::Result;

            pub fn add_member_from_file(
                workspace_path: &Path,
                file_path: &Path,
                force: bool,
            ) -> Result<String> {
                let content =
                    load_text_with_limit(file_path, MAX_JSON_DOCUMENT_READ_SIZE, "PublicKey file")?;
                let source_name = format_path_relative_to_cwd(file_path);
                let addition = build_member_addition_from_content(&content, &source_name, false)?;

                save_member_content(
                    workspace_path,
                    MemberStatus::Incoming,
                    &addition.member_handle,
                    &content,
                    force,
                )?;

                Ok(addition.member_handle)
            }
        }
        pub mod verification {
            use std::path::PathBuf;

            use crate::io::verify_online::VerificationResult;

            pub async fn verify_member_files(
                member_files: &[PathBuf],
                verbose: bool,
            ) -> Vec<VerificationResult> {
                crate::app::member::verification::verify_member_files(member_files, verbose).await
            }
        }
    }
    pub mod trust {
        pub mod recipient_sets {
            pub use crate::feature::trust::recipient_sets::{
                compute_recipient_set_hash, ArtifactRecipientSet,
            };
        }
        pub mod signature {
            pub use crate::feature::trust::signature::sign_trust_store;
        }
    }
    pub mod verify {
        pub mod file {
            pub use crate::feature::verify::file::{
                verify_file_content, verify_file_document, verify_file_document_report,
            };
        }
        pub mod kv {
            pub mod signature {
                pub use crate::feature::verify::kv::signature::{
                    verify_kv_content, verify_kv_document, verify_kv_document_report,
                };
            }
        }
    }
}
pub mod wire {
    pub mod content {
        pub use crate::format::content::KvEncContent;
    }
    pub mod public_key {
        pub use crate::format::public_key::{build_attestation_body_bytes, AttestationBodyInput};
    }
    pub mod kv {
        pub mod enc {
            pub mod canonical {
                pub use crate::format::kv::enc::canonical::{
                    build_canonical_bytes, extract_recipients_from_wrap, parse_kv_wrap,
                };
            }
        }
    }
    pub mod schema {
        pub mod document {
            pub use crate::format::schema::document::{
                parse_file_enc_str, parse_kv_entry_token, parse_kv_head_token,
                parse_kv_signature_token, parse_kv_wrap_token, parse_public_key_str,
                parse_trust_store_str,
            };
        }
        pub mod validator {
            pub use crate::format::schema::validator::{
                load_embedded_trust_validator, load_embedded_validator, SchemaTarget, Validator,
            };
        }
    }
    pub mod token {
        pub use crate::format::token::TokenCodec;
    }
}
pub mod storage {
    pub mod config {
        pub mod paths {
            pub use crate::io::config::paths::get_base_dir;
        }
    }
    pub mod keystore {
        pub mod active {
            pub use crate::io::keystore::active::{load_active_kid, set_active_kid};
        }
        pub mod member {
            pub use crate::io::keystore::member::find_active_key_document;
        }
        pub mod paths {
            pub use crate::io::keystore::paths::get_keystore_root_from_base;
        }
        pub mod storage {
            pub use crate::io::keystore::storage::{
                list_kids, load_private_key, save_key_pair_atomic,
            };
        }
    }
    pub mod ssh {
        pub mod agent {
            pub mod traits {
                pub use crate::io::ssh::agent::traits::AgentSigner;
            }
        }
        pub mod backend {
            pub use crate::io::ssh::backend::SignatureBackend;
            pub mod ssh_keygen {
                pub use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
            }
        }
        pub mod external {
            pub mod keygen {
                pub use crate::io::ssh::external::keygen::DefaultSshKeygen;
            }
        }
        pub mod protocol {
            pub mod base64 {
                pub use crate::io::ssh::protocol::base64::decode_base64_armored;
            }
            pub mod constants {
                pub use crate::io::ssh::protocol::constants::{
                    ATTESTATION_METHOD_SSH_SIGN, ATTESTATION_NAMESPACE, KEYGEN_TYPE_ED25519,
                    KEY_PROTECTION_NAMESPACE, KEY_TYPE_ED25519,
                };
            }
            pub mod fingerprint {
                pub use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
            }
            pub mod key_descriptor {
                pub use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
            }
            pub mod sshsig {
                pub use crate::io::ssh::protocol::sshsig::{
                    build_sshsig_signed_data, parse_sshsig_armored, parse_sshsig_blob,
                    SSHSIG_HASHALG, SSHSIG_MAGIC,
                };
            }
            pub mod types {
                pub use crate::io::ssh::protocol::types::Ed25519RawSignature;
            }
            pub mod wire {
                pub use crate::io::ssh::protocol::wire::{decode_ssh_string, encode_ssh_string};
            }
        }
    }
    pub mod trust {
        pub mod paths {
            pub use crate::io::trust::paths::get_trust_store_file_path;
        }
        pub mod store {
            pub use crate::io::trust::store::save_trust_store;
        }
    }
    pub mod verify_online {
        pub use crate::io::verify_online::VerifiedGithubIdentity;
        #[cfg(feature = "online")]
        pub mod github {
            pub use crate::io::verify_online::github::{
                verify_github_account_with_api, GitHubApiFuture, GitHubVerificationApi,
            };
        }
    }
    pub mod workspace {
        pub mod detection {
            pub use crate::io::workspace::detection::{
                detect_workspace_root, resolve_workspace, WorkspaceRoot,
            };
        }
        pub mod members {
            pub use crate::io::workspace::members::{
                load_active_member_files, load_member_file_from_path, load_member_files,
            };
        }
    }
}
pub mod domain {
    pub mod common {
        pub use crate::model::common::WrapItem;
    }
    pub mod identity {
        pub use crate::model::identity::{Kid, MemberHandle};
    }
    pub mod private_key {
        pub use crate::model::private_key::{
            IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm,
            PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
        };
    }
    pub mod public_key {
        pub use crate::model::public_key::{
            Attestation, AttestationProof, AttestedKeyStatement, IdentityKeys, JwkOkpPublicKey,
            PublicKey, PublicKeyParts, PublicKeyProtected, VerifiedBindingClaims,
            VerifiedPublicKeyAttested, VerifiedRecipientKey,
        };
    }
    pub mod signature {
        pub use crate::model::signature::{
            ArtifactSignature, KeyPossessionProof, KeyPossessionProofAlgorithm,
        };
    }
    pub mod ssh {
        pub use crate::model::ssh::SshDeterminismStatus;
    }
    pub mod trust_store {
        pub use crate::model::trust_store::{
            KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount,
            RecipientHandleHint, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreDocument,
            TrustStoreProtected, TrustStoreSignature,
        };
    }
    pub mod verification {
        pub use crate::model::verification::{
            BindingVerificationProof, ExpiryProof, SelfSignatureProof, SignatureVerificationProof,
            VerifyingKeySource,
        };
    }
    pub mod verified {
        pub use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
    }
    pub mod wire {
        pub mod algorithm {
            pub use crate::model::wire::algorithm::{
                AEAD_XCHACHA20_POLY1305, HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
            };
        }
        pub mod context {
            pub use crate::model::wire::context::{
                AAD_KV_ENTRY_PAYLOAD_V1, HASH_DOMAIN_RECIPIENT_SET_V1,
                HKDF_INFO_FILE_CONTENT_KEY_V1, HKDF_INFO_FILE_MAC_KEY_V1, HKDF_INFO_KV_CEK_V1,
                HKDF_INFO_KV_MAC_KEY_V1, HKDF_INFO_PRIVATE_KEY_PASSWORD_V1,
                HKDF_INFO_PRIVATE_KEY_SSHSIG_V1, HKDF_SALT_FILE_V1, HKDF_SALT_KV_V1,
                HPKE_INFO_FILE_WRAP_V1, HPKE_INFO_KV_WRAP_V1, MAC_DOMAIN_KEY_POSSESSION_V1,
                SIG_DOMAIN_ARTIFACT_SIGNATURE_V1, SSHSIG_MESSAGE_DETERMINISM_CHECK_V1,
                SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V1,
                SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1,
            };
        }
        pub mod format {
            pub use crate::model::wire::format::{
                FILE_ENC_V1, FILE_PAYLOAD_V1, LOCAL_TRUST_V1, PRIVATE_KEY_V1, PUBLIC_KEY_V1,
            };
        }
        pub mod jwk {
            pub use crate::model::wire::jwk::{CURVE_ED25519, CURVE_X25519};
        }
        pub mod private_key {
            pub use crate::model::wire::private_key::{
                PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256,
                PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256,
            };
        }
    }
}
pub mod helpers {
    pub mod codec {
        pub mod base64_public {
            pub use crate::format::codec::base64_public::{
                decode_base64_standard, decode_base64url_nopad, decode_base64url_nopad_array,
                encode_base64_standard, encode_base64_standard_nopad, encode_base64url_nopad,
            };
        }
        pub mod base64_secret {
            pub use crate::format::codec::base64_secret::{
                decode_base64url_nopad_secret_32, decode_base64url_nopad_secret_64,
                encode_base64url_nopad_secret_32, encode_base64url_nopad_secret_64,
            };
        }
    }
    pub mod fs {
        pub mod atomic {
            pub use crate::support::fs::atomic::save_json;
        }
    }
    pub mod kid {
        pub use crate::support::kid::format_kid_half_display;
    }
    pub mod secret {
        pub use crate::support::secret::{SecretArray, SecretString};
    }
    pub mod time {
        pub use crate::support::time::format_timestamp_rfc3339;
    }
    pub mod tty {
        pub use crate::support::tty::set_interactive_override;
    }
}
