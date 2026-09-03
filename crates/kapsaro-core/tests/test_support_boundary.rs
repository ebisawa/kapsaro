// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Boundary test for the hidden first-party `kapsaro_core::test_support` API.
//! The import list pins the purpose-specific helper surface used by repository tests.

/// Every symbol `test_support` exposes. This list keeps the module a narrow,
/// purpose-grouped
/// allow-list rather than a mirror of the implementation roots underneath it:
/// each helper the repository tests reach for is named here, so one that moves
/// or is dropped breaks the list. The `online` helpers are listed under the same
/// gate they carry, because the crate is also built without that feature.
#[allow(unused_imports)]
mod test_support_surface {
    pub mod settings {
        pub mod types {
            pub use kapsaro_core::test_support::settings::types::SshSigningMethod;
        }
    }

    pub mod primitives {
        pub mod kem {
            pub use kapsaro_core::test_support::primitives::kem::generate_keypair;
        }
    }

    pub mod operations {
        pub mod context {
            pub use kapsaro_core::test_support::operations::context::crypto::{
                load_crypto_context_from_keystore, CryptoContext,
            };
        }

        pub mod key {
            pub use kapsaro_core::test_support::operations::key::generate::{
                generate_key, KeyGenerationOptions,
            };
            pub use kapsaro_core::test_support::operations::key::material::generate_keypairs;
            pub use kapsaro_core::test_support::operations::key::portable_export::{
                export_private_key_portable, ExportPasswordPolicy, PortableExportOptions,
            };
            pub use kapsaro_core::test_support::operations::key::protection::encryption::{
                decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
            };
            pub use kapsaro_core::test_support::operations::key::public_key_document::{
                build_attestation, build_public_key, PublicKeyDocumentParams,
            };
            pub use kapsaro_core::test_support::operations::key::ssh_binding::SshBindingContext;
        }

        pub mod member {
            pub use kapsaro_core::test_support::operations::member::add::add_member_from_file;
            pub use kapsaro_core::test_support::operations::member::verification::verify_member_files;
        }

        pub mod trust {
            pub use kapsaro_core::test_support::operations::trust::recipient_sets::{
                compute_recipient_set_hash, ArtifactRecipientSet,
            };
            pub use kapsaro_core::test_support::operations::trust::review::build_known_key_review_candidate;
            pub use kapsaro_core::test_support::operations::trust::signature::sign_trust_store;
        }
    }

    pub mod wire {
        pub use kapsaro_core::test_support::wire::public_key::AttestationBodyInput;
        pub use kapsaro_core::test_support::wire::schema::document::parse_kv_signature_token;
        pub use kapsaro_core::test_support::wire::token::TokenCodec;
    }

    pub mod storage {
        pub mod config {
            pub use kapsaro_core::test_support::storage::config::paths::get_base_dir;
        }

        pub mod keystore {
            pub use kapsaro_core::test_support::storage::keystore::active::{
                load_active_kid, set_active_kid,
            };
            pub use kapsaro_core::test_support::storage::keystore::member::{
                find_active_key_document, load_single_member_handle_from_keystore, ActiveKeyFixture,
            };
            pub use kapsaro_core::test_support::storage::keystore::paths::get_keystore_root_from_base;
            pub use kapsaro_core::test_support::storage::keystore::storage::{
                list_kids, load_private_key, load_public_key, save_key_pair_atomic,
            };
        }

        pub mod ssh {
            pub use kapsaro_core::test_support::storage::ssh::agent::traits::AgentSigner;
            pub use kapsaro_core::test_support::storage::ssh::backend::ssh_keygen::SshKeygenBackend;
            pub use kapsaro_core::test_support::storage::ssh::backend::SignatureBackend;
            pub use kapsaro_core::test_support::storage::ssh::external::keygen::DefaultSshKeygen;
            pub use kapsaro_core::test_support::storage::ssh::protocol::base64::decode_base64_armored;
            pub use kapsaro_core::test_support::storage::ssh::protocol::constants::{
                KEYGEN_TYPE_ED25519, KEY_PROTECTION_NAMESPACE,
            };
            pub use kapsaro_core::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;
            pub use kapsaro_core::test_support::storage::ssh::protocol::key_descriptor::SshKeyDescriptor;
            pub use kapsaro_core::test_support::storage::ssh::protocol::sshsig::build_sshsig_signed_data;
            pub use kapsaro_core::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
            pub use kapsaro_core::test_support::storage::ssh::protocol::wire::decode_ssh_string;
        }

        pub mod trust {
            pub use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
            pub use kapsaro_core::test_support::storage::trust::store::save_trust_store;
        }

        pub mod verify_online {
            pub use kapsaro_core::test_support::storage::verify_online::VerifiedGithubIdentity;

            #[cfg(feature = "online")]
            pub use kapsaro_core::test_support::storage::verify_online::github::{
                verify_github_account_with_api, GitHubApiFuture, GitHubVerificationApi,
            };
        }

        pub mod workspace {
            pub use kapsaro_core::test_support::storage::workspace::detection::WorkspaceRoot;
            pub use kapsaro_core::test_support::storage::workspace::members::{
                load_active_member_files, load_member_file_from_path,
            };
        }
    }

    pub mod domain {
        pub use kapsaro_core::test_support::domain::common::WrapItem;
        pub use kapsaro_core::test_support::domain::identity::{Kid, MemberHandle};
        pub use kapsaro_core::test_support::domain::private_key::{
            IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyPlaintext,
        };
        pub use kapsaro_core::test_support::domain::public_key::{
            build_unverified_recipient_key, Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey,
            PublicKeyProtected, VerifiedRecipientKey,
        };
        pub use kapsaro_core::test_support::domain::signature::KeyPossessionProof;
        pub use kapsaro_core::test_support::domain::ssh::SshDeterminismStatus;
        pub use kapsaro_core::test_support::domain::trust_store::{
            KnownKey, KnownKeyApprovalVia, RecipientHandleHint, RecipientSetApprovalVia,
            RecipientSetRecord, TrustStoreProtected,
        };
        pub use kapsaro_core::test_support::domain::verified::{
            DecryptionProof, VerifiedPrivateKey,
        };

        pub mod wire {
            pub use kapsaro_core::test_support::domain::wire::format::{
                FILE_ENC_V1, LOCAL_TRUST_V1, PRIVATE_KEY_V1, PUBLIC_KEY_V1,
            };
            pub use kapsaro_core::test_support::domain::wire::jwk::{CURVE_ED25519, CURVE_X25519};
            pub use kapsaro_core::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256;
        }
    }

    pub mod helpers {
        pub mod codec {
            pub use kapsaro_core::test_support::helpers::codec::base64_public::{
                decode_base64url_nopad_array, encode_base64url_nopad,
            };
            pub use kapsaro_core::test_support::helpers::codec::base64_secret::encode_base64url_nopad_secret_32;
        }
        pub mod fs {
            pub use kapsaro_core::test_support::helpers::fs::atomic::save_json;
        }
        pub use kapsaro_core::test_support::helpers::kid::{
            format_kid_display, format_kid_half_display,
        };
        pub use kapsaro_core::test_support::helpers::secret::{SecretArray, SecretString};
        pub use kapsaro_core::test_support::helpers::time::format_timestamp_rfc3339;
    }
}

#[test]
fn active_kid_helper_requires_an_existing_key() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let keystore_root = temp.path().join("keys");

    let error = kapsaro_core::test_support::storage::keystore::active::set_active_kid(
        "alice@example.com",
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        &keystore_root,
    )
    .expect_err("missing keystore must reject activation");

    assert_eq!(error.kind(), kapsaro_core::ErrorKind::NotFound);
    assert!(!keystore_root.exists());
}
