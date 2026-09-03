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
    pub mod context {
        pub mod crypto {
            use std::path::PathBuf;

            use crate::io::keystore::access::KeystoreAccess;
            use crate::io::ssh::backend::SignatureBackend;
            use crate::model::identity::MemberHandle;
            use crate::Result;

            pub use crate::feature::context::crypto::CryptoContext;

            pub fn load_crypto_context_from_keystore(
                keystore_root: PathBuf,
                member_handle: &str,
                explicit_kid: Option<&str>,
                ssh_backend: Box<dyn SignatureBackend>,
                ssh_pubkey: String,
                workspace_path: Option<PathBuf>,
            ) -> Result<CryptoContext> {
                crate::feature::context::crypto::load_crypto_context_from_keystore(
                    KeystoreAccess::open(keystore_root)?,
                    MemberHandle::try_from(member_handle)?,
                    explicit_kid,
                    ssh_backend,
                    ssh_pubkey,
                    workspace_path,
                )
            }
        }
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
            use crate::support::fs::anchor::AnchoredDir;
            use crate::support::fs::load_text_with_limit;
            use crate::support::fs::relative::DirectoryScope;
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
                let member_handle = build_member_addition_from_content(&content, &source_name)?;
                let workspace = AnchoredDir::open(
                    workspace_path.to_path_buf(),
                    DirectoryScope::Generic,
                    "workspace root",
                )?;

                save_member_content(
                    &workspace,
                    MemberStatus::Incoming,
                    &member_handle,
                    &content,
                    force,
                )?;

                Ok(member_handle)
            }
        }
        pub mod verification {
            use std::path::PathBuf;

            use crate::io::verify_online::VerificationResult;

            pub async fn verify_member_files(member_files: &[PathBuf]) -> Vec<VerificationResult> {
                crate::service::member::verification::verify_member_files(member_files).await
            }
        }
    }
    pub mod trust {
        pub mod review {
            use crate::service::trust::KnownKeyReviewCandidate;

            /// Build a typed known-key candidate for first-party CLI review tests.
            pub fn build_known_key_review_candidate(
                subject_handle: impl Into<String>,
                kid: impl Into<String>,
                attestor: impl Into<String>,
                github_binding_configured: bool,
            ) -> KnownKeyReviewCandidate {
                KnownKeyReviewCandidate::for_test_with_github_binding(
                    subject_handle,
                    kid,
                    attestor,
                    github_binding_configured,
                )
            }
        }
        pub mod recipient_sets {
            pub use crate::feature::trust::recipient_sets::{
                compute_recipient_set_hash, ArtifactRecipientSet,
            };
        }
        pub mod signature {
            pub use crate::feature::trust::signature::sign_trust_store;
        }
    }
}
pub mod wire {
    pub mod public_key {
        pub use crate::format::public_key::AttestationBodyInput;
    }
    pub mod schema {
        pub mod document {
            pub use crate::format::schema::document::parse_kv_signature_token;
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
            use std::path::Path;

            use crate::io::keystore::access::KeystoreAccess;
            use crate::model::identity::{Kid, MemberHandle};
            use crate::service::key::LocalKeyStore;
            use crate::Result;

            pub fn load_active_kid(
                member_handle: &str,
                keystore_root: &Path,
            ) -> Result<Option<String>> {
                let access = KeystoreAccess::open(keystore_root)?;
                let member_handle = MemberHandle::try_from(member_handle)?;
                access
                    .load_active_kid(&member_handle)
                    .map(|kid| kid.map(Kid::into_string))
            }

            pub fn set_active_kid(
                member_handle: &str,
                kid: &str,
                keystore_root: &Path,
            ) -> Result<()> {
                let key_store = LocalKeyStore::open(keystore_root)?;
                key_store.set_active_kid(
                    &MemberHandle::try_from(member_handle)?,
                    &Kid::try_from(kid)?,
                )
            }

            pub fn set_active_kid_unchecked(
                member_handle: &str,
                kid: &str,
                keystore_root: &Path,
            ) -> Result<()> {
                let access = KeystoreAccess::open(keystore_root)?;
                access.set_active_kid_unchecked(
                    &MemberHandle::try_from(member_handle)?,
                    &Kid::try_from(kid)?,
                )
            }
        }
        pub mod member {
            use std::path::Path;

            use crate::io::keystore::access::KeystoreAccess;
            use crate::model::identity::MemberHandle;
            use crate::model::public_key::PublicKey;
            use crate::{ErrorKind, Result};

            pub struct ActiveKeyFixture {
                pub kid: String,
                pub public_key: PublicKey,
            }

            pub fn find_active_key_document(
                member_handle: &str,
                keystore_root: &Path,
            ) -> Result<Option<ActiveKeyFixture>> {
                let access = KeystoreAccess::open(keystore_root)?;
                let member_handle = MemberHandle::try_from(member_handle)?;
                crate::io::keystore::member::find_active_key_document(&access, &member_handle).map(
                    |document| {
                        document.map(|document| ActiveKeyFixture {
                            kid: document.kid.into_string(),
                            public_key: document.public_key,
                        })
                    },
                )
            }

            pub fn load_single_member_handle_from_keystore(
                keystore_root: &Path,
            ) -> Result<Option<String>> {
                let access = match KeystoreAccess::open(keystore_root) {
                    Ok(access) => access,
                    Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error),
                };
                crate::io::keystore::member::load_single_member_handle_from_keystore(&access)
                    .map(|member| member.map(MemberHandle::into_string))
            }
        }
        pub mod paths {
            pub use crate::io::keystore::paths::get_keystore_root_from_base;
        }
        pub mod storage {
            use std::path::Path;

            use crate::io::keystore::access::KeystoreAccess;
            use crate::model::identity::{Kid, MemberHandle};
            use crate::model::private_key::PrivateKey;
            use crate::model::public_key::PublicKey;
            use crate::Result;

            pub fn list_kids(keystore_root: &Path, member_handle: &str) -> Result<Vec<String>> {
                let access = KeystoreAccess::open(keystore_root)?;
                access
                    .list_kids(&MemberHandle::try_from(member_handle)?)
                    .map(|kids| kids.into_iter().map(Kid::into_string).collect())
            }

            pub fn load_private_key(
                keystore_root: &Path,
                member_handle: &str,
                kid: &str,
            ) -> Result<PrivateKey> {
                let access = KeystoreAccess::open(keystore_root)?;
                access.load_private_key(
                    &MemberHandle::try_from(member_handle)?,
                    &Kid::try_from(kid)?,
                )
            }

            pub fn load_public_key(
                keystore_root: &Path,
                member_handle: &str,
                kid: &str,
            ) -> Result<PublicKey> {
                let access = KeystoreAccess::open(keystore_root)?;
                access.load_public_key(
                    &MemberHandle::try_from(member_handle)?,
                    &Kid::try_from(kid)?,
                )
            }

            pub fn save_key_pair_atomic(
                keystore_root: &Path,
                member_handle: &str,
                kid: &str,
                private_key: &PrivateKey,
                public_key: &PublicKey,
            ) -> Result<()> {
                let access = KeystoreAccess::create(keystore_root)?;
                access.save_key_pair_atomic(
                    &MemberHandle::try_from(member_handle)?,
                    &Kid::try_from(kid)?,
                    private_key,
                    public_key,
                )
            }
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
                    KEYGEN_TYPE_ED25519, KEY_PROTECTION_NAMESPACE,
                };
            }
            pub mod fingerprint {
                pub use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
            }
            pub mod key_descriptor {
                pub use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
            }
            pub mod sshsig {
                pub use crate::io::ssh::protocol::sshsig::build_sshsig_signed_data;
            }
            pub mod types {
                pub use crate::io::ssh::protocol::types::Ed25519RawSignature;
            }
            pub mod wire {
                pub use crate::io::ssh::protocol::wire::decode_ssh_string;
            }
        }
    }
    pub mod trust {
        pub mod paths {
            pub use crate::io::trust::paths::get_trust_store_file_path;
        }
        pub mod store {
            use std::path::Path;

            use crate::io::trust::paths::TRUST_DIR_NAME;
            use crate::io::trust::store::save_trust_store_at;
            use crate::model::trust_store::TrustStoreDocument;
            use crate::support::fs::anchor::AnchoredDir;
            use crate::support::fs::lock;
            use crate::support::fs::relative::{ensure_child_dir_restricted_at, DirectoryScope};
            use crate::{Error, Result};

            pub fn save_trust_store(path: &Path, document: &TrustStoreDocument) -> Result<()> {
                let trust_path = path.parent().ok_or_else(invalid_trust_store_path)?;
                let base_path = trust_path.parent().ok_or_else(invalid_trust_store_path)?;
                if trust_path.file_name().and_then(|name| name.to_str()) != Some(TRUST_DIR_NAME) {
                    return Err(invalid_trust_store_path());
                }
                let base = AnchoredDir::create(
                    base_path,
                    DirectoryScope::LocalState,
                    "test local state root",
                )?;
                let trust_dir = ensure_child_dir_restricted_at(&base, TRUST_DIR_NAME)?;
                lock::with_exclusive_locked_directory(&trust_dir, |locked_trust_dir| {
                    save_trust_store_at(&base, locked_trust_dir, path, document)
                })
            }

            fn invalid_trust_store_path() -> Error {
                Error::build_invalid_argument_error(
                    "Trust store test path must be <base>/trust/<owner>.json".to_string(),
                )
            }
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
            pub use crate::io::workspace::detection::WorkspaceRoot;
        }
        pub mod members {
            pub use crate::io::workspace::members::{
                load_active_member_files, load_member_file_from_path,
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
            IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyPlaintext,
        };
    }
    pub mod public_key {
        pub use crate::model::public_key::{
            Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
            VerifiedRecipientKey,
        };

        use crate::model::public_key::{
            AttestationProof, AttestedKeyStatement, VerifiedPublicKeyAttested,
        };
        use crate::model::verification::{ExpiryProof, SelfSignatureProof};

        /// Wrap a public key as a recipient without running the checks.
        ///
        /// The verified wrappers are minted where their checks run, so tests
        /// that start from an already-trusted key get one from here instead of
        /// assembling the proofs themselves.
        pub fn build_unverified_recipient_key(public_key: PublicKey) -> VerifiedRecipientKey {
            let statement = AttestedKeyStatement::new(
                public_key.protected.keys.clone(),
                AttestationProof::new(),
            );
            let attested =
                VerifiedPublicKeyAttested::new(public_key, SelfSignatureProof::new(), statement);
            VerifiedRecipientKey::new(attested, ExpiryProof::new())
        }

        /// Recompute a synthetic fixture's key identifier after protected fields change.
        pub fn refresh_public_key_kid(public_key: &mut PublicKey) -> crate::Result<()> {
            let mut protected_without_kid = serde_json::to_value(&public_key.protected)?;
            protected_without_kid
                .as_object_mut()
                .expect("PublicKeyProtected serializes as an object")
                .remove("kid");
            public_key.protected.kid =
                crate::format::kid::derive_public_key_kid(&protected_without_kid)?;
            Ok(())
        }
    }
    pub mod signature {
        pub use crate::model::signature::KeyPossessionProof;
    }
    pub mod ssh {
        pub use crate::model::ssh::SshDeterminismStatus;
    }
    pub mod trust_store {
        pub use crate::model::trust_store::{
            KnownKey, KnownKeyApprovalVia, RecipientHandleHint, RecipientSetApprovalVia,
            RecipientSetRecord, TrustStoreProtected,
        };
    }
    pub mod verified {
        pub use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
    }
    pub mod wire {
        pub mod format {
            pub use crate::model::wire::format::{
                FILE_ENC_V1, LOCAL_TRUST_V1, PRIVATE_KEY_V1, PUBLIC_KEY_V1,
            };
        }
        pub mod jwk {
            pub use crate::model::wire::jwk::{CURVE_ED25519, CURVE_X25519};
        }
        pub mod private_key {
            pub use crate::model::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256;
        }
    }
}
pub mod helpers {
    /// Build the failures a CLI recovery flow branches on.
    ///
    /// A recovery route is attached inside the crate, so a test outside it
    /// cannot stand one up through the public builders. These name the same
    /// conditions the real read paths report, and they name them the way those
    /// paths do: the category the failure came in as, plus the route out of it.
    pub mod recovery {
        use crate::error::{
            LOCAL_KEYSTORE_MISSING_RECOVERY, TRUST_SIGNER_KEY_MISSING_RECOVERY,
            TRUST_STORE_RESET_REQUIRED_RECOVERY,
        };
        use crate::Error;

        /// A stored trust store whose bytes would not parse.
        pub fn build_unparsable_trust_store_error(message: impl Into<String>) -> Error {
            Error::build_parse_error(message).with_recovery(TRUST_STORE_RESET_REQUIRED_RECOVERY)
        }

        /// A trust store whose signer key the keystore no longer holds.
        pub fn build_missing_trust_signer_key_error(message: impl Into<String>) -> Error {
            Error::build_invalid_operation_error(message)
                .with_recovery(TRUST_SIGNER_KEY_MISSING_RECOVERY)
        }

        /// A local keystore that is not there to verify anything against.
        pub fn build_local_keystore_missing_error(message: impl Into<String>) -> Error {
            Error::build_invalid_operation_error(message)
                .with_recovery(LOCAL_KEYSTORE_MISSING_RECOVERY)
        }
    }
    pub mod codec {
        pub mod base64_public {
            pub use crate::format::codec::base64_public::{
                decode_base64url_nopad_array, encode_base64url_nopad,
            };
        }
        pub mod base64_secret {
            pub use crate::format::codec::base64_secret::encode_base64url_nopad_secret_32;
        }
    }
    pub mod fs {
        pub mod atomic {
            pub use crate::support::fs::atomic::save_json;
        }
    }
    pub mod kid {
        pub use crate::support::kid::{format_kid_display, format_kid_half_display};
    }
    pub mod secret {
        pub use crate::support::secret::{SecretArray, SecretString};
    }
    pub mod time {
        pub use crate::support::time::format_timestamp_rfc3339;
    }
}
