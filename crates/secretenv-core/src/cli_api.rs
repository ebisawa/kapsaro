// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! First-party CLI API boundary.
//!
//! This module is available only with the `cli-internal` feature. It is not part
//! of the external embedding API.

pub mod app {
    pub mod config {
        pub use crate::app::config::{
            list_config_command, resolve_config_value_command, set_config_command,
            unset_config_command, ConfigScope, ConfigSetResult, ConfigUnsetResult,
        };
    }

    pub mod context {
        pub mod env_key {
            pub use crate::app::context::env_key::is_env_key_mode;
        }

        pub mod execution {
            pub use crate::app::context::execution::{resolve_write_execution, ExecutionContext};
        }

        pub mod identity {
            pub use crate::app::context::identity::{
                build_missing_member_handle_error, resolve_github_user_input,
                resolve_member_handle_input,
            };
        }

        pub mod member {
            pub use crate::app::context::member::resolve_required_member;
        }

        pub mod options {
            pub use crate::app::context::options::CommonCommandOptions;
        }

        pub mod ssh {
            pub use crate::app::context::ssh::{
                build_ssh_signing_context, resolve_ssh_context_by_active_key,
                resolve_ssh_key_candidates, SshKeyCandidateView, SshSigningContextResolution,
            };
        }
    }

    pub mod doctor {
        pub use crate::app::doctor::{run_doctor, DoctorRequest};

        pub mod types {
            pub use crate::app::doctor::types::{
                DoctorCategory, DoctorCheck, DoctorReport, DoctorStatus, DoctorSubject,
            };
        }
    }

    pub mod file {
        pub mod decrypt {
            pub use crate::app::file::decrypt::{
                execute_decrypt_file_command, resolve_decrypt_file_command, DecryptFileCommand,
            };
        }

        pub mod encrypt {
            pub use crate::app::file::encrypt::{
                execute_encrypt_file_command_with_recipient_set_confirmation,
                resolve_encrypt_file_command, EncryptFileCommand,
            };
        }

        pub mod inspect {
            pub use crate::app::file::inspect::{execute_inspect_file_command, InspectCommand};
        }
    }

    pub mod key {
        pub mod generate {
            pub use crate::app::key::generate::generate_key_command;
        }

        pub mod manage {
            pub use crate::app::key::manage::{
                activate_key_command, export_key_command, export_private_key_command,
                list_keys_command, remove_key_command, validate_kid,
            };
        }

        pub mod types {
            pub use crate::app::key::types::{KeyExportPrivateResult, KeyInfo, KeyListResult};
        }
    }

    pub mod kv {
        pub mod mutation {
            pub use crate::app::kv::mutation::{
                import_kv_command_with_recipient_set_confirmation, resolve_mutation_write_plan,
                set_kv_command_with_recipient_set_confirmation,
                unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
            };
        }

        pub mod query {
            pub use crate::app::kv::query::{
                execute_kv_read_command, list_kv_command, resolve_kv_read_command, KvReadCommand,
            };
        }

        pub mod types {
            pub use crate::app::kv::types::{
                KvDisclosedEntry, KvImportResult, KvInputEntry, KvReadMode, KvReadResult,
                KvWriteOutcome,
            };
        }
    }

    pub mod member {
        pub mod approval {
            pub use crate::app::member::approval::{
                evaluate_members_for_approval, save_member_approvals, MemberApprovalEvaluation,
                MemberApprovalResult,
            };
        }

        pub mod mutation {
            pub use crate::app::member::mutation::{
                add_member, evaluate_member_removal, remove_member,
            };
        }

        pub mod query {
            pub use crate::app::member::query::{list_members, load_member_show_result};
        }

        pub mod types {
            pub use crate::app::member::types::{
                MemberDocumentStatus, MemberDocumentView, MemberGithubClaim, MemberListEntry,
                MemberListResult, MemberRemovalReport, MemberRemoveResult, MemberShowResult,
                MemberVerificationResult, MembershipStatus,
            };
        }

        pub mod verification {
            pub use crate::app::member::verification::verify_members;
        }
    }

    pub mod registration {
        pub use crate::app::registration::{
            ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
        };

        pub mod command {
            pub use crate::app::registration::command::{
                evaluate_registration_decision, execute_registration_decision,
                resolve_registration_command, RegistrationDecision,
            };
        }

        pub mod key_plan {
            pub use crate::app::registration::key_plan::resolve_registration_key_plan;
        }

        pub mod types {
            pub use crate::app::registration::types::{
                MemberKeySetupResult, RegistrationCommand, RegistrationKeyPlan, RegistrationMode,
                RegistrationOutcome, RegistrationResult, RegistrationTarget,
            };
        }
    }

    pub mod rewrap {
        pub use crate::app::rewrap::{execute_rewrap_batch_command, RewrapBatchCommandInput};

        pub mod promotion {
            pub use crate::app::rewrap::promotion::{
                PromotionReviewFailure, PromotionReviewPrompt, PromotionReviewView,
            };
        }

        pub mod types {
            pub use crate::app::rewrap::types::RewrapBatchOutcome;
        }
    }

    pub mod run {
        pub use crate::app::run::execute_run_command;
    }

    pub mod trust {
        pub use crate::app::trust::{
            ArtifactRecipientTrustOutcome, CommandCapability, GetPolicy, ImportPolicy,
            RecipientTrustOutcome, RunPolicy, SetPolicy, SignerTrustOutcome,
            TrustApprovalCandidate, UnsetPolicy, WriteTrustPolicy,
        };

        pub mod enforcement {
            pub use crate::app::trust::enforcement::ArtifactRecipientSetReview;
        }

        pub mod list {
            pub use crate::app::trust::list::{
                list_known_keys, list_recipient_sets, RecipientSetListItem, RecipientSetListResult,
                TrustListItem, TrustListResult,
            };
        }

        pub mod management {
            pub use crate::app::trust::management::{
                execute_purge, execute_recipient_set_purge, list_purge_candidates,
                list_recipient_set_purge_candidates, remove_known_key_command,
                remove_recipient_set_command, PurgeKnownKeysResult, PurgeRecipientSetsResult,
                RemoveKnownKeyResult, RemoveRecipientSetResult,
            };
        }

        pub mod recovery {
            pub use crate::app::trust::recovery::{
                build_trust_store_reset_plan, execute_trust_store_reset,
                requires_trust_store_reset, TrustStoreResetPlan,
            };
        }

        pub mod review {
            pub use crate::app::trust::review::{
                execute_read_with_signer_trust, execute_write_with_recipient_trust,
                ReadSignerTrustReviewPlan, SignerTrustLabels, TrustExecutionContext,
                WriteRecipientTrustReviewPlan,
            };
        }
    }

    pub mod verification {
        pub use crate::app::verification::OnlineVerificationStatus;
    }
}

pub mod presentation {
    pub mod config {
        pub use crate::config::types::SshSigningMethod;
    }

    pub mod file_content {
        use crate::format::content::FileEncContent;
        use crate::Result;

        pub fn detect_file_enc_content_with_source(
            content: String,
            source_name: impl Into<String>,
        ) -> Result<FileEncContent> {
            FileEncContent::detect_with_source(content, source_name)
        }
    }

    pub mod fs {
        pub use crate::support::fs::atomic::{save_bytes, save_text};
        pub use crate::support::fs::{load_bytes, load_text_with_limit};
    }

    pub mod inspect {
        pub use crate::feature::inspect::{InspectOutput, InspectSection};
    }

    pub mod kid {
        pub use crate::support::kid::{
            format_kid_display, format_kid_display_lossy, format_kid_half_display,
        };
    }

    pub mod limits {
        pub use crate::support::limits::{MAX_JSON_DOCUMENT_READ_SIZE, MAX_KV_ENC_FILE_SIZE};
    }

    pub mod path {
        pub use crate::support::path::format_path_relative_to_cwd;
    }

    pub mod secret {
        pub use crate::support::secret::SecretString;
    }

    pub mod ssh {
        pub use crate::model::ssh::SshDeterminismStatus;
    }

    pub mod trust_document {
        pub use crate::model::trust_store::RecipientHandleHint;
    }

    pub mod tty {
        pub use crate::support::tty::is_interactive;
    }

    pub mod validation {
        pub use crate::support::validation::{validate_github_login, validate_member_handle};
    }
}

#[cfg(any(feature = "cli-test-support", test))]
#[doc(hidden)]
pub mod test_support {
    pub mod settings {
        pub mod types {
            pub use crate::config::types::SshSigningMethod;
        }
    }
    pub mod primitives {
        pub use crate::crypto::{
            build_crypto_error, build_crypto_error_with_source, build_crypto_operation_error,
            CryptoError,
        };
        pub mod aead {
            pub mod xchacha {
                pub use crate::crypto::aead::xchacha::{
                    decrypt, encrypt, encrypt_with_nonce, NONCE_SIZE,
                };
            }
        }
        pub mod kdf {
            pub use crate::crypto::kdf::{expand, expand_to_array};
        }
        pub mod kem {
            pub use crate::crypto::kem::{
                decode_kem_secret_key, derive_public_key_from_secret, generate_keypair, open_base,
                seal_base, X25519PublicKey, X25519SecretKey,
            };
        }
        pub mod sign {
            pub use crate::crypto::sign::{
                sign_artifact_bytes, sign_detached_bytes, sign_trust_store_bytes,
                verify_artifact_bytes, verify_trust_store_bytes,
            };
        }
        pub mod types {
            pub mod data {
                pub use crate::crypto::types::data::{Aad, Ciphertext, Enc, Ikm, Info, Plaintext};
            }
            pub mod keys {
                pub use crate::crypto::types::keys::{Cek, MasterKey, XChaChaKey};
            }
            pub mod primitives {
                pub use crate::crypto::types::primitives::{
                    AsHkdfSalt, HkdfSalt, KvSalt, PrivateKeyIkmSalt, XChaChaNonce,
                };
            }
        }
    }
    pub mod operations {
        pub mod config {
            pub use crate::feature::config::{
                load_global_config, resolve_config_location, resolve_config_value, validate_key,
                ConfigLocation, ConfigScope, ConfigValueResolution,
            };
        }
        pub mod context {
            pub mod crypto {
                pub use crate::feature::context::crypto::{
                    load_crypto_context_from_keystore, CryptoContext, DecryptionKeyInfo,
                    DecryptionResult, LocalKeyAccess,
                };
            }
            pub mod env_key {
                pub use crate::feature::context::env_key::{
                    is_env_key_mode, load_private_key_from_env, EnvKeyLoadResult,
                };
            }
            pub mod expiry {
                pub use crate::feature::context::expiry::{
                    build_key_expiry_warning, build_recipient_key_expiry_warning,
                    build_signing_key_expiry_warning, check_key_expiry,
                    collect_recipient_key_expiry_warnings, enforce_key_not_expired_for_signing,
                    enforce_recipient_key_not_expired, KeyExpiryStatus, VerifiedExpiresAt,
                };
            }
        }
        pub mod decrypt {
            pub mod file {
                pub use crate::feature::decrypt::file::{
                    decrypt_file_document, decrypt_file_document_with_context,
                };
            }
        }
        pub mod disclosure {
            pub use crate::feature::disclosure::{add_to_removed_history, merge_removed_history};
        }
        pub mod encrypt {
            pub use crate::feature::encrypt::encrypt_file_content;
            pub mod file {
                pub use crate::feature::encrypt::file::encrypt_file_document;
            }
        }
        pub mod envelope {
            pub mod binding {
                pub use crate::feature::envelope::binding::{
                    build_file_payload_aad, build_file_wrap_info, build_kv_cek_info,
                    build_kv_entry_aad, build_kv_wrap_info,
                };
            }
            pub mod cek {
                pub use crate::feature::envelope::cek::derive_cek;
            }
            pub mod signature {
                pub use crate::feature::envelope::signature::{
                    build_signing_context, sign_file_document, verify_file_signature,
                    verify_kv_signature, SigningContext, VerifiedSigningContext,
                };
            }
            pub mod unwrap {
                pub use crate::feature::envelope::unwrap::{
                    parse_master_key_from_plaintext, unwrap_master_key, unwrap_master_key_for_file,
                    unwrap_master_key_for_file_with_context, unwrap_master_key_for_kv,
                    unwrap_master_key_for_kv_with_context, unwrap_master_key_from_item,
                };
            }
            pub mod wrap {
                pub use crate::feature::envelope::wrap::{
                    build_wrap_item, build_wrap_item_for_file, build_wrap_item_for_kv,
                    build_wraps_for_recipients, WrapFormat,
                };
            }
        }
        pub mod inspect {
            pub use crate::feature::inspect::{build_inspect_view, InspectOutput, InspectSection};
            pub mod verification {
                pub use crate::feature::inspect::verification::{
                    build_online_verification_section, OnlineVerificationDisplay,
                };
            }
        }
        pub mod key {
            pub mod generate {
                pub use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
            }
            pub mod manage {
                pub mod export {
                    pub use crate::feature::key::manage::export::export_key;
                }
                pub mod mutation {
                    pub use crate::feature::key::manage::mutation::{activate_key, remove_key};
                }
                pub mod query {
                    pub use crate::feature::key::manage::query::list_keys;
                }
            }
            pub mod material {
                pub use crate::feature::key::material::{
                    build_identity_keys, build_private_key_plaintext, generate_keypairs,
                    validate_ed25519_consistency, validate_okp_key, validate_x25519_consistency,
                    KeypairMaterial,
                };
            }
            pub mod portable_export {
                pub use crate::feature::key::portable_export::{
                    build_password_strength_warning, export_private_key_portable,
                    PortableExportOutput,
                };
            }
            pub mod protection {
                pub mod binding {
                    pub use crate::feature::key::protection::binding::build_private_key_aad;
                }
                pub mod encryption {
                    pub use crate::feature::key::protection::encryption::{
                        decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
                    };
                }
                pub mod key_derivation {
                    pub use crate::feature::key::protection::key_derivation::{
                        build_sign_message, derive_key_from_ssh,
                    };
                }
                pub mod password_encryption {
                    pub use crate::feature::key::protection::password_encryption::{
                        decrypt_private_key_with_password, encrypt_private_key_with_password,
                    };
                }
                pub mod password_key_derivation {
                    pub use crate::feature::key::protection::password_key_derivation::{
                        derive_key_from_password, generate_hkdf_salt, generate_ikm_salt,
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
        pub mod kv {
            pub mod builder {
                pub use crate::feature::kv::builder::KvDocumentBuilder;
            }
            pub mod decrypt {
                pub use crate::feature::kv::decrypt::{
                    decrypt_kv_document, decrypt_kv_single_entry,
                };
            }
            pub mod encrypt {
                pub use crate::feature::kv::encrypt::encrypt_kv_document;
            }
            pub mod mutate {
                pub use crate::feature::kv::mutate::{
                    set_kv_entry_with_recipients, unset_kv_entry_with_recipients,
                    KvRecipientSnapshot, KvSetResult, KvWriteContext,
                };
            }
            pub mod types {
                pub use crate::feature::kv::types::KvInputEntry;
            }
        }
        pub mod member {
            pub mod add {
                pub use crate::feature::member::add::add_member_from_file;
            }
            pub mod verification {
                pub use crate::feature::member::verification::verify_member;
            }
        }
        pub mod rewrap {
            pub use crate::feature::rewrap::{rewrap_content, RewrapRequest};
        }
        pub mod trust {
            pub mod judgment {
                pub use crate::feature::trust::judgment::{
                    judge_recipients_trust, judge_signer_trust, ActiveMemberSnapshot,
                    KnownKeyCache, SelfTrustSet, TrustIdentity, TrustJudgment,
                };
            }
            pub mod known_keys {
                pub use crate::feature::trust::known_keys::{
                    add_known_key, find_known_key, judge_known_key, purge_known_keys,
                    remove_known_key, validate_kid_integrity, IntoKnownKid, IntoKnownMemberHandle,
                    KnownKeyIdentity, KnownKeyJudgment,
                };
            }
            pub mod recipient_sets {
                pub use crate::feature::trust::recipient_sets::{
                    compute_recipient_set_hash, find_recipient_handle_mismatch,
                    is_self_only_recipient_set, is_signer_in_recipient_set, judge_recipient_set,
                    normalize_recipient_kids, purge_recipient_sets, remove_recipient_set,
                    upsert_recipient_set, validate_recipient_set_record, ArtifactRecipientSet,
                    RecipientHandleMismatch, RecipientSetJudgment,
                };
            }
            pub mod signature {
                pub use crate::feature::trust::signature::sign_trust_store;
            }
            pub mod verification {
                pub use crate::feature::trust::verification::verify_trust_store;
            }
        }
        pub mod verify {
            pub mod file {
                pub use crate::feature::verify::file::{
                    verify_file_content, verify_file_document, verify_file_document_report,
                };
            }
            pub mod key_loader {
                pub use crate::feature::verify::key_loader::load_verifying_key_from_signature;
            }
            pub mod kv {
                pub mod signature {
                    pub use crate::feature::verify::kv::signature::{
                        verify_kv_content, verify_kv_document, verify_kv_document_report,
                    };
                }
            }
            pub mod public_key {
                pub use crate::feature::verify::public_key::{
                    verify_public_key_with_attestation, verify_recipient_public_keys,
                };
            }
        }
    }
    pub mod wire {
        pub use crate::format::FormatError;
        pub mod content {
            pub use crate::format::content::{EncContent, FileEncContent, KvEncContent};
        }
        pub mod detection {
            pub use crate::format::detection::{detect_format, InputFormat};
        }
        pub mod file {
            pub use crate::format::file::build_file_signature_bytes;
        }
        pub mod jcs {
            pub use crate::format::jcs::{normalize, normalize_to_bytes, normalize_to_string};
        }
        pub mod kid {
            pub use crate::format::kid::derive_public_key_kid;
        }
        pub mod kv {
            pub mod document {
                pub use crate::format::kv::document::{
                    parse_kv_document, validate_kv_file_structure,
                };
            }
            pub mod dotenv {
                pub use crate::format::kv::dotenv::{
                    build_dotenv_string, is_valid_key_name, parse_dotenv, parse_dotenv_value,
                    validate_dotenv_strict,
                };
            }
            pub mod enc {
                pub mod canonical {
                    pub use crate::format::kv::enc::canonical::{
                        build_canonical_bytes, extract_kv_header_tokens,
                        extract_recipients_from_wrap, parse_kv_wrap,
                    };
                }
                pub mod parser {
                    pub use crate::format::kv::enc::parser::KvEncParser;
                }
            }
        }
        pub mod schema {
            pub mod document {
                pub use crate::format::schema::document::{
                    parse_file_enc_bytes, parse_file_enc_str, parse_kv_entry_token,
                    parse_kv_entry_token_with_source, parse_kv_head_token,
                    parse_kv_head_token_with_source, parse_kv_signature_token,
                    parse_kv_signature_token_with_source, parse_kv_wrap_token,
                    parse_kv_wrap_token_with_source, parse_private_key_bytes,
                    parse_private_key_str, parse_public_key_bytes, parse_public_key_str,
                };
            }
            pub mod validator {
                pub use crate::format::schema::validator::{
                    load_embedded_trust_validator, Validator,
                };
            }
        }
        pub mod token {
            pub use crate::format::token::TokenCodec;
        }
        pub mod trust_store {
            pub use crate::format::trust_store::build_trust_store_signature_bytes;
        }
    }
    pub mod storage {
        pub mod config {
            pub mod bootstrap {
                pub use crate::io::config::bootstrap::validate_member_handle;
            }
            pub mod paths {
                pub use crate::io::config::paths::{get_base_dir, get_global_config_path};
            }
            pub mod store {
                pub use crate::io::config::store::{
                    load_config_file, set_config_value, unset_config_value,
                };
            }
        }
        pub mod github {
            pub mod account {
                pub use crate::io::github::account::resolve_github_account_by_login;
                #[cfg(feature = "online")]
                pub use crate::io::github::account::{
                    resolve_github_account_by_login_with_api, GitHubAccountLookupApi,
                    GitHubAccountLookupFuture,
                };
            }
            #[cfg(feature = "online")]
            pub mod http {
                pub use crate::io::github::http::GitHubKeyRecord;
            }
        }
        pub mod keystore {
            pub mod active {
                pub use crate::io::keystore::active::{
                    clear_active_kid, load_active_kid, set_active_kid,
                };
            }
            pub mod helpers {
                pub use crate::io::keystore::helpers::resolve_kid;
            }
            pub mod member {
                pub use crate::io::keystore::member::{
                    find_active_key_document, load_public_keys_for_member,
                    load_single_member_handle_from_keystore, remove_key_directory,
                    select_latest_valid_kid, select_most_recent_kid, ActiveKeyDocument,
                };
            }
            pub mod paths {
                pub use crate::io::keystore::paths::{
                    get_active_file_path_from_root, get_key_path_from_root,
                    get_keystore_root_from_base, get_member_keystore_path_from_root,
                    get_private_key_file_path_from_root, get_public_key_file_path_from_root,
                };
            }
            pub mod public_key_source {
                pub use crate::io::keystore::public_key_source::{
                    KeystorePublicKeySource, PublicKeySource, WorkspacePublicKeySource,
                };
            }
            pub mod public_keys {
                pub use crate::io::keystore::public_keys::load_public_keys_for_member_handles;
            }
            pub mod resolver {
                pub use crate::io::keystore::resolver::KeystoreResolver;
            }
            pub mod signer {
                pub use crate::io::keystore::signer::load_signer_public_key;
            }
            pub mod storage {
                pub use crate::io::keystore::storage::{
                    find_member_by_kid, list_kids, list_member_handles, load_private_key,
                    load_public_key, save_key_pair_atomic,
                };
            }
        }
        pub mod process {
            pub use crate::io::process::execute_command_with_env;
        }
        pub mod ssh {
            pub use crate::io::ssh::SshError;
            pub mod agent {
                pub mod client {
                    pub use crate::io::ssh::agent::client::DefaultAgentSigner;
                }
                pub mod socket {
                    pub use crate::io::ssh::agent::socket::resolve_agent_socket_path;
                }
                pub mod traits {
                    pub use crate::io::ssh::agent::traits::AgentSigner;
                }
                pub mod validation {
                    pub use crate::io::ssh::agent::validation::{
                        find_key_in_agent, validate_agent_has_keys, validate_key_present,
                        AgentIdentity,
                    };
                }
            }
            pub mod backend {
                pub use crate::io::ssh::backend::SignatureBackend;
                pub mod signature_backend {
                    pub use crate::io::ssh::backend::signature_backend::SignatureBackend;
                }
                pub mod ssh_agent {
                    pub use crate::io::ssh::backend::ssh_agent::SshAgentBackend;
                }
                pub mod ssh_keygen {
                    pub use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
                }
            }
            pub mod external {
                pub mod add {
                    pub use crate::io::ssh::external::add::DefaultSshAdd;
                }
                pub mod keygen {
                    pub use crate::io::ssh::external::keygen::DefaultSshKeygen;
                }
                pub mod pubkey {
                    pub use crate::io::ssh::external::pubkey::{
                        collect_ed25519_keys_in_output, load_ed25519_keys_from_agent,
                        load_ssh_key_candidate_from_file, load_ssh_public_key_file,
                        load_ssh_public_key_with_descriptor_trait, SshKeyCandidate,
                    };
                }
                pub mod traits {
                    pub use crate::io::ssh::external::traits::{SshAdd, SshKeygen};
                }
            }
            pub mod openssh_config {
                pub use crate::io::ssh::openssh_config::{
                    extract_config_line_before_comment, find_identity_agent, parse_identity_agent,
                    parse_quoted_value,
                };
            }
            pub mod protocol {
                pub use crate::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
                pub mod base64 {
                    pub use crate::io::ssh::protocol::base64::decode_base64_armored;
                }
                pub mod constants {
                    pub use crate::io::ssh::protocol::constants::{
                        ATTESTATION_METHOD_SSH_SIGN, ATTESTATION_NAMESPACE, KEYGEN_TYPE_ED25519,
                        KEY_PROTECTION_NAMESPACE, KEY_TYPE_ED25519, SSHSIG_ARMOR_BEGIN,
                        SSHSIG_ARMOR_END,
                    };
                }
                pub mod fingerprint {
                    pub use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
                }
                pub mod key_descriptor {
                    pub use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
                }
                pub mod parse {
                    pub use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
                }
                pub mod sshsig {
                    pub use crate::io::ssh::protocol::sshsig::{
                        build_sshsig_signed_data, parse_sshsig_armored, parse_sshsig_blob,
                        SSHSIG_HASHALG, SSHSIG_MAGIC,
                    };
                }
                pub mod types {
                    pub use crate::io::ssh::protocol::types::{
                        Ed25519RawSignature, SshSignatureBlob, SshsigBlob,
                    };
                }
                pub mod wire {
                    pub use crate::io::ssh::protocol::wire::{
                        decode_ssh_string, encode_ssh_string,
                    };
                }
            }
            pub mod verify {
                pub use crate::io::ssh::verify::{
                    build_attestation_signed_data, validate_sshsig_inputs, verify_attestation,
                    verify_sshsig,
                };
            }
        }
        pub mod trust {
            pub mod paths {
                pub use crate::io::trust::paths::{get_trust_store_dir, get_trust_store_file_path};
            }
            pub mod store {
                pub use crate::io::trust::store::{
                    load_trust_store, save_trust_store, TrustStoreLoadResult,
                };
            }
        }
        pub mod verify_online {
            pub use crate::io::verify_online::{
                VerificationResult, VerificationStatus, VerifiedGithubIdentity,
            };
            pub mod github {
                pub use crate::io::verify_online::github::verify_github_account;
                #[cfg(feature = "online")]
                pub use crate::io::verify_online::github::{
                    verify_github_account_with_api, GitHubApiFuture, GitHubVerificationApi,
                };
                pub mod preflight {
                    #[cfg(feature = "online")]
                    pub use crate::io::verify_online::github::preflight::verify_ssh_key_on_github_with_api;
                }
            }
        }
        pub mod workspace {
            pub mod detection {
                pub use crate::io::workspace::detection::{
                    detect_workspace_root, resolve_workspace, resolve_workspace_creation_path,
                    WorkspaceRoot,
                };
            }
            pub mod members {
                pub use crate::io::workspace::members::{
                    list_active_member_handles, load_active_member_files,
                    load_incoming_member_files, load_member_file, load_member_file_from_path,
                    load_member_files, load_verified_member_file_from_path, remove_member,
                };
            }
            pub mod setup {
                pub use crate::io::workspace::setup::{
                    check_workspace_has_active_members, ensure_workspace_structure,
                    save_member_document, validate_workspace_exists,
                };
            }
        }
    }
    pub mod domain {
        pub mod common {
            pub use crate::model::common::{
                normalize_recipients, validate_wrap_items, RecipientWrap, RemovedRecipient,
                WrapAlgorithm, WrapItem, WrapSet,
            };
        }
        pub mod file_enc {
            pub use crate::model::file_enc::{
                FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
                FilePayloadCiphertext, FilePayloadHeader, VerifiedFileEncDocument,
            };
        }
        pub mod identity {
            pub use crate::model::identity::{Kid, MemberHandle};
        }
        pub mod kv_enc {
            pub mod document {
                pub use crate::model::kv_enc::document::KvEncDocument;
            }
            pub mod entry {
                pub use crate::model::kv_enc::entry::KvEntryValue;
            }
            pub mod header {
                pub use crate::model::kv_enc::header::{KvFileAlgorithm, KvHeader, KvWrap};
            }
            pub mod line {
                pub use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};
            }
            pub mod verified {
                pub use crate::model::kv_enc::verified::VerifiedKvEncDocument;
            }
        }
        pub mod private_key {
            pub use crate::model::private_key::{
                IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm,
                PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
            };
        }
        pub mod public_key {
            pub use crate::model::public_key::{
                Attestation, AttestationProof, AttestedIdentity, BindingClaims, GithubAccount,
                Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
                VerifiedBindingClaims, VerifiedPublicKeyAttested, VerifiedRecipientKey,
            };
        }
        pub mod signature {
            pub use crate::model::signature::ArtifactSignature;
        }
        pub mod ssh {
            pub use crate::model::ssh::SshDeterminismStatus;
        }
        pub mod trust_store {
            pub use crate::model::trust_store::{
                KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount,
                RecipientHandleHint, RecipientSetApprovalVia, RecipientSetRecord,
                TrustStoreDocument, TrustStoreProtected, TrustStoreSignature,
            };
        }
        pub mod verification {
            pub use crate::model::verification::{
                BindingVerificationProof, ExpiryProof, SelfSignatureProof,
                SignatureVerificationProof, VerifyingKeySource,
            };
        }
        pub mod verified {
            pub use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
        }
        pub mod wire {
            pub mod algorithm {
                pub use crate::model::wire::algorithm::{
                    AEAD_XCHACHA20_POLY1305, HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                    SIGNATURE_ED25519,
                };
            }
            pub mod context {
                pub use crate::model::wire::context::{
                    AAD_KV_ENTRY_PAYLOAD_V6, HKDF_INFO_PRIVATE_KEY_SSHSIG_V7,
                    HPKE_INFO_FILE_WRAP_V5, HPKE_INFO_KV_WRAP_V6,
                    SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7,
                };
            }
            pub mod format {
                pub use crate::model::wire::format::{
                    FILE_ENC_V5, FILE_PAYLOAD_V5, LOCAL_TRUST_V5, PRIVATE_KEY_V7, PUBLIC_KEY_V6,
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
                pub use crate::support::codec::base64_public::{
                    decode_base64_standard, decode_base64url_nopad, decode_base64url_nopad_array,
                    decode_base64url_nopad_ciphertext, decode_base64url_nopad_token,
                    encode_base64_standard, encode_base64_standard_nopad, encode_base64url_nopad,
                };
            }
            pub mod base64_secret {
                pub use crate::support::codec::base64_secret::{
                    decode_base64url_nopad_secret_32, decode_base64url_nopad_secret_64,
                    decode_base64url_nopad_secret_bytes, encode_base64url_nopad_secret_32,
                    encode_base64url_nopad_secret_64, encode_base64url_nopad_secret_bytes,
                };
            }
        }
        pub mod display {
            pub use crate::support::display::{
                sanitize_display_field, sanitize_display_field_with_limit,
            };
        }
        pub mod fs {
            pub use crate::support::fs::{
                check_permission, check_permission_chain, ensure_dir, ensure_dir_restricted,
                ensure_text_file_matches_snapshot, ensure_text_file_matches_snapshot_with_limit,
                list_dir, load_bytes_with_limit, load_text, load_text_with_limit,
            };
            pub mod atomic {
                pub use crate::support::fs::atomic::{
                    save_bytes, save_json, save_json_restricted, save_text, save_text_restricted,
                };
            }
            pub mod lock {
                pub use crate::support::fs::lock::with_file_lock;
            }
        }
        pub mod kid {
            pub use crate::support::kid::{
                format_kid_display, format_kid_display_lossy, format_kid_half_display,
                format_kid_half_display_lossy, normalize_kid, normalize_kid_query,
                resolve_unique_kid,
            };
        }
        pub mod limits {
            pub use crate::support::limits::{
                MAX_ACTIVE_KID_FILE_SIZE, MAX_CONFIG_FILE_SIZE, MAX_JSON_DEPTH,
                MAX_JSON_DOCUMENT_READ_SIZE, MAX_WRAP_ITEMS,
            };
        }
        pub mod secret {
            pub use crate::support::secret::{
                SecretArray, SecretBytes, SecretEnvMap, SecretString,
            };
        }
        pub mod time {
            pub use crate::support::time::{format_timestamp_rfc3339, generate_current_timestamp};
        }
        pub mod tty {
            pub use crate::support::tty::{is_interactive, set_interactive_override};
        }
        pub mod validation {
            pub use crate::support::validation::{
                validate_github_login, validate_kv_file_basename, validate_member_handle,
            };
        }
    }
}
