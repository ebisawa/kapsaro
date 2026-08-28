// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Boundary test for `kapsaro_core::cli_api`, the internal API the first-party CLI builds on.
//! Each half is pinned symbol by symbol: `presentation` through function-pointer bindings that
//! also fix each signature, and `app` and `test_support` through import lists, because a re-export
//! the CLI stopped calling sits inside a `pub mod` where neither `unused_imports` nor `dead_code`
//! would report it. Both forms hold the listed symbols still; neither reports one the module gained.

use std::path::Path;
use std::process::Command;

use kapsaro_core::api::kv::KvInputEntry;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::context::ssh::SshSigningContextResolution;
use kapsaro_core::cli_api::app::key::manage::export_private_key_command;
use kapsaro_core::cli_api::app::key::types::KeyExportPrivateResult;
use kapsaro_core::cli_api::app::kv::mutation::{
    set_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
};
use kapsaro_core::cli_api::app::kv::types::KvWriteOutcome;
use kapsaro_core::cli_api::app::trust::{ArtifactRecipientTrustOutcome, SetPolicy};
use kapsaro_core::cli_api::presentation::config::SshSigningMethod;
use kapsaro_core::cli_api::presentation::fs::{
    load_bytes, load_text_with_limit, save_bytes, save_bytes_restricted, save_text,
    save_text_restricted,
};
use kapsaro_core::cli_api::presentation::kid::{format_kid_display, format_kid_display_lossy};
use kapsaro_core::cli_api::presentation::limits::{
    MAX_JSON_DOCUMENT_READ_SIZE, MAX_KV_ENC_FILE_SIZE,
};
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::cli_api::presentation::process::remove_parent_kapsaro_env_vars;
use kapsaro_core::cli_api::presentation::ssh::SshDeterminismStatus;
use kapsaro_core::cli_api::presentation::tty::is_interactive;
use kapsaro_core::cli_api::presentation::validation::{
    validate_github_login, validate_member_handle,
};
use kapsaro_core::Result;

/// Every symbol `cli_api::app` re-exports, mirrored module by module and pinned
/// as the path the CLI imports it by. A symbol that moves or disappears breaks
/// this import list. A symbol that is added does not: an import list states what
/// must exist, not what may, so widening the module stays invisible here and is
/// caught in review instead. The two wrapper functions the module defines itself
/// are pinned by `app_wrapper_functions_are_pinned` instead, where their shapes
/// can be held still as well.
#[allow(unused_imports)]
mod app_surface {
    pub mod config {
        pub use kapsaro_core::cli_api::app::config::{
            list_config_command, resolve_config_value_command, set_config_command,
            unset_config_command, ConfigScope, ConfigSetResult, ConfigUnsetResult,
        };
    }

    pub mod context {
        pub use kapsaro_core::cli_api::app::context::env_key::is_env_key_mode;
        pub use kapsaro_core::cli_api::app::context::execution::{
            resolve_read_execution, resolve_read_trust_evaluator, resolve_write_execution,
            ExecutionContext,
        };
        pub use kapsaro_core::cli_api::app::context::identity::{
            build_missing_member_handle_error, resolve_github_user_input,
            resolve_member_handle_input,
        };
        pub use kapsaro_core::cli_api::app::context::options::{
            resolve_allow_expired_key_option, resolve_read_trust_allowances, CommonCommandOptions,
            ReadTrustAllowances,
        };
        pub use kapsaro_core::cli_api::app::context::paths::require_workspace;
        pub use kapsaro_core::cli_api::app::context::ssh::{
            build_ssh_signing_context, resolve_ssh_context_for_member_key,
            resolve_ssh_key_candidates, SshKeyCandidateView, SshSigningContextResolution,
        };
    }

    pub mod doctor {
        pub use kapsaro_core::cli_api::app::doctor::types::{
            DoctorCategory, DoctorCheck, DoctorReason, DoctorReport, DoctorStatus, DoctorSubject,
        };
        pub use kapsaro_core::cli_api::app::doctor::{execute_doctor_command, DoctorRequest};
    }

    pub mod errors {
        pub use kapsaro_core::cli_api::app::errors::build_kv_key_not_found_error;
    }

    pub mod file {
        pub use kapsaro_core::cli_api::app::file::decrypt::evaluate_decrypt_file_trust_plan;
        pub use kapsaro_core::cli_api::app::file::encrypt::{
            execute_encrypt_file_command_with_recipient_set_confirmation,
            resolve_encrypt_file_command, EncryptFileCommand,
        };
        pub use kapsaro_core::cli_api::app::file::inspect::{
            execute_inspect_file_command, InspectCommand, InspectOutput, InspectSection,
        };
    }

    pub mod key {
        pub use kapsaro_core::cli_api::app::key::generate::{
            generate_key_command, KeyExpiryRequest, KeyGenerationHome,
        };
        pub use kapsaro_core::cli_api::app::key::manage::{
            activate_key_command, export_key_command, list_keys_command, remove_key_command,
            validate_kid,
        };
        pub use kapsaro_core::cli_api::app::key::types::{
            KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyGenerationResult,
            KeyInfo, KeyListResult, KeyRemoveResult,
        };
    }

    pub mod kv {
        pub use kapsaro_core::cli_api::app::kv::mutation::{
            import_kv_command_with_recipient_set_confirmation,
            reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
            unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
        };
        pub use kapsaro_core::cli_api::app::kv::query::{
            evaluate_kv_read_trust_plan, load_kv_read_input, KvReadInput,
        };
        pub use kapsaro_core::cli_api::app::kv::types::{KvImportResult, KvWriteOutcome};
    }

    pub mod member {
        pub use kapsaro_core::cli_api::app::member::approval::{
            evaluate_members_for_approval, save_member_approvals, MemberApprovalEvaluation,
            MemberApprovalResult,
        };
        pub use kapsaro_core::cli_api::app::member::mutation::{
            add_member, evaluate_member_removal, remove_member,
        };
        pub use kapsaro_core::cli_api::app::member::query::{
            list_members, load_member_show_result,
        };
        pub use kapsaro_core::cli_api::app::member::types::{
            MemberDocumentStatus, MemberDocumentView, MemberGithubClaim, MemberListEntry,
            MemberListResult, MemberRemovalReport, MemberRemoveResult, MemberShowResult,
            MemberVerificationResult, MembershipStatus,
        };
        pub use kapsaro_core::cli_api::app::member::verification::verify_members;
    }

    pub mod registration {
        pub use kapsaro_core::cli_api::app::registration::command::{
            evaluate_registration_decision, execute_registration_decision,
            resolve_registration_command, RegistrationDecision,
        };
        pub use kapsaro_core::cli_api::app::registration::key_plan::{
            open_registration_local_state, RegistrationLocalState,
        };
        pub use kapsaro_core::cli_api::app::registration::types::{
            MemberKeySetupResult, RegistrationCommand, RegistrationKeyPlan, RegistrationMode,
            RegistrationOutcome, RegistrationResult, RegistrationTarget,
        };
        pub use kapsaro_core::cli_api::app::registration::{
            ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
        };
    }

    pub mod rewrap {
        pub use kapsaro_core::cli_api::app::rewrap::promotion::{
            PromotionReviewFailure, PromotionReviewPrompt, PromotionReviewView,
        };
        pub use kapsaro_core::cli_api::app::rewrap::types::RewrapBatchOutcome;
        pub use kapsaro_core::cli_api::app::rewrap::{
            execute_rewrap_batch_command, RewrapBatchCommandInput,
        };
    }

    pub mod trust {
        pub use kapsaro_core::cli_api::app::trust::enforcement::{
            ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
        };
        pub use kapsaro_core::cli_api::app::trust::list::{
            list_known_keys_command, list_recipient_sets_command, resolve_trust_list_command,
            RecipientSetListItem, RecipientSetListResult, TrustListCommand, TrustListItem,
            TrustListResult,
        };
        pub use kapsaro_core::cli_api::app::trust::management::{
            execute_purge, execute_recipient_set_purge, list_purge_candidates,
            list_recipient_set_purge_candidates, remove_known_key_command,
            remove_recipient_set_command, PurgeOutcome, ReviewedPurgeCandidates,
        };
        pub use kapsaro_core::cli_api::app::trust::recovery::{
            build_trust_store_reset_plan_from_execution,
            build_trust_store_reset_plan_from_list_command, classify_trust_store_reset,
            execute_trust_store_reset, TrustStoreResetCause, TrustStoreResetPlan,
        };
        pub use kapsaro_core::cli_api::app::trust::resign::{
            resign_trust_store_command, TrustStoreResignResult,
        };
        pub use kapsaro_core::cli_api::app::trust::review::{
            execute_read_with_signer_trust, review_write_recipient_trust,
            ReadSignerTrustReviewPlan, SignerTrustLabels, TrustExecutionContext,
            TrustReviewContext, WriteRecipientTrustReviewPlan,
        };
        pub use kapsaro_core::cli_api::app::trust::{
            evaluate_file_after_cli_review, evaluate_kv_after_cli_review,
            ArtifactRecipientTrustOutcome, CommandCapability, GetPolicy, ImportPolicy, ListPolicy,
            ReadArtifactTrustPlan, RecipientTrustOutcome, RunPolicy, SetPolicy, SignerTrustOutcome,
            TrustApprovalCandidate, UnsetPolicy, WriteTrustPolicy,
        };
    }
}

/// Every symbol `cli_api::test_support` exposes, mirrored the same way as
/// `app_surface`. This half exists to keep the module a narrow, purpose-grouped
/// allow-list rather than a mirror of the implementation roots underneath it:
/// each helper the repository tests reach for is named here, so one that moves
/// or is dropped breaks the list. The `online` helpers are listed under the same
/// gate they carry, because the crate is also built without that feature.
#[allow(unused_imports)]
mod test_support_surface {
    pub mod settings {
        pub mod types {
            pub use kapsaro_core::cli_api::test_support::settings::types::SshSigningMethod;
        }
    }

    pub mod primitives {
        pub mod kem {
            pub use kapsaro_core::cli_api::test_support::primitives::kem::generate_keypair;
        }
    }

    pub mod operations {
        pub mod context {
            pub use kapsaro_core::cli_api::test_support::operations::context::crypto::{
                load_crypto_context_from_keystore, CryptoContext,
            };
        }

        pub mod key {
            pub use kapsaro_core::cli_api::test_support::operations::key::generate::{
                generate_key, KeyGenerationOptions,
            };
            pub use kapsaro_core::cli_api::test_support::operations::key::material::generate_keypairs;
            pub use kapsaro_core::cli_api::test_support::operations::key::portable_export::{
                export_private_key_portable, ExportPasswordPolicy, PortableExportOptions,
            };
            pub use kapsaro_core::cli_api::test_support::operations::key::protection::encryption::{
                decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
            };
            pub use kapsaro_core::cli_api::test_support::operations::key::public_key_document::{
                build_attestation, build_public_key, PublicKeyDocumentParams,
            };
            pub use kapsaro_core::cli_api::test_support::operations::key::ssh_binding::SshBindingContext;
        }

        pub mod member {
            pub use kapsaro_core::cli_api::test_support::operations::member::add::add_member_from_file;
            pub use kapsaro_core::cli_api::test_support::operations::member::verification::verify_member_files;
        }

        pub mod trust {
            pub use kapsaro_core::cli_api::test_support::operations::trust::recipient_sets::{
                compute_recipient_set_hash, ArtifactRecipientSet,
            };
            pub use kapsaro_core::cli_api::test_support::operations::trust::signature::sign_trust_store;
        }
    }

    pub mod wire {
        pub use kapsaro_core::cli_api::test_support::wire::public_key::AttestationBodyInput;
        pub use kapsaro_core::cli_api::test_support::wire::schema::document::parse_kv_signature_token;
        pub use kapsaro_core::cli_api::test_support::wire::token::TokenCodec;
    }

    pub mod storage {
        pub mod config {
            pub use kapsaro_core::cli_api::test_support::storage::config::paths::get_base_dir;
        }

        pub mod keystore {
            pub use kapsaro_core::cli_api::test_support::storage::keystore::active::{
                load_active_kid, set_active_kid,
            };
            pub use kapsaro_core::cli_api::test_support::storage::keystore::member::{
                find_active_key_document, load_single_member_handle_from_keystore, ActiveKeyFixture,
            };
            pub use kapsaro_core::cli_api::test_support::storage::keystore::paths::get_keystore_root_from_base;
            pub use kapsaro_core::cli_api::test_support::storage::keystore::storage::{
                list_kids, load_private_key, load_public_key, save_key_pair_atomic,
            };
        }

        pub mod ssh {
            pub use kapsaro_core::cli_api::test_support::storage::ssh::agent::traits::AgentSigner;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::backend::ssh_keygen::SshKeygenBackend;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::external::keygen::DefaultSshKeygen;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::base64::decode_base64_armored;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::{
                KEYGEN_TYPE_ED25519, KEY_PROTECTION_NAMESPACE,
            };
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::key_descriptor::SshKeyDescriptor;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::sshsig::build_sshsig_signed_data;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
            pub use kapsaro_core::cli_api::test_support::storage::ssh::protocol::wire::decode_ssh_string;
        }

        pub mod trust {
            pub use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;
            pub use kapsaro_core::cli_api::test_support::storage::trust::store::save_trust_store;
        }

        pub mod verify_online {
            pub use kapsaro_core::cli_api::test_support::storage::verify_online::VerifiedGithubIdentity;

            #[cfg(feature = "online")]
            pub use kapsaro_core::cli_api::test_support::storage::verify_online::github::{
                verify_github_account_with_api, GitHubApiFuture, GitHubVerificationApi,
            };
        }

        pub mod workspace {
            pub use kapsaro_core::cli_api::test_support::storage::workspace::detection::WorkspaceRoot;
            pub use kapsaro_core::cli_api::test_support::storage::workspace::members::{
                load_active_member_files, load_member_file_from_path,
            };
        }
    }

    pub mod domain {
        pub use kapsaro_core::cli_api::test_support::domain::common::WrapItem;
        pub use kapsaro_core::cli_api::test_support::domain::identity::{Kid, MemberHandle};
        pub use kapsaro_core::cli_api::test_support::domain::private_key::{
            IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyPlaintext,
        };
        pub use kapsaro_core::cli_api::test_support::domain::public_key::{
            build_unverified_recipient_key, Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey,
            PublicKeyProtected, VerifiedRecipientKey,
        };
        pub use kapsaro_core::cli_api::test_support::domain::signature::KeyPossessionProof;
        pub use kapsaro_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;
        pub use kapsaro_core::cli_api::test_support::domain::trust_store::{
            KnownKey, KnownKeyApprovalVia, RecipientHandleHint, RecipientSetApprovalVia,
            RecipientSetRecord, TrustStoreProtected,
        };
        pub use kapsaro_core::cli_api::test_support::domain::verified::{
            DecryptionProof, VerifiedPrivateKey,
        };

        pub mod wire {
            pub use kapsaro_core::cli_api::test_support::domain::wire::format::{
                FILE_ENC_V1, LOCAL_TRUST_V1, PRIVATE_KEY_V1, PUBLIC_KEY_V1,
            };
            pub use kapsaro_core::cli_api::test_support::domain::wire::jwk::{
                CURVE_ED25519, CURVE_X25519,
            };
            pub use kapsaro_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256;
        }
    }

    pub mod helpers {
        pub mod codec {
            pub use kapsaro_core::cli_api::test_support::helpers::codec::base64_public::{
                decode_base64url_nopad_array, encode_base64url_nopad,
            };
            pub use kapsaro_core::cli_api::test_support::helpers::codec::base64_secret::encode_base64url_nopad_secret_32;
        }
        pub mod fs {
            pub use kapsaro_core::cli_api::test_support::helpers::fs::atomic::save_json;
        }
        pub use kapsaro_core::cli_api::test_support::helpers::kid::format_kid_half_display;
        pub use kapsaro_core::cli_api::test_support::helpers::secret::{SecretArray, SecretString};
        pub use kapsaro_core::cli_api::test_support::helpers::time::format_timestamp_rfc3339;
        pub use kapsaro_core::cli_api::test_support::helpers::tty::set_interactive_override;
    }
}

type ExportPrivateKeyCommandFn = fn(
    &CommonCommandOptions,
    String,
    Option<String>,
    &SecretString,
    bool,
    SshSigningContextResolution,
) -> Result<KeyExportPrivateResult>;

type ConfirmRecipientSetFn = fn(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>;

type SetKvCommandFn = for<'a> fn(
    &MutationWriteTrustPlan<'a, SetPolicy>,
    Vec<KvInputEntry>,
    Option<&str>,
    ConfirmRecipientSetFn,
) -> Result<KvWriteOutcome>;

/// `cli_api::app` owns two wrapper functions rather than re-exports, so their
/// shapes are the part of that module only this test can hold still.
#[test]
fn app_wrapper_functions_are_pinned() {
    let _export_private_key_command: ExportPrivateKeyCommandFn = export_private_key_command;

    // Generic over the write policy and the confirmation callback, so the shape
    // is pinned through a closure that fixes both.
    let _set_kv_command_with_recipient_set_confirmation: SetKvCommandFn =
        |plan, entries, success_message, confirm_recipient_set| {
            set_kv_command_with_recipient_set_confirmation(
                plan,
                entries,
                success_message,
                confirm_recipient_set,
            )
        };
}

#[test]
fn presentation_filesystem_helpers_are_pinned() {
    let _save_bytes: fn(&Path, &[u8]) -> Result<()> = save_bytes;
    let _save_text: fn(&Path, &str) -> Result<()> = save_text;
    let _save_bytes_restricted: fn(&Path, &[u8]) -> Result<()> = save_bytes_restricted;
    let _save_text_restricted: fn(&Path, &str) -> Result<()> = save_text_restricted;
    let _load_bytes: fn(&Path) -> Result<Vec<u8>> = load_bytes;
    let _load_text_with_limit: fn(&Path, usize, &str) -> Result<String> = load_text_with_limit;
    let _format_path_relative_to_cwd: fn(&Path) -> String = format_path_relative_to_cwd;
}

#[test]
fn presentation_formatting_helpers_are_pinned() {
    let _format_kid_display: fn(&str) -> Result<String> = format_kid_display;
    let _format_kid_display_lossy: fn(&str) -> String = format_kid_display_lossy;
    let _validate_github_login: fn(&str) -> Result<()> = validate_github_login;
    let _validate_member_handle: fn(&str) -> Result<()> = validate_member_handle;

    assert_eq!(format_kid_display_lossy("not-a-kid"), "not-a-kid");
}

#[test]
fn presentation_environment_helpers_are_pinned() {
    let _remove_parent_kapsaro_env_vars: fn(&mut Command) = remove_parent_kapsaro_env_vars;
    let _is_interactive: fn() -> bool = is_interactive;
}

#[test]
fn presentation_read_limits_are_pinned() {
    let json_limit: usize = MAX_JSON_DOCUMENT_READ_SIZE;
    let kv_limit: usize = MAX_KV_ENC_FILE_SIZE;

    assert_eq!(json_limit, 24 * 1024 * 1024);
    assert_eq!(kv_limit, 16 * 1024 * 1024);
}

#[test]
fn presentation_ssh_types_are_pinned() {
    let signing_methods = [SshSigningMethod::SshAgent, SshSigningMethod::SshKeygen];
    let determinism = [
        SshDeterminismStatus::Verified,
        SshDeterminismStatus::Skipped,
        SshDeterminismStatus::Failed {
            message: "mismatch".to_string(),
        },
    ];

    assert_eq!(signing_methods.len(), 2);
    assert!(determinism[0].is_verified());
}
