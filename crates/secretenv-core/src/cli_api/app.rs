// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI application API allow-list.
//! This module exposes app-layer entry points used by the first-party CLI.

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
        pub use crate::app::context::options::{
            resolve_allow_expired_key_option, CommonCommandOptions,
        };
    }

    pub mod ssh {
        pub use crate::app::context::ssh::{
            build_ssh_signing_context, resolve_ssh_context_by_active_key,
            resolve_ssh_key_candidates, SshKeyCandidateView, SshSigningContextResolution,
        };
    }
}

pub mod doctor {
    pub use crate::app::doctor::{execute_doctor_command, DoctorRequest};

    pub mod types {
        pub use crate::app::doctor::types::{
            DoctorCategory, DoctorCheck, DoctorReport, DoctorStatus, DoctorSubject,
        };
    }
}

pub mod file {
    pub mod decrypt {
        pub use crate::app::file::decrypt::{
            execute_decrypt_file_command, resolve_decrypt_file_command,
            validate_decrypt_file_input, DecryptFileCommand,
        };
    }

    pub mod encrypt {
        pub use crate::app::file::encrypt::{
            execute_encrypt_file_command_with_recipient_set_confirmation,
            resolve_encrypt_file_command, EncryptFileCommand,
        };
    }

    pub mod inspect {
        pub use crate::app::file::inspect::{
            execute_inspect_file_command, InspectCommand, InspectOutput, InspectSection,
        };
    }
}

pub mod key {
    pub mod generate {
        pub use crate::app::key::generate::generate_key_command;
    }

    pub mod manage {
        use crate::api::secret::SecretString;
        use crate::app::context::options::CommonCommandOptions;
        use crate::app::context::ssh::SshSigningContextResolution;
        use crate::app::key::types::KeyExportPrivateResult;
        use crate::Result;

        pub use crate::app::key::manage::{
            activate_key_command, export_key_command, list_keys_command, remove_key_command,
            validate_kid,
        };

        pub fn export_private_key_command(
            options: &CommonCommandOptions,
            member_handle: String,
            kid: Option<String>,
            password: &SecretString,
            ssh_ctx: SshSigningContextResolution,
        ) -> Result<KeyExportPrivateResult> {
            crate::app::key::manage::export_private_key_command(
                options,
                member_handle,
                kid,
                password.as_inner(),
                ssh_ctx,
            )
        }
    }

    pub mod types {
        pub use crate::app::key::types::{
            KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyGenerationResult,
            KeyInfo, KeyListResult, KeyRemoveResult,
        };
    }
}

pub mod kv {
    pub mod mutation {
        use crate::api::kv::KvInputEntry as ApiKvInputEntry;
        use crate::app::kv::types::KvInputEntry as AppKvInputEntry;
        use crate::app::trust::{ArtifactRecipientTrustOutcome, WriteTrustPolicy};
        use crate::Result;

        pub use crate::app::kv::mutation::{
            import_kv_command_with_recipient_set_confirmation, resolve_mutation_write_plan,
            unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
        };

        pub fn set_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
            plan: &MutationWriteTrustPlan<P>,
            entries: Vec<ApiKvInputEntry>,
            success_message: Option<&str>,
            confirm_recipient_set: ConfirmRecipientSet,
        ) -> Result<crate::app::kv::types::KvWriteOutcome>
        where
            P: WriteTrustPolicy,
            ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
        {
            crate::app::kv::mutation::set_kv_command_with_recipient_set_confirmation(
                plan,
                entries.into_iter().map(to_app_entry).collect(),
                success_message,
                confirm_recipient_set,
            )
        }

        fn to_app_entry(entry: ApiKvInputEntry) -> AppKvInputEntry {
            let (key, value) = entry.into_secret_parts();
            AppKvInputEntry::new_secret(key, value.into_inner())
        }
    }

    pub mod query {
        pub use crate::app::kv::query::{
            execute_kv_read_command, list_kv_command, resolve_kv_read_command, KvReadCommand,
        };
    }

    pub mod types {
        pub use crate::app::kv::types::{
            KvDisclosedEntry, KvImportResult, KvReadMode, KvReadResult, KvWriteOutcome,
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
        RecipientTrustOutcome, RunPolicy, SetPolicy, SignerTrustOutcome, TrustApprovalCandidate,
        UnsetPolicy, WriteTrustPolicy,
    };

    pub mod enforcement {
        pub use crate::app::trust::{
            ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
        };
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
            build_trust_store_reset_plan, execute_trust_store_reset, requires_trust_store_reset,
            TrustStoreResetPlan,
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
