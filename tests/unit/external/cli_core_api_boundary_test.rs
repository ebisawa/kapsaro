// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn cli_api_test_support_is_hidden_and_feature_gated() {
    let root = cli_api_root_source();
    let test_support = cli_api_test_support_source();

    assert!(root.contains("#[cfg(any(feature = \"cli-test-support\", test))]"));
    assert!(root.contains("#[doc(hidden)]"));
    assert!(root.contains("pub mod test_support;"));

    for new_root in [
        "pub mod settings {",
        "pub mod primitives {",
        "pub mod operations {",
        "pub mod wire {",
        "pub mod storage {",
        "pub mod domain {",
        "pub mod helpers {",
    ] {
        assert!(
            test_support.contains(new_root),
            "test_support is missing redesigned root: {new_root}"
        );
    }
}

#[test]
fn cli_api_uses_explicit_allow_lists() {
    let root = cli_api_root_source();
    let app = cli_api_app_source();
    let presentation = cli_api_presentation_source();
    let test_support = cli_api_test_support_source();
    let content = cli_api_combined_source();

    assert!(root.contains("pub mod app;"));
    assert!(root.contains("pub mod presentation;"));
    assert!(root.contains("pub mod test_support;"));
    assert!(app.contains("pub mod context {"));
    assert!(app.contains("pub mod file {"));
    assert!(app.contains("pub mod kv {"));
    assert!(app.contains("pub mod trust {"));
    assert!(app.contains("execute_decrypt_file_command"));
    assert!(app.contains("execute_inspect_file_command"));
    assert!(app.contains("InspectOutput, InspectSection"));
    assert!(presentation.contains("pub use crate::support::fs::atomic::{save_bytes, save_text};"));
    assert!(test_support.contains("pub mod settings {"));
    assert!(content.contains("pub use crate::app::kv::types::{"));
    assert!(
        content.contains("use crate::api::kv::KvInputEntry as ApiKvInputEntry;"),
        "cli_api app set command bridge must take public api KV entries"
    );
}

#[test]
fn api_module_does_not_flat_reexport_facades() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/api/mod.rs").expect("read api source");

    assert!(
        !content.contains("pub use "),
        "api/mod.rs must keep canonical module paths instead of flat re-exports"
    );
}

#[test]
fn cli_api_test_support_keeps_single_canonical_paths() {
    let test_support = cli_api_test_support_source();

    assert_absent(
        &test_support,
        "pub mod signature_backend {",
        "SignatureBackend must be exposed only through storage::ssh::backend",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::{",
        "SSH protocol helpers must be exposed through their purpose-specific modules",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::build_sha256_fingerprint",
        "build_sha256_fingerprint must use storage::ssh::protocol::fingerprint",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::SshKeyDescriptor",
        "SshKeyDescriptor must use storage::ssh::protocol::key_descriptor",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::backend::signature_backend::SignatureBackend",
        "SignatureBackend must not be duplicated under signature_backend",
    );
    assert_absent(
        &test_support,
        "pub mod bootstrap {",
        "member handle validation must be exposed through helpers::validation",
    );
    assert_absent(
        &test_support,
        "::*;",
        "test_support must use explicit re-export allow-lists",
    );
}

#[test]
fn cli_api_does_not_reintroduce_broad_test_support_exports() {
    let test_support = cli_api_test_support_source();

    for obsolete_export in [
        "build_crypto_operation_error",
        "sign_artifact_bytes",
        "verify_artifact_bytes",
        "AsHkdfSalt",
        "load_global_config",
        "ConfigValueResolution",
        "DecryptionResult",
        "EnvKeyLoadResult",
        "VerifiedExpiresAt",
        "verify_kv_signature",
        "unwrap_master_key_for_kv",
        "build_wrap_item,",
        "IntoKnownKid",
        "find_recipient_handle_mismatch",
        "extract_kv_header_tokens",
        "parse_private_key_str",
        "resolve_github_account_by_login;",
        "select_latest_valid_kid",
        "find_member_by_kid",
        "load_ssh_key_candidate_from_file",
        "SSHSIG_ARMOR_BEGIN",
        "validate_sshsig_inputs",
        "verify_github_account;",
        "normalize_recipients",
        "decode_base64url_nopad_ciphertext",
        "SecretEnvironmentMap",
        "PortableExportOutput",
        "ActiveKeyDocument",
        "TrustStoreLoadResult",
        "RecipientWrap",
    ] {
        assert_absent(
            &test_support,
            obsolete_export,
            "test_support must keep a narrow purpose-based allow-list",
        );
    }
}

#[test]
fn core_internal_roots_do_not_keep_dead_convenience_reexports() {
    let cases = [
        (
            "crates/kapsaro-core/src/feature/trust/judgment.rs",
            [
                "CurrentMemberMatch",
                "KnownKeyMatch",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/detection.rs",
            ["resolve_workspace_with_base,", "", "", "", "", "", "", ""],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/members.rs",
            [
                "promote_incoming_members,",
                "find_active_member_by_kid,",
                "list_member_file_paths,",
                "load_active_member_index_by_kid,",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/members/store.rs",
            [
                "find_active_member_by_kid,",
                "list_member_file_paths,",
                "load_active_member_index_by_kid,",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/support/fs.rs",
            [
                "check_permission,",
                "load_bytes_with_limit,",
                "ensure_text_file_matches_snapshot,",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
    ];

    for (path, obsolete_exports) in cases {
        let content = fs::read_to_string(path).expect("read core source");
        for obsolete_export in obsolete_exports
            .into_iter()
            .filter(|value| !value.is_empty())
        {
            assert_absent(
                &content,
                obsolete_export,
                "core internal root must avoid unused convenience re-exports",
            );
        }
    }
}

#[test]
fn internal_helper_results_are_not_public_surface() {
    let cases = [(
        "crates/kapsaro-core/src/feature/key/portable_export.rs",
        "pub struct PortableExportOutput",
    )];

    for (path, obsolete_visibility) in cases {
        let content = fs::read_to_string(path).expect("read core source");
        assert_absent(
            &content,
            obsolete_visibility,
            "internal helper result types must not be public surface",
        );
    }
}

#[test]
fn production_cli_uses_only_allowed_core_boundaries() {
    for path in rust_files_under(Path::new("src")) {
        let content = fs::read_to_string(&path).expect("read production source");
        let display_path = path.display();

        assert!(
            !content.contains("kapsaro_core::cli_api::test_support"),
            "{display_path} must not use hidden test support"
        );

        for root in [
            "app", "config", "crypto", "feature", "format", "io", "model", "support",
        ] {
            let direct_path = format!("kapsaro_core::{root}::");
            assert!(
                !content.contains(&direct_path),
                "{display_path} must use cli_api/app or cli_api/presentation instead of {direct_path}"
            );
        }

        assert_core_alias_does_not_reach_hidden_surface(&content, &path);
    }
}

#[test]
fn secret_inputs_use_api_facade_boundary() {
    let set = fs::read_to_string("src/cli/set.rs").expect("read set command source");
    let key_operations =
        fs::read_to_string("src/cli/key/operations.rs").expect("read key operations source");

    for (display_path, content) in [
        ("src/cli/set.rs", set.as_str()),
        ("src/cli/key/operations.rs", key_operations.as_str()),
    ] {
        assert_absent(
            content,
            "cli_api::presentation::secret::SecretString",
            "production CLI secret-bearing input must use the public API facade boundary",
        );
        assert!(
            content.contains("api::secret::SecretString"),
            "{display_path} must make the secret input boundary explicit"
        );
    }
}

#[test]
fn cli_api_does_not_reexport_redundant_secret_or_kv_input_facades() {
    let app = cli_api_app_source();
    let presentation = cli_api_presentation_source();

    assert_absent(
        &presentation,
        "pub mod secret",
        "production CLI must use api::secret for secret-bearing input",
    );
    assert_absent(
        &app,
        "KvInputEntry,",
        "cli_api::app::kv::types must not re-export KV input entries",
    );
    assert!(
        app.contains("use crate::api::kv::KvInputEntry as ApiKvInputEntry;"),
        "set command bridge must keep public api KV input as the boundary"
    );
}

#[test]
fn app_cli_boundary_does_not_expose_online_io_status() {
    let cli_app = cli_api_app_source();
    let key_types = fs::read_to_string("crates/kapsaro-core/src/app/key/types.rs")
        .expect("read app key types source");
    let registration_types =
        fs::read_to_string("crates/kapsaro-core/src/app/registration/types.rs")
            .expect("read app registration types source");

    for (display_path, content) in [
        ("crates/kapsaro-core/src/cli_api/app.rs", cli_app.as_str()),
        (
            "crates/kapsaro-core/src/app/key/types.rs",
            key_types.as_str(),
        ),
        (
            "crates/kapsaro-core/src/app/registration/types.rs",
            registration_types.as_str(),
        ),
    ] {
        assert_absent(
            content,
            "crate::io::verify_online::VerificationStatus",
            &format!("{display_path} must expose app-owned online verification status"),
        );
    }

    assert_absent(
        &cli_app,
        "KeyRemoveResult, OnlineVerificationStatus",
        "cli_api::app::key::types must not re-export online status when api::online owns the public path",
    );
    assert_absent(
        &cli_app,
        "MemberKeySetupResult, OnlineVerificationStatus",
        "cli_api::app::registration::types must not re-export online status when api::online owns the public path",
    );
}

#[test]
fn production_cli_uses_api_online_status_boundary() {
    let key_text =
        fs::read_to_string("src/cli/common/output/text/key.rs").expect("read key text source");

    assert!(
        key_text.contains("use kapsaro_core::api::online::OnlineVerificationStatus;"),
        "key text output must use the public api::online status boundary"
    );
    assert_absent(
        &key_text,
        "cli_api::app::key::types::OnlineVerificationStatus",
        "production CLI must not depend on cli_api online status re-exports",
    );
}

#[test]
fn feature_member_layer_does_not_own_file_or_online_io() {
    let member_add = fs::read_to_string("crates/kapsaro-core/src/feature/member/add.rs")
        .expect("read feature member add source");
    let member_verification =
        fs::read_to_string("crates/kapsaro-core/src/feature/member/verification.rs")
            .expect("read feature member verification source");

    for (display_path, content) in [
        (
            "crates/kapsaro-core/src/feature/member/add.rs",
            member_add.as_str(),
        ),
        (
            "crates/kapsaro-core/src/feature/member/verification.rs",
            member_verification.as_str(),
        ),
    ] {
        for forbidden in [
            "load_text_with_limit",
            "save_member_content",
            "load_member_file_from_path",
            "verify_github_account(",
        ] {
            assert_absent(
                content,
                forbidden,
                &format!("{display_path} must keep file and online I/O in app/io"),
            );
        }
    }
}

#[test]
fn public_entrypoints_do_not_keep_redundant_modules() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/lib.rs").expect("read core lib source");

    assert!(
        content.contains("\nmod error;"),
        "error implementation must stay private behind root error re-exports"
    );
    assert!(
        content.contains("pub use error::{Error, ErrorKind, Result};"),
        "root error re-exports must remain the stable error surface"
    );
    for redundant_module in ["pub mod prelude;", "pub mod error;"] {
        assert!(
            !content.contains(redundant_module),
            "core public surface must use canonical api modules and root error exports"
        );
    }
}

#[test]
fn cli_api_app_does_not_reexport_feature_dtos() {
    let app = cli_api_app_source();

    assert_absent(
        &app,
        "pub use crate::feature::kv::types::KvInputEntry",
        "cli_api::app must expose app-owned DTOs instead of feature DTOs",
    );
    assert_absent(
        &app,
        "KvInputEntry,",
        "cli_api::app::kv::types must not expose KV input DTOs; use api::kv::KvInputEntry",
    );
}

#[test]
fn online_test_support_modules_are_feature_gated() {
    let content = cli_api_test_support_source();

    assert!(
        module_is_feature_gated(&content, "pub mod account {"),
        "github account test-support module must be gated as a whole"
    );
    assert!(
        module_is_feature_gated(&content, "pub mod github {"),
        "online verification github test-support module must be gated as a whole"
    );
}

#[test]
fn implementation_roots_stay_crate_private() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/lib.rs").expect("read core lib source");

    assert!(content.contains("\nmod app;"));

    for root in [
        "config", "crypto", "feature", "format", "io", "model", "support",
    ] {
        assert!(
            content.contains(&format!("pub(crate) mod {root};")),
            "{root} must remain crate-private"
        );
        assert!(
            !content.contains(&format!("\npub mod {root};")),
            "{root} must not become a public implementation root"
        );
    }
}

fn cli_api_root_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api.rs").expect("read cli_api root source")
}

fn cli_api_app_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/app.rs").expect("read cli_api app source")
}

fn cli_api_presentation_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/presentation.rs")
        .expect("read cli_api presentation source")
}

fn cli_api_test_support_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/test_support.rs")
        .expect("read cli_api test_support source")
}

fn cli_api_combined_source() -> String {
    [
        cli_api_root_source(),
        cli_api_app_source(),
        cli_api_presentation_source(),
        cli_api_test_support_source(),
    ]
    .join("\n")
}

fn module_is_feature_gated(content: &str, module_header: &str) -> bool {
    content
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| {
            window[0].trim() == "#[cfg(feature = \"online\")]" && window[1].trim() == module_header
        })
}

fn assert_absent(content: &str, needle: &str, message: &str) {
    assert!(!content.contains(needle), "{message}: {needle}");
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read source directory") {
            collect_rust_files(&entry.expect("read source entry").path(), files);
        }
        return;
    }

    if path.extension().is_some_and(|extension| extension == "rs") {
        files.push(path.to_path_buf());
    }
}

fn assert_core_alias_does_not_reach_hidden_surface(content: &str, path: &Path) {
    let aliases = core_aliases(content);
    let display_path = path.display();

    for alias in aliases {
        assert!(
            !content.contains(&format!("{alias}::cli_api::test_support")),
            "{display_path} must not use hidden test support through alias {alias}"
        );

        for root in [
            "app", "config", "crypto", "feature", "format", "io", "model", "support",
        ] {
            assert!(
                !content.contains(&format!("{alias}::{root}::")),
                "{display_path} must not use internal root {root} through alias {alias}"
            );
        }
    }
}

fn core_aliases(content: &str) -> Vec<&str> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let alias = trimmed
                .strip_prefix("use kapsaro_core as ")
                .or_else(|| trimmed.strip_prefix("extern crate kapsaro_core as "))?;
            alias.trim_end_matches(';').split_whitespace().next()
        })
        .collect()
}
