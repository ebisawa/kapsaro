// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn cli_api_test_support_is_hidden_and_feature_gated() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let test_support = test_support_section(&content);

    assert!(content.contains("#[cfg(any(feature = \"cli-test-support\", test))]"));
    assert!(content.contains("pub mod test_support {"));

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
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");

    assert!(content.contains("pub mod context {"));
    assert!(content.contains("pub mod file {"));
    assert!(content.contains("pub mod kv {"));
    assert!(content.contains("pub mod trust {"));
    assert!(content.contains("pub mod presentation {"));
    assert!(content.contains("execute_decrypt_file_command"));
    assert!(content.contains("execute_inspect_file_command"));
    assert!(content.contains("InspectOutput, InspectSection"));
    assert!(content.contains("pub use crate::support::fs::atomic::{save_bytes, save_text};"));
    assert!(content.contains("pub mod test_support {"));
    assert!(content.contains("pub mod app {"));
}

#[test]
fn api_module_does_not_flat_reexport_facades() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/api/mod.rs").expect("read api source");

    assert!(
        !content.contains("pub use "),
        "api/mod.rs must keep canonical module paths instead of flat re-exports"
    );
}

#[test]
fn cli_api_test_support_keeps_single_canonical_paths() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let test_support = test_support_section(&content);

    assert_absent(
        test_support,
        "pub mod signature_backend {",
        "SignatureBackend must be exposed only through storage::ssh::backend",
    );
    assert_absent(
        test_support,
        "pub use crate::io::ssh::protocol::{",
        "SSH protocol helpers must be exposed through their purpose-specific modules",
    );
    assert_absent(
        test_support,
        "pub use crate::io::ssh::protocol::build_sha256_fingerprint",
        "build_sha256_fingerprint must use storage::ssh::protocol::fingerprint",
    );
    assert_absent(
        test_support,
        "pub use crate::io::ssh::protocol::SshKeyDescriptor",
        "SshKeyDescriptor must use storage::ssh::protocol::key_descriptor",
    );
    assert_absent(
        test_support,
        "pub use crate::io::ssh::backend::signature_backend::SignatureBackend",
        "SignatureBackend must not be duplicated under signature_backend",
    );
    assert_absent(
        test_support,
        "::*;",
        "test_support must use explicit re-export allow-lists",
    );
}

#[test]
fn cli_api_does_not_reintroduce_broad_test_support_exports() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let test_support = test_support_section(&content);

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
        "SecretEnvMap",
        "PortableExportOutput",
        "ActiveKeyDocument",
        "TrustStoreLoadResult",
        "RecipientWrap",
    ] {
        assert_absent(
            test_support,
            obsolete_export,
            "test_support must keep a narrow purpose-based allow-list",
        );
    }
}

#[test]
fn core_internal_roots_do_not_keep_dead_convenience_reexports() {
    let cases = [
        (
            "crates/secretenv-core/src/feature/trust/judgment.rs",
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
            "crates/secretenv-core/src/io/workspace/detection.rs",
            [
                "resolve_optional_workspace,",
                "resolve_workspace_with_base,",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/secretenv-core/src/io/workspace/members.rs",
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
            "crates/secretenv-core/src/io/workspace/members/store.rs",
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
            "crates/secretenv-core/src/support/fs.rs",
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
        "crates/secretenv-core/src/feature/key/portable_export.rs",
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
            !content.contains("secretenv_core::cli_api::test_support"),
            "{display_path} must not use hidden test support"
        );

        for root in [
            "app", "config", "crypto", "feature", "format", "io", "model", "support",
        ] {
            let direct_path = format!("secretenv_core::{root}::");
            assert!(
                !content.contains(&direct_path),
                "{display_path} must use cli_api/app or cli_api/presentation instead of {direct_path}"
            );
        }

        assert_core_alias_does_not_reach_hidden_surface(&content, &path);
    }
}

#[test]
fn public_entrypoints_do_not_keep_redundant_modules() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/lib.rs").expect("read core lib source");

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
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let app_section = cli_app_section(&content);

    assert_absent(
        app_section,
        "pub use crate::feature::kv::types::KvInputEntry",
        "cli_api::app must expose app-owned DTOs instead of feature DTOs",
    );
    assert!(
        content.contains("pub use crate::app::kv::types::{"),
        "cli_api::app::kv::types must expose app-owned KV DTOs"
    );
}

#[test]
fn online_test_support_modules_are_feature_gated() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");

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
        fs::read_to_string("crates/secretenv-core/src/lib.rs").expect("read core lib source");

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

fn test_support_section(content: &str) -> &str {
    content
        .split("#[cfg(any(feature = \"cli-test-support\", test))]")
        .nth(1)
        .expect("test_support cfg section")
}

fn cli_app_section(content: &str) -> &str {
    content
        .split("pub mod presentation {")
        .next()
        .expect("cli_api app section")
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
                .strip_prefix("use secretenv_core as ")
                .or_else(|| trimmed.strip_prefix("extern crate secretenv_core as "))?;
            alias.trim_end_matches(';').split_whitespace().next()
        })
        .collect()
}
