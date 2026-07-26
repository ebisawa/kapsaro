// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Repository-level check that Ed25519 verification stays strict.
//! Guards the property that accepting a signature implies a private key holder.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const VERIFIER_TRAIT_IMPORT: &str = "ed25519_dalek::Verifier";
const STRICT_VERIFICATION_CALL: &str = "verify_strict(";
const SIGN_MODULE: &str = "crates/kapsaro-core/src/crypto/sign.rs";

/// `VerifyingKey::verify` is reachable only through the `Verifier` trait, while
/// `verify_strict` is an inherent method. Keeping the trait out of production
/// sources therefore rules out the permissive form.
#[test]
fn test_production_sources_avoid_the_permissive_verifier_trait() {
    let importing = production_sources()
        .into_iter()
        .filter(|path| file_mentions(path, VERIFIER_TRAIT_IMPORT))
        .map(|path| display_path(&path))
        .collect::<BTreeSet<_>>();

    assert!(
        importing.is_empty(),
        "these sources reach Ed25519 verification through the permissive \
         Verifier trait; route them through crypto::sign instead: {importing:?}",
    );
}

#[test]
fn test_signature_primitive_module_uses_strict_verification() {
    let path = repo_root().join(SIGN_MODULE);

    assert!(
        file_mentions(&path, STRICT_VERIFICATION_CALL),
        "{SIGN_MODULE} must call verify_strict",
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn display_path(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn file_mentions(path: &Path, needle: &str) -> bool {
    fs::read_to_string(path).is_ok_and(|contents| contents.contains(needle))
}

fn production_sources() -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for root in ["src", "crates/kapsaro-core/src"] {
        collect_rust_sources(&repo_root().join(root), &mut sources);
    }
    sources
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            sources.push(path);
        }
    }
}
