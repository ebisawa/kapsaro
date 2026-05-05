// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared document store permission handling.

use crate::support::fs::{atomic, check_permission_chain, load_text_with_limit};
use crate::{Error, Result};
use serde::Serialize;
use std::marker::PhantomData;
use std::path::Path;

pub(crate) trait PermissionPolicy {
    fn evaluate(warnings: Vec<String>) -> Result<Vec<String>>;
}

pub(crate) struct FailOnPermissionWarning;

impl PermissionPolicy for FailOnPermissionWarning {
    fn evaluate(warnings: Vec<String>) -> Result<Vec<String>> {
        if let Some(warning) = warnings.into_iter().next() {
            return Err(Error::build_io_error(warning));
        }
        Ok(Vec::new())
    }
}

pub(crate) struct CollectPermissionWarnings;

impl PermissionPolicy for CollectPermissionWarnings {
    fn evaluate(warnings: Vec<String>) -> Result<Vec<String>> {
        Ok(warnings)
    }
}

#[derive(Debug)]
pub(crate) struct LoadedDocument<T> {
    pub(crate) document: T,
    pub(crate) permission_warnings: Vec<String>,
}

pub(crate) struct DocumentStore<P> {
    _policy: PhantomData<P>,
}

impl<P> DocumentStore<P>
where
    P: PermissionPolicy,
{
    pub(crate) fn load_required<T>(
        path: &Path,
        base_dir: &Path,
        max_size: usize,
        subject: &str,
        parse: impl FnOnce(&str) -> Result<T>,
    ) -> Result<LoadedDocument<T>> {
        let warnings = P::evaluate(check_permission_chain(path, base_dir))?;
        let content = load_text_with_limit(path, max_size, subject)?;
        let document = parse(&content)?;
        Ok(LoadedDocument {
            document,
            permission_warnings: warnings,
        })
    }

    pub(crate) fn load_optional<T>(
        path: &Path,
        base_dir: &Path,
        max_size: usize,
        subject: &str,
        parse: impl FnOnce(&str) -> Result<T>,
    ) -> Result<Option<LoadedDocument<T>>> {
        if !path.exists() {
            return Ok(None);
        }
        Self::load_required(path, base_dir, max_size, subject, parse).map(Some)
    }

    pub(crate) fn save_json_restricted<T>(path: &Path, document: &T) -> Result<()>
    where
        T: Serialize,
    {
        atomic::save_json_restricted(path, document)
    }

    pub(crate) fn save_text_restricted(path: &Path, content: &str) -> Result<()> {
        atomic::save_text_restricted(path, content)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/io_document_store_test.rs"]
mod tests;
