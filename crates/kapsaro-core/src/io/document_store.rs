// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared document store permission handling.

use crate::support::fs::relative::{self, DirectoryFd};
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

    pub(crate) fn load_required_at<D, T>(
        dir: &D,
        path: &Path,
        base_dir: &Path,
        max_size: usize,
        subject: &str,
        parse: impl FnOnce(&str) -> Result<T>,
    ) -> Result<LoadedDocument<T>>
    where
        D: DirectoryFd,
    {
        let warnings = P::evaluate(check_permission_chain(path, base_dir))?;
        let content = relative::load_text_with_limit_at(dir, file_name(path)?, max_size, subject)?;
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

    pub(crate) fn load_optional_at<D, T>(
        dir: &D,
        path: &Path,
        base_dir: &Path,
        max_size: usize,
        subject: &str,
        parse: impl FnOnce(&str) -> Result<T>,
    ) -> Result<Option<LoadedDocument<T>>>
    where
        D: DirectoryFd,
    {
        if !relative::file_exists_at(dir, file_name(path)?)? {
            return Ok(None);
        }
        Self::load_required_at(dir, path, base_dir, max_size, subject, parse).map(Some)
    }

    pub(crate) fn save_json_restricted<T>(path: &Path, document: &T) -> Result<()>
    where
        T: Serialize,
    {
        atomic::save_json_restricted(path, document)
    }

    pub(crate) fn save_json_restricted_at<D, T>(dir: &D, path: &Path, document: &T) -> Result<()>
    where
        D: DirectoryFd,
        T: Serialize,
    {
        let json = serde_json::to_string_pretty(document)
            .map_err(Error::build_json_serialization_error)?;
        relative::save_text_restricted_at(dir, file_name(path)?, &json)
    }

    pub(crate) fn save_text_restricted(path: &Path, content: &str) -> Result<()> {
        atomic::save_text_restricted(path, content)
    }
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::build_config_error(format!("Invalid document path '{}'", path.display()))
        })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/io_document_store_test.rs"]
mod tests;
