// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::execution::{
    build_read_execution_warnings, build_write_execution_warnings, resolve_read_execution,
    resolve_write_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::errors::build_default_kv_file_not_found_error;
use crate::format::content::KvEncContent;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_KV_ENC_FILE_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::validation::validate_kv_file_basename;
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub(crate) struct KvFileTarget {
    pub workspace_root: WorkspaceRoot,
    pub file_path: PathBuf,
}

impl KvFileTarget {
    pub(crate) fn resolve(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let workspace_root = require_workspace(options, "kv access")?;
        let name = match file_name {
            Some(supplied) => {
                validate_kv_file_basename(supplied)?;
                supplied
            }
            None => DEFAULT_KV_ENC_BASENAME,
        };
        let file_path = workspace_root
            .secrets_dir()
            .join(format!("{name}{KV_ENC_EXTENSION}"));

        Ok(Self {
            workspace_root,
            file_path,
        })
    }
}

pub(crate) struct KvFileSession {
    pub target: KvFileTarget,
    content: String,
}

impl KvFileSession {
    pub(crate) fn load(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let target = KvFileTarget::resolve(options, file_name)?;
        Self::load_target(target)
    }

    pub(crate) fn load_target(target: KvFileTarget) -> Result<Self> {
        if !target.file_path.exists() {
            return Err(build_default_kv_file_not_found_error(&target.file_path));
        }

        let content = load_text_with_limit(&target.file_path, MAX_KV_ENC_FILE_SIZE, "kv-enc file")?;
        Ok(Self { target, content })
    }
    pub(crate) fn kv_content(&self) -> KvEncContent {
        KvEncContent::new_unchecked_with_source(
            self.content.clone(),
            format_path_relative_to_cwd(&self.target.file_path),
        )
    }
}

pub(crate) struct KvCommandSession {
    pub target: KvFileTarget,
    pub execution: ExecutionContext,
    pub warnings: Vec<String>,
}

impl KvCommandSession {
    pub(crate) fn resolve_read(
        options: &CommonCommandOptions,
        member_handle: Option<String>,
        file_name: Option<&str>,
        ssh_ctx: Option<SshSigningContextResolution>,
    ) -> Result<Self> {
        let target = KvFileTarget::resolve(options, file_name)?;
        let execution = resolve_read_execution(options, member_handle, None, ssh_ctx)?;
        let warnings = build_read_execution_warnings(&execution)?;
        Ok(Self {
            target,
            execution,
            warnings,
        })
    }

    pub(crate) fn resolve_write(
        options: &CommonCommandOptions,
        member_handle: Option<String>,
        file_name: Option<&str>,
        ssh_ctx: Option<SshSigningContextResolution>,
    ) -> Result<Self> {
        let target = KvFileTarget::resolve(options, file_name)?;
        let execution = resolve_write_execution(options, member_handle, ssh_ctx)?;
        let warnings = build_write_execution_warnings(&execution)?;
        Ok(Self {
            target,
            execution,
            warnings,
        })
    }

    pub(crate) fn load_required_file(&self) -> Result<KvFileSession> {
        KvFileSession::load_target(self.target.clone())
    }
}

pub(crate) fn load_existing_content(
    target: &KvFileTarget,
    allow_missing: bool,
) -> Result<Option<KvEncContent>> {
    if target.file_path.exists() {
        let content = load_text_with_limit(&target.file_path, MAX_KV_ENC_FILE_SIZE, "kv-enc file")?;
        Ok(Some(KvEncContent::new_unchecked_with_source(
            content,
            format_path_relative_to_cwd(&target.file_path),
        )))
    } else if allow_missing {
        Ok(None)
    } else {
        Err(Error::Config {
            message: format!("File not found: {}", target.file_path.display()),
        })
    }
}
