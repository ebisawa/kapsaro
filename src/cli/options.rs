// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared clap option groups for the CLI commands.
//! Keeps parsed CLI flags in a CLI-owned representation.

use clap::Args;
use std::path::PathBuf;

use kapsaro_core::api::ssh::SshSigningMethod;
use kapsaro_core::{Error, Result};

#[derive(Debug, Clone, Default)]
pub(crate) struct CommonOptions {
    pub(crate) home: Option<PathBuf>,
    pub(crate) identity: Option<PathBuf>,
    pub(crate) ssh_agent: bool,
    pub(crate) ssh_keygen: bool,
    pub(crate) workspace: Option<PathBuf>,
}

pub(crate) trait ToCommonOptions {
    fn to_common_options(&self) -> CommonOptions;
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct HomeOption {
    /// Base directory for kapsaro
    #[arg(long)]
    pub(crate) home: Option<PathBuf>,
}

pub(crate) fn resolve_base_dir(home: &HomeOption) -> Result<PathBuf> {
    if let Some(path) = &home.home {
        return Ok(path.clone());
    }
    if let Ok(path) = std::env::var("KAPSARO_HOME") {
        return Ok(PathBuf::from(path));
    }
    std::env::var("HOME")
        .map(|path| PathBuf::from(path).join(".config").join("kapsaro"))
        .map_err(|_| Error::build_config_error("HOME environment variable not set"))
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct WorkspaceOption {
    /// Workspace root directory
    #[arg(long, short = 'w')]
    pub(crate) workspace: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct JsonOption {
    /// Output in JSON format
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct QuietOption {
    /// Quiet mode (suppress non-error status output)
    #[arg(long, short = 'q')]
    pub(crate) quiet: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct VerboseOption {
    /// Verbose output
    #[arg(long, short = 'v')]
    pub(crate) verbose: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct DebugOption {
    /// Enable debug trace logging
    #[arg(long)]
    pub(crate) debug: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct SshSigningOptions {
    /// SSH identity file (private key path)
    #[arg(long = "ssh-identity", short = 'i')]
    pub(crate) identity: Option<PathBuf>,

    /// Use ssh-agent for SSH signing
    #[arg(long, conflicts_with = "ssh_keygen")]
    pub(crate) ssh_agent: bool,

    /// Use ssh-keygen for SSH signing
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_keygen: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct MemberHandleOption {
    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub(crate) member_handle: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct KvStoreNameOption {
    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct ForceOption {
    /// Proceed past the confirmation or safety check that would stop the command
    #[arg(long, short = 'f')]
    pub(crate) force: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct AllowExpiredKeyOption {
    /// Explicitly allow expired keys for this operation
    #[arg(long)]
    pub(crate) allow_expired_key: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct AllowNonMemberOption {
    /// Enable one-shot interactive acceptance for non-member artifact signers
    #[arg(long)]
    pub(crate) allow_non_member: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct LocalOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,
}

/// Local-state options for a command that may have to sign as a side effect.
///
/// No workspace option: these commands act on the local keystore alone, and the
/// signing identity is only resolved when the command actually needs to sign.
#[derive(Debug, Clone, Args, Default)]
pub(crate) struct LocalSigningOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) ssh: SshSigningOptions,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct LocalOutputOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) json: JsonOption,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct WorkspaceOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct WorkspaceOutputOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) json: JsonOption,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct SigningOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) ssh: SshSigningOptions,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct SigningOutputOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) ssh: SshSigningOptions,

    #[command(flatten)]
    pub(crate) json: JsonOption,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct SigningQuietOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) ssh: SshSigningOptions,

    #[command(flatten)]
    pub(crate) quiet: QuietOption,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct SigningQuietOutputOptions {
    #[command(flatten)]
    pub(crate) home: HomeOption,

    #[command(flatten)]
    pub(crate) workspace: WorkspaceOption,

    #[command(flatten)]
    pub(crate) ssh: SshSigningOptions,

    #[command(flatten)]
    pub(crate) json: JsonOption,

    #[command(flatten)]
    pub(crate) quiet: QuietOption,

    #[command(flatten)]
    pub(crate) verbose: VerboseOption,

    #[command(flatten)]
    pub(crate) debug: DebugOption,
}

impl CommonOptions {
    pub(crate) fn ssh_signing_method(&self) -> Option<SshSigningMethod> {
        if self.ssh_agent {
            Some(SshSigningMethod::SshAgent)
        } else if self.ssh_keygen {
            Some(SshSigningMethod::SshKeygen)
        } else {
            None
        }
    }
}

impl SshSigningOptions {
    fn apply_to(&self, common: &mut CommonOptions) {
        common.identity = self.identity.clone();
        common.ssh_agent = self.ssh_agent;
        common.ssh_keygen = self.ssh_keygen;
    }
}

fn build_common_options(home: &HomeOption, workspace: Option<&WorkspaceOption>) -> CommonOptions {
    CommonOptions {
        home: home.home.clone(),
        workspace: workspace.and_then(|option| option.workspace.clone()),
        ..CommonOptions::default()
    }
}

fn build_signing_common_options(
    home: &HomeOption,
    workspace: &WorkspaceOption,
    ssh: &SshSigningOptions,
) -> CommonOptions {
    let mut common = build_common_options(home, Some(workspace));
    ssh.apply_to(&mut common);
    common
}

impl ToCommonOptions for CommonOptions {
    fn to_common_options(&self) -> CommonOptions {
        self.clone()
    }
}

impl ToCommonOptions for LocalOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_common_options(&self.home, None)
    }
}

impl ToCommonOptions for LocalSigningOptions {
    fn to_common_options(&self) -> CommonOptions {
        let mut common = build_common_options(&self.home, None);
        self.ssh.apply_to(&mut common);
        common
    }
}

impl ToCommonOptions for LocalOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_common_options(&self.home, None)
    }
}

impl ToCommonOptions for WorkspaceOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_common_options(&self.home, Some(&self.workspace))
    }
}

impl ToCommonOptions for WorkspaceOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_common_options(&self.home, Some(&self.workspace))
    }
}

impl ToCommonOptions for SigningOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_signing_common_options(&self.home, &self.workspace, &self.ssh)
    }
}

impl ToCommonOptions for SigningOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_signing_common_options(&self.home, &self.workspace, &self.ssh)
    }
}

impl ToCommonOptions for SigningQuietOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_signing_common_options(&self.home, &self.workspace, &self.ssh)
    }
}

impl ToCommonOptions for SigningQuietOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        build_signing_common_options(&self.home, &self.workspace, &self.ssh)
    }
}
