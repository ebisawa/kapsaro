// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::path::PathBuf;

use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::presentation::config::SshSigningMethod;

#[derive(Debug, Clone, Default)]
pub struct CommonOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub json: bool,
    pub quiet: bool,
    pub ssh_agent: bool,
    pub ssh_keygen: bool,
    pub verbose: bool,
    pub debug: bool,
    pub workspace: Option<PathBuf>,
}

pub(crate) trait ToCommonOptions {
    fn to_common_options(&self) -> CommonOptions;
}

#[derive(Debug, Clone, Args, Default)]
pub struct HomeOption {
    /// Base directory for secretenv
    #[arg(long)]
    pub home: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct WorkspaceOption {
    /// Workspace root directory
    #[arg(long, short = 'w')]
    pub workspace: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct JsonOption {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct QuietOption {
    /// Quiet mode (suppress non-error status output)
    #[arg(long, short = 'q')]
    pub quiet: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct VerboseOption {
    /// Verbose output
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct DebugOption {
    /// Enable debug trace logging
    #[arg(long)]
    pub debug: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct SshSigningOptions {
    /// SSH identity file (private key path)
    #[arg(long = "ssh-identity", short = 'i')]
    pub identity: Option<PathBuf>,

    /// Use ssh-agent for SSH signing
    #[arg(long, conflicts_with = "ssh_keygen")]
    pub ssh_agent: bool,

    /// Use ssh-keygen for SSH signing
    #[arg(long, conflicts_with = "ssh_agent")]
    pub ssh_keygen: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct MemberHandleOption {
    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_handle: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct KvStoreNameOption {
    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct ForceOption {
    /// Force operation without confirmation
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct LocalOptions {
    #[command(flatten)]
    pub home: HomeOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct LocalOutputOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub json: JsonOption,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct WorkspaceOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct WorkspaceOutputOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub json: JsonOption,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct SigningOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub ssh: SshSigningOptions,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct SigningOutputOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub ssh: SshSigningOptions,

    #[command(flatten)]
    pub json: JsonOption,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct SigningQuietOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub ssh: SshSigningOptions,

    #[command(flatten)]
    pub quiet: QuietOption,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

#[derive(Debug, Clone, Args, Default)]
pub struct SigningQuietOutputOptions {
    #[command(flatten)]
    pub home: HomeOption,

    #[command(flatten)]
    pub workspace: WorkspaceOption,

    #[command(flatten)]
    pub ssh: SshSigningOptions,

    #[command(flatten)]
    pub json: JsonOption,

    #[command(flatten)]
    pub quiet: QuietOption,

    #[command(flatten)]
    pub verbose: VerboseOption,

    #[command(flatten)]
    pub debug: DebugOption,
}

impl CommonOptions {
    pub fn ssh_signing_method(&self) -> Option<SshSigningMethod> {
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

impl ToCommonOptions for CommonOptions {
    fn to_common_options(&self) -> CommonOptions {
        self.clone()
    }
}

impl ToCommonOptions for LocalOptions {
    fn to_common_options(&self) -> CommonOptions {
        CommonOptions {
            home: self.home.home.clone(),
            ..CommonOptions::default()
        }
    }
}

impl ToCommonOptions for LocalOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        CommonOptions {
            home: self.home.home.clone(),
            json: self.json.json,
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        }
    }
}

impl ToCommonOptions for WorkspaceOptions {
    fn to_common_options(&self) -> CommonOptions {
        CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            debug: self.debug.debug,
            ..CommonOptions::default()
        }
    }
}

impl ToCommonOptions for WorkspaceOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            json: self.json.json,
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        }
    }
}

impl ToCommonOptions for SigningOptions {
    fn to_common_options(&self) -> CommonOptions {
        let mut common = CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        };
        self.ssh.apply_to(&mut common);
        common
    }
}

impl ToCommonOptions for SigningOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        let mut common = CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            json: self.json.json,
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        };
        self.ssh.apply_to(&mut common);
        common
    }
}

impl ToCommonOptions for SigningQuietOptions {
    fn to_common_options(&self) -> CommonOptions {
        let mut common = CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            quiet: self.quiet.quiet,
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        };
        self.ssh.apply_to(&mut common);
        common
    }
}

impl ToCommonOptions for SigningQuietOutputOptions {
    fn to_common_options(&self) -> CommonOptions {
        let mut common = CommonOptions {
            home: self.home.home.clone(),
            workspace: self.workspace.workspace.clone(),
            json: self.json.json,
            quiet: self.quiet.quiet,
            verbose: self.verbose.verbose,
            debug: self.debug.debug,
            ..CommonOptions::default()
        };
        self.ssh.apply_to(&mut common);
        common
    }
}

impl From<&CommonOptions> for CommonCommandOptions {
    fn from(value: &CommonOptions) -> Self {
        Self {
            home: value.home.clone(),
            identity: value.identity.clone(),
            debug: value.debug,
            verbose: value.verbose,
            workspace: value.workspace.clone(),
            ssh_signing_method: value.ssh_signing_method(),
        }
    }
}

impl From<CommonOptions> for SigningOptions {
    fn from(value: CommonOptions) -> Self {
        Self {
            home: HomeOption { home: value.home },
            workspace: WorkspaceOption {
                workspace: value.workspace,
            },
            ssh: SshSigningOptions {
                identity: value.identity,
                ssh_agent: value.ssh_agent,
                ssh_keygen: value.ssh_keygen,
            },
            verbose: VerboseOption {
                verbose: value.verbose,
            },
            debug: DebugOption { debug: value.debug },
        }
    }
}

impl From<CommonOptions> for SigningQuietOptions {
    fn from(value: CommonOptions) -> Self {
        Self {
            home: HomeOption { home: value.home },
            workspace: WorkspaceOption {
                workspace: value.workspace,
            },
            ssh: SshSigningOptions {
                identity: value.identity,
                ssh_agent: value.ssh_agent,
                ssh_keygen: value.ssh_keygen,
            },
            quiet: QuietOption { quiet: value.quiet },
            verbose: VerboseOption {
                verbose: value.verbose,
            },
            debug: DebugOption { debug: value.debug },
        }
    }
}

impl From<CommonOptions> for SigningQuietOutputOptions {
    fn from(value: CommonOptions) -> Self {
        Self {
            home: HomeOption { home: value.home },
            workspace: WorkspaceOption {
                workspace: value.workspace,
            },
            ssh: SshSigningOptions {
                identity: value.identity,
                ssh_agent: value.ssh_agent,
                ssh_keygen: value.ssh_keygen,
            },
            json: JsonOption { json: value.json },
            quiet: QuietOption { quiet: value.quiet },
            verbose: VerboseOption {
                verbose: value.verbose,
            },
            debug: DebugOption { debug: value.debug },
        }
    }
}
