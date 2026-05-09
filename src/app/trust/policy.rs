// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Command capability and trust policy definitions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandCapability {
    Config,
    Decrypt,
    Doctor,
    Encrypt,
    Get,
    Import,
    Init,
    Inspect,
    Join,
    Key,
    List,
    Member,
    Rewrap,
    Run,
    Set,
    Trust,
    Unset,
}

impl CommandCapability {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Decrypt => "decrypt",
            Self::Doctor => "doctor",
            Self::Encrypt => "encrypt",
            Self::Get => "get",
            Self::Import => "import",
            Self::Init => "init",
            Self::Inspect => "inspect",
            Self::Join => "join",
            Self::Key => "key",
            Self::List => "list",
            Self::Member => "member",
            Self::Rewrap => "rewrap",
            Self::Run => "run",
            Self::Set => "set",
            Self::Trust => "trust",
            Self::Unset => "unset",
        }
    }

    pub(crate) fn allows_env_key_mode(self) -> bool {
        matches!(
            self,
            Self::Decrypt | Self::Doctor | Self::Get | Self::List | Self::Run
        )
    }

    pub(crate) fn allows_non_member_acceptance(self) -> bool {
        matches!(self, Self::Decrypt | Self::Get | Self::Rewrap)
    }

    pub(crate) fn allows_strict_key_checking_no(self) -> bool {
        matches!(self, Self::Decrypt | Self::Get | Self::Run)
    }
}

pub(crate) trait TrustPolicy {
    const CAPABILITY: CommandCapability;
}

pub(crate) trait ReadTrustPolicy: TrustPolicy {}

pub(crate) trait WriteTrustPolicy: TrustPolicy {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecryptPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GetPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SetPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnsetPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportPolicy;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RewrapInputPolicy;

impl TrustPolicy for DecryptPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Decrypt;
}

impl ReadTrustPolicy for DecryptPolicy {}

impl TrustPolicy for GetPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Get;
}

impl ReadTrustPolicy for GetPolicy {}

impl TrustPolicy for RunPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Run;
}

impl ReadTrustPolicy for RunPolicy {}

impl TrustPolicy for EncryptPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Encrypt;
}

impl WriteTrustPolicy for EncryptPolicy {}

impl TrustPolicy for SetPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Set;
}

impl WriteTrustPolicy for SetPolicy {}

impl TrustPolicy for UnsetPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Unset;
}

impl WriteTrustPolicy for UnsetPolicy {}

impl TrustPolicy for ImportPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Import;
}

impl WriteTrustPolicy for ImportPolicy {}

impl TrustPolicy for RewrapInputPolicy {
    const CAPABILITY: CommandCapability = CommandCapability::Rewrap;
}
