// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Convenient imports for applications embedding SecretEnv core.

pub use crate::api::file::{FileEncArtifact, VerifiedFileEncArtifact};
pub use crate::api::home::SecretEnvHome;
pub use crate::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, RecipientKeys};
pub use crate::api::kv::{KvDisclosedEntry, KvEncArtifact, KvInputEntry, VerifiedKvEncArtifact};
pub use crate::api::operation::OperationOptions;
pub use crate::api::secret::{SecretBytes, SecretString};
pub use crate::api::ssh::{SshRawSignature, SshSignatureBackend};
pub use crate::api::trust::{
    LocalTrustStore, RecipientSetSubject, TrustDecision, TrustPolicyEvaluator,
    VerifiedLocalTrustStore,
};
pub use crate::error::{Error, ErrorKind, Result};
