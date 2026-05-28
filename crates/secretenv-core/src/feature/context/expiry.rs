// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key expiration checking.
//!
//! Provides functions to check key expiry status and enforce the rule that
//! expired keys must not be used for encryption (wrap) or signing.

use time::OffsetDateTime;

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::model::public_key::{VerifiedPublicKeyAttested, VerifiedRecipientKey};
use crate::support::display::sanitize_display_field;
use crate::{Error, Result};

const EXPIRY_WARNING_DAYS: i64 = 30;

/// Expiration timestamp whose source key metadata has already been integrity-checked by the
/// relevant key loading flow.
///
/// This type does **not** mean the key is currently valid (not expired). Expiry policy must be
/// applied separately via functions like `enforce_key_not_expired_for_signing`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExpiresAt(String);

impl VerifiedExpiresAt {
    pub(crate) fn from_verified_private_key_metadata(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn from_verified_public_key_metadata(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Expiration metadata for a local PrivateKey and its sibling PublicKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalKeyPairExpiry {
    private_expires_at: VerifiedExpiresAt,
    public_expires_at: Option<VerifiedExpiresAt>,
}

impl LocalKeyPairExpiry {
    pub(crate) fn from_private_key(private_expires_at: VerifiedExpiresAt) -> Self {
        Self {
            private_expires_at,
            public_expires_at: None,
        }
    }

    pub(crate) fn from_private_and_public_key(
        private_expires_at: VerifiedExpiresAt,
        public_expires_at: VerifiedExpiresAt,
    ) -> Self {
        Self {
            private_expires_at,
            public_expires_at: Some(public_expires_at),
        }
    }

    pub(crate) fn primary_expires_at(&self) -> &str {
        self.private_expires_at.as_str()
    }

    pub(crate) fn enforce_not_expired_for_signing(&self) -> Result<()> {
        match self.select_status(OffsetDateTime::now_utc())? {
            KeyExpiryStatus::Valid | KeyExpiryStatus::ExpiringSoon { .. } => Ok(()),
            KeyExpiryStatus::Expired { expires_at } => Err(Error::build_verification_error(
                "key-expiry".to_string(),
                format!(
                    "Local key has expired.\n\
                     Expires at: {}\n\
                     Action: Rotate the key before encryption or signing.",
                    expires_at
                ),
            )),
        }
    }

    pub(crate) fn enforce_expired_usage(&self, allow_expired_key: bool) -> Result<Option<String>> {
        enforce_selected_status_usage(
            self.select_status(OffsetDateTime::now_utc())?,
            allow_expired_key,
            "Local key",
        )
    }

    pub(crate) fn build_signing_warning(&self) -> Result<Option<String>> {
        match self.select_status(OffsetDateTime::now_utc())? {
            KeyExpiryStatus::Valid | KeyExpiryStatus::Expired { .. } => Ok(None),
            KeyExpiryStatus::ExpiringSoon {
                expires_at,
                days_remaining,
            } => Ok(Some(format_expiring_key_warning(
                "Local key",
                days_remaining,
                &expires_at,
            ))),
        }
    }

    fn select_status(&self, now: OffsetDateTime) -> Result<KeyExpiryStatus> {
        let mut status = check_key_expiry(self.private_expires_at.as_str(), now)?;
        if let Some(public_expires_at) = &self.public_expires_at {
            status = select_stricter_key_expiry_status(
                status,
                check_key_expiry(public_expires_at.as_str(), now)?,
            );
        }
        Ok(status)
    }
}

/// Key expiration status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExpiryStatus {
    /// Key is valid and not close to expiring
    Valid,
    /// Key will expire within EXPIRY_WARNING_DAYS
    ExpiringSoon {
        expires_at: String,
        days_remaining: i64,
    },
    /// Key has expired
    Expired { expires_at: String },
}

/// Check the expiration status of a key.
///
/// Accepts `now` as a parameter for testability.
pub fn check_key_expiry(expires_at: &str, now: OffsetDateTime) -> Result<KeyExpiryStatus> {
    let expiry = parse_expires_at(expires_at)?;

    if now >= expiry {
        return Ok(KeyExpiryStatus::Expired {
            expires_at: expires_at.to_string(),
        });
    }

    let remaining = expiry - now;
    let days_remaining = remaining.whole_days();

    if days_remaining <= EXPIRY_WARNING_DAYS {
        return Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at: expires_at.to_string(),
            days_remaining,
        });
    }

    Ok(KeyExpiryStatus::Valid)
}

/// Enforce that a key is not expired for write operations (encrypt/sign).
///
/// Returns `Err` if the key has expired.
pub fn enforce_key_not_expired_for_signing(expires_at: &VerifiedExpiresAt) -> Result<()> {
    match check_key_expiry(expires_at.as_str(), OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(()),
        KeyExpiryStatus::ExpiringSoon { .. } => Ok(()),
        KeyExpiryStatus::Expired { expires_at } => Err(Error::build_verification_error(
            "key-expiry".to_string(),
            format!(
                "Private key has expired.\n\
                 Expires at: {}\n\
                 Action: Rotate the key before encryption or signing.",
                expires_at
            ),
        )),
    }
}

/// Build a warning message if the key is expired or expiring soon.
///
/// For read operations (decrypt/verify) that allow expired keys with a warning.
pub fn build_key_expiry_warning(expires_at: &VerifiedExpiresAt) -> Result<Option<String>> {
    match check_key_expiry(expires_at.as_str(), OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format_expiring_key_warning(
            "Private key",
            days_remaining,
            &expires_at,
        ))),
        KeyExpiryStatus::Expired { expires_at } => {
            Ok(Some(format_expired_key_warning("Private key", &expires_at)))
        }
    }
}

/// Enforce explicit allowance before using an expired key operationally.
pub(crate) fn enforce_expired_key_usage(
    expires_at: &str,
    allow_expired_key: bool,
    key_label: &str,
) -> Result<Option<String>> {
    enforce_selected_status_usage(
        check_key_expiry(expires_at, OffsetDateTime::now_utc())?,
        allow_expired_key,
        key_label,
    )
}

fn enforce_selected_status_usage(
    status: KeyExpiryStatus,
    allow_expired_key: bool,
    key_label: &str,
) -> Result<Option<String>> {
    match status {
        KeyExpiryStatus::Valid => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format_expiring_key_warning(
            key_label,
            days_remaining,
            &sanitize_display_field(&expires_at),
        ))),
        KeyExpiryStatus::Expired { expires_at } if allow_expired_key => Ok(Some(format!(
            "{} Reason: expired key use was explicitly allowed.",
            format_expired_key_warning(key_label, &sanitize_display_field(&expires_at))
        ))),
        KeyExpiryStatus::Expired { expires_at } => Err(Error::build_verification_error(
            "E_KEY_EXPIRED".to_string(),
            format!(
                "{} has expired.\n\
                 Expires at: {}\n\
                 Action: Use --allow-expired-key only for explicit recovery.",
                key_label,
                sanitize_display_field(&expires_at)
            ),
        )),
    }
}

/// Build a warning message for write operations when the signing key expires soon.
pub fn build_signing_key_expiry_warning(expires_at: &VerifiedExpiresAt) -> Result<Option<String>> {
    match check_key_expiry(expires_at.as_str(), OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid | KeyExpiryStatus::Expired { .. } => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format_expiring_key_warning(
            "Private key",
            days_remaining,
            &expires_at,
        ))),
    }
}

/// Build a warning message for recipient keys that will expire soon.
pub fn build_recipient_key_expiry_warning(
    doc: &VerifiedPublicKeyAttested,
) -> Result<Option<String>> {
    let doc = doc.document();
    if doc.protected.expires_at.is_empty() {
        return Ok(None);
    }
    match check_key_expiry(&doc.protected.expires_at, OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid | KeyExpiryStatus::Expired { .. } => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format_expiring_key_warning(
            &format!(
                "Recipient public key for '{}'",
                sanitize_display_field(&doc.protected.subject_handle)
            ),
            days_remaining,
            &sanitize_display_field(&expires_at),
        ))),
    }
}

pub fn collect_recipient_key_expiry_warnings(keys: &[VerifiedRecipientKey]) -> Result<Vec<String>> {
    keys.iter()
        .filter_map(|key| build_recipient_key_expiry_warning(key.attested()).transpose())
        .collect()
}

pub(crate) fn collect_recipient_key_expiry_warnings_excluding_local_key(
    keys: &[VerifiedRecipientKey],
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for key in keys {
        if matches_local_key_identity(key.attested(), local_key_identity)? {
            continue;
        }
        if let Some(warning) = build_recipient_key_expiry_warning(key.attested())? {
            warnings.push(warning);
        }
    }
    Ok(warnings)
}

/// Enforce that a recipient public key is not expired for wrap operations.
///
/// Returns `Err` if the key has expired.
/// Keys with empty `expires_at` are considered valid (no expiry set).
pub fn enforce_recipient_key_not_expired(doc: &VerifiedPublicKeyAttested) -> Result<()> {
    let doc = doc.document();
    if doc.protected.expires_at.is_empty() {
        return Ok(());
    }
    match check_key_expiry(&doc.protected.expires_at, OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(()),
        KeyExpiryStatus::ExpiringSoon { .. } => Ok(()),
        KeyExpiryStatus::Expired { expires_at } => Err(Error::build_verification_error(
            "key-expiry".to_string(),
            format!(
                "Recipient public key has expired.\n\
                 Member: {}\n\
                 Expires at: {}\n\
                 Action: Rotate the recipient key before encryption.",
                sanitize_display_field(&doc.protected.subject_handle),
                sanitize_display_field(&expires_at)
            ),
        )),
    }
}

fn parse_expires_at(expires_at: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339).map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Invalid expires_at format: {}",
                sanitize_display_field(&e.to_string())
            ),
            e,
        )
    })
}

fn matches_local_key_identity(
    public_key: &VerifiedPublicKeyAttested,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<bool> {
    let Some(identity) = local_key_identity else {
        return Ok(false);
    };
    identity.matches_public_key(public_key.document())
}

fn select_stricter_key_expiry_status(
    left: KeyExpiryStatus,
    right: KeyExpiryStatus,
) -> KeyExpiryStatus {
    match (left, right) {
        (KeyExpiryStatus::Expired { .. }, KeyExpiryStatus::Expired { expires_at })
        | (KeyExpiryStatus::Valid, KeyExpiryStatus::Expired { expires_at })
        | (KeyExpiryStatus::ExpiringSoon { .. }, KeyExpiryStatus::Expired { expires_at }) => {
            KeyExpiryStatus::Expired { expires_at }
        }
        (KeyExpiryStatus::Expired { expires_at }, _) => KeyExpiryStatus::Expired { expires_at },
        (
            KeyExpiryStatus::ExpiringSoon {
                expires_at: _,
                days_remaining,
            },
            KeyExpiryStatus::ExpiringSoon {
                expires_at: right_expires_at,
                days_remaining: right_days_remaining,
            },
        ) if right_days_remaining < days_remaining => KeyExpiryStatus::ExpiringSoon {
            expires_at: right_expires_at,
            days_remaining: right_days_remaining,
        },
        (status @ KeyExpiryStatus::ExpiringSoon { .. }, _) => status,
        (_, status @ KeyExpiryStatus::ExpiringSoon { .. }) => status,
        (KeyExpiryStatus::Valid, KeyExpiryStatus::Valid) => KeyExpiryStatus::Valid,
    }
}

fn format_expiring_key_warning(key_label: &str, days_remaining: i64, expires_at: &str) -> String {
    format!("{key_label} expires in {days_remaining} days. Expires at: {expires_at}")
}

fn format_expired_key_warning(key_label: &str, expires_at: &str) -> String {
    format!("{key_label} has expired. Expires at: {expires_at}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc3339(dt: OffsetDateTime) -> String {
        dt.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    fn future_time(days: i64) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc();
        now + time::Duration::days(days)
    }

    fn past_time(days: i64) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc();
        now - time::Duration::days(days)
    }

    #[test]
    fn enforce_not_expired_valid() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(365)));
        assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
    }

    #[test]
    fn enforce_not_expired_expired_fails() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
        let result = enforce_key_not_expired_for_signing(&expires_at);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn enforce_not_expired_expiring_soon_ok() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
        assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
    }

    #[test]
    fn build_warning_expired() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
        let warning = build_key_expiry_warning(&expires_at).unwrap();
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert!(warning.contains("expired"));
        assert!(!warning.contains('\n'));
    }

    #[test]
    fn build_warning_expiring_soon() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
        let warning = build_key_expiry_warning(&expires_at).unwrap();
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert!(warning.contains("expir"));
        assert!(!warning.contains('\n'));
    }

    #[test]
    fn build_warning_valid_none() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(365)));
        let warning = build_key_expiry_warning(&expires_at).unwrap();
        assert!(warning.is_none());
    }

    #[test]
    fn build_signing_warning_expiring_soon() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
        let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert!(warning.contains("expir"));
        assert!(!warning.contains('\n'));
    }

    #[test]
    fn build_signing_warning_expired_none() {
        let expires_at =
            VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
        let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
        assert!(warning.is_none());
    }
}
