// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::support::time as time_util;
use crate::{Error, Result};

pub fn resolve_key_timestamps(
    expires_at_arg: &Option<String>,
    valid_for_arg: &Option<String>,
) -> Result<(String, String)> {
    let created_at = time::OffsetDateTime::now_utc();
    let expires_at = parse_expiration(expires_at_arg, valid_for_arg)?;

    Ok((
        time_util::format_timestamp_rfc3339(created_at)?,
        time_util::format_timestamp_rfc3339(expires_at)?,
    ))
}

fn parse_expiration(
    expires_at: &Option<String>,
    valid_for: &Option<String>,
) -> Result<time::OffsetDateTime> {
    if expires_at.is_some() && valid_for.is_some() {
        return Err(Error::build_config_error(
            "cannot specify both --expires-at and --valid-for".to_string(),
        ));
    }

    if let Some(datetime_str) = expires_at {
        time::OffsetDateTime::parse(datetime_str, &time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                Error::build_parse_error_with_source(
                    format!("Invalid --expires-at format (expected RFC3339): {}", e),
                    e,
                )
            })
    } else if let Some(duration_str) = valid_for {
        let duration = parse_duration(duration_str)?;
        Ok(time::OffsetDateTime::now_utc() + duration)
    } else {
        Ok(time::OffsetDateTime::now_utc() + time::Duration::days(365))
    }
}

fn parse_duration(s: &str) -> Result<time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::build_parse_error(
            "Empty duration string".to_string(),
        ));
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|_| Error::build_parse_error(format!("Invalid duration number: {}", num_str)))?;

    match unit {
        "d" => Ok(time::Duration::days(num)),
        "m" => Ok(time::Duration::days(num * 30)),
        "y" => Ok(time::Duration::days(num * 365)),
        _ => Err(Error::build_parse_error(format!(
            "Invalid duration unit: {} (expected d, m, or y)",
            unit
        ))),
    }
}
