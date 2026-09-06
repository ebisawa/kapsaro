// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Numeric constraints shared by document parsing, schema validation, and JCS.
//! Restricts JSON numbers to integers represented exactly by binary64.

use serde_json::Value;

pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub(crate) const FLOAT_ERROR: &str =
    "JSON numbers must be safe integers; floating-point values are forbidden";

pub(crate) fn validate_integer(value: i128) -> Result<(), &'static str> {
    let limit = i128::from(MAX_SAFE_INTEGER);
    if (-limit..=limit).contains(&value) {
        Ok(())
    } else {
        Err("JSON integer exceeds the safe range -9007199254740991..=9007199254740991")
    }
}

pub(crate) fn validate_numbers(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .ok_or(FLOAT_ERROR)?;
            validate_integer(integer)
        }
        Value::Array(values) => values.iter().try_for_each(validate_numbers),
        Value::Object(values) => values.values().try_for_each(validate_numbers),
        _ => Ok(()),
    }
}
