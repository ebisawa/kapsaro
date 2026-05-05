// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON depth and element count validation for DoS protection

use crate::support::limits::{MAX_JSON_DEPTH, MAX_JSON_ELEMENTS};
use crate::{Error, Result};

/// Validate JSON input against depth and element count limits.
///
/// Scans the raw JSON bytes to count nesting depth and element count
/// without fully parsing. Correctly handles string literals (including
/// escaped characters) so that `{`/`[` inside strings are not counted.
pub fn validate_json_limits(input: &[u8]) -> Result<()> {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut elements: usize = 0;
    let mut in_string = false;
    let mut escape = false;

    for &byte in input {
        if escape {
            escape = false;
            continue;
        }

        if in_string {
            match byte {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                elements += 1;
                if max_depth > MAX_JSON_DEPTH {
                    return Err(Error::Parse {
                        message: format!(
                            "JSON nesting depth exceeds limit ({} > {})",
                            max_depth, MAX_JSON_DEPTH
                        ),
                        source: None,
                    });
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            b':' => {
                // A colon outside a string indicates a key-value pair
                elements += 1;
            }
            b',' => {
                // A comma outside a string indicates an additional element
                elements += 1;
            }
            _ => {}
        }

        if elements > MAX_JSON_ELEMENTS {
            return Err(Error::Parse {
                message: format!(
                    "JSON element count exceeds limit ({} > {})",
                    elements, MAX_JSON_ELEMENTS
                ),
                source: None,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_json_limits_internal_test.rs"]
mod tests;
