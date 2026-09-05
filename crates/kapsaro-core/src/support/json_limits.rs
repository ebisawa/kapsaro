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
    let mut state = JsonScanState::default();
    for &byte in input {
        state.consume(byte)?;
    }
    Ok(())
}

/// What the scan carries from one byte of JSON to the next.
///
/// The counts and the string-literal position have to move together: a brace
/// inside a string is not nesting, and the limits are checked against the same
/// counts the position decides to raise.
#[derive(Default)]
struct JsonScanState {
    depth: usize,
    max_depth: usize,
    elements: usize,
    in_string: bool,
    escape: bool,
}

impl JsonScanState {
    fn consume(&mut self, byte: u8) -> Result<()> {
        if self.escape {
            self.escape = false;
            return Ok(());
        }
        if self.in_string {
            self.consume_in_string(byte);
            return Ok(());
        }

        match byte {
            b'"' => self.in_string = true,
            b'{' | b'[' => self.open_container()?,
            b'}' | b']' => self.depth = self.depth.saturating_sub(1),
            // A colon or a comma outside a string introduces one more element.
            b':' | b',' => self.elements += 1,
            _ => {}
        }

        self.enforce_element_limit()
    }

    fn consume_in_string(&mut self, byte: u8) {
        match byte {
            b'\\' => self.escape = true,
            b'"' => self.in_string = false,
            _ => {}
        }
    }

    fn open_container(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        self.elements += 1;
        if self.max_depth > MAX_JSON_DEPTH {
            return Err(build_depth_limit_error(self.max_depth));
        }
        Ok(())
    }

    fn enforce_element_limit(&self) -> Result<()> {
        if self.elements > MAX_JSON_ELEMENTS {
            return Err(build_element_limit_error(self.elements));
        }
        Ok(())
    }
}

fn build_depth_limit_error(max_depth: usize) -> Error {
    Error::build_parse_error(format!(
        "JSON nesting depth exceeds limit ({} > {})",
        max_depth, MAX_JSON_DEPTH
    ))
}

fn build_element_limit_error(elements: usize) -> Error {
    Error::build_parse_error(format!(
        "JSON element count exceeds limit ({} > {})",
        elements, MAX_JSON_ELEMENTS
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_json_limits_internal_test.rs"]
mod support_json_limits_internal_test;
