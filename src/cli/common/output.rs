// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Output utilities for CLI commands.

use self::text::print_warnings;
use crate::Result;

pub(crate) mod config;
pub(crate) mod file;
pub(crate) mod json;
pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod member;
pub(crate) mod rewrap;
pub(crate) mod text;
pub(crate) mod trust;

pub(crate) fn print_json_or_text<PrintJson, PrintText>(
    json_output: bool,
    print_json: PrintJson,
    print_text: PrintText,
) -> Result<()>
where
    PrintJson: FnOnce() -> Result<()>,
    PrintText: FnOnce(),
{
    if json_output {
        return print_json();
    }

    print_text();
    Ok(())
}

pub(crate) fn print_empty_or_json_or_text<PrintEmptyJson, PrintEmptyText, PrintJson, PrintText>(
    json_output: bool,
    is_empty: bool,
    print_empty_json: PrintEmptyJson,
    print_empty_text: PrintEmptyText,
    print_json: PrintJson,
    print_text: PrintText,
) -> Result<()>
where
    PrintEmptyJson: FnOnce() -> Result<()>,
    PrintEmptyText: FnOnce(),
    PrintJson: FnOnce() -> Result<()>,
    PrintText: FnOnce(),
{
    if is_empty {
        return print_json_or_text(json_output, print_empty_json, print_empty_text);
    }

    print_json_or_text(json_output, print_json, print_text)
}

pub(crate) fn print_json_or_text_with_warnings<PrintJson, PrintText>(
    json_output: bool,
    warnings: &[String],
    print_json: PrintJson,
    print_text: PrintText,
) -> Result<()>
where
    PrintJson: FnOnce() -> Result<()>,
    PrintText: FnOnce(),
{
    print_json_or_text(json_output, print_json, print_text)?;
    print_warnings(warnings);
    Ok(())
}

pub(crate) fn print_empty_or_json_or_text_with_warnings<
    PrintEmptyJson,
    PrintEmptyText,
    PrintJson,
    PrintText,
>(
    json_output: bool,
    is_empty: bool,
    warnings: &[String],
    print_empty_json: PrintEmptyJson,
    print_empty_text: PrintEmptyText,
    print_json: PrintJson,
    print_text: PrintText,
) -> Result<()>
where
    PrintEmptyJson: FnOnce() -> Result<()>,
    PrintEmptyText: FnOnce(),
    PrintJson: FnOnce() -> Result<()>,
    PrintText: FnOnce(),
{
    print_empty_or_json_or_text(
        json_output,
        is_empty,
        print_empty_json,
        print_empty_text,
        print_json,
        print_text,
    )?;
    print_warnings(warnings);
    Ok(())
}
