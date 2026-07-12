// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::Error;
use serial_test::serial;

use super::format_error_line;
use crate::cli::stderr_color_guard::StderrColorGuard;

#[test]
#[serial]
fn test_format_error_line_keeps_plain_text_when_stderr_colors_disabled() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_invalid_argument_error("broken input");

    let rendered = format_error_line(&error);

    assert_eq!(rendered, "Error: broken input");
}

#[test]
#[serial]
fn test_format_error_line_adds_ansi_color_when_stderr_colors_enabled() {
    let _guard = StderrColorGuard::new(true);
    let error = Error::build_invalid_argument_error("broken input");

    let rendered = format_error_line(&error);

    assert!(rendered.starts_with("\u{1b}[31mError: broken input"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}

#[test]
#[serial]
fn test_format_error_line_keeps_detail_block_plain_when_colored() {
    let _guard = StderrColorGuard::new(true);
    let error = Error::build_invalid_operation_error(
        "member handle not configured.\n\
         Reason: member handle is required but could not be determined.\n\
         Options:\n\
         1. Specify a member handle with --member-handle <handle>\n\
         2. Configure a default member handle explicitly",
    );

    let rendered = format_error_line(&error);
    let (first_line, body) = rendered
        .split_once('\n')
        .expect("multiline error should render with a newline");

    assert_eq!(
        first_line,
        "\u{1b}[31mError: member handle not configured.\u{1b}[0m"
    );
    assert!(
        !body.contains("\u{1b}[31m"),
        "detail block should not start a red ANSI span: {rendered}"
    );
}

#[test]
#[serial]
fn test_format_error_line_colors_error_continuation_lines() {
    let _guard = StderrColorGuard::new(true);
    let error = Error::build_invalid_operation_error(
        "Recipient kid is not active.\nKid: KAD1-AAAA\nAction: Run kapsaro rewrap.",
    );

    let rendered = format_error_line(&error);

    assert_eq!(
        rendered,
        concat!(
            "\u{1b}[31mError: Recipient kid is not active.\u{1b}[0m\n",
            "\u{1b}[31m       Kid: KAD1-AAAA\u{1b}[0m\n",
            "\u{1b}[31m       Action: Run kapsaro rewrap.\u{1b}[0m"
        )
    );
}

#[test]
#[serial]
fn test_format_error_line_keeps_reason_options_as_detail_block() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_config_error(
        "workspace not found.\n\
         Reason: kv access requires a Kapsaro workspace, but no workspace could be resolved.\n\
         Options:\n\
         1. Run kapsaro init to create a new workspace in the current Git repository\n\
         2. Run inside a Git repository that contains .kapsaro/\n\
         3. Configure an existing workspace explicitly with --workspace <path>",
    );

    let rendered = format_error_line(&error);

    assert_eq!(
        rendered,
        concat!(
            "Error: workspace not found.\n",
            "Reason: kv access requires a Kapsaro workspace, but no workspace could be resolved.\n",
            "Options:\n",
            "1. Run kapsaro init to create a new workspace in the current Git repository\n",
            "2. Run inside a Git repository that contains .kapsaro/\n",
            "3. Configure an existing workspace explicitly with --workspace <path>"
        )
    );
}

#[test]
#[serial]
fn test_format_error_line_keeps_long_error_inline() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_invalid_operation_error(
        "Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact.",
    );

    let rendered = format_error_line(&error);

    assert_eq!(
        rendered,
        "Error: Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact."
    );
}

#[test]
#[serial]
fn test_format_error_line_preserves_structured_details() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_invalid_operation_error(
        "Recipient kid is not active.\nKid: KAD1-AAAA\nAction: Run kapsaro rewrap.",
    );

    let rendered = format_error_line(&error);

    assert_eq!(
        rendered,
        concat!(
            "Error: Recipient kid is not active.\n",
            "       Kid: KAD1-AAAA\n",
            "       Action: Run kapsaro rewrap."
        )
    );
}

#[test]
#[serial]
fn test_format_error_line_keeps_non_member_signer_summary_short() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_verification_error(
        "E_TRUST_NON_MEMBER",
        concat!(
            "Signer is not in active members.\n",
            "signer: ex-member@example.com\n",
            "kid: KAD1AAAA1111BBBB2222CCCC3333DDDD\n",
            "Run with '--allow-non-member' to enable one-shot non-member acceptance."
        ),
    );

    let rendered = format_error_line(&error);

    assert_eq!(
        rendered,
        concat!(
            "Error: Signer is not in active members.\n",
            "       signer: ex-member@example.com\n",
            "       kid: KAD1AAAA1111BBBB2222CCCC3333DDDD\n",
            "       Run with '--allow-non-member' to enable one-shot non-member acceptance."
        )
    );
}
