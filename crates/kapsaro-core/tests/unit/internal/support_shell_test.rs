// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shell quoting for repair commands.
//! Pins that a path stays one word whatever characters its name holds.

use super::{append_repair_command, format_repair_command, quote_posix_argument};
use std::path::Path;

#[test]
fn test_quote_posix_argument_wraps_a_plain_path_in_single_quotes() {
    let quoted = quote_posix_argument(Path::new("/home/alice/keys")).unwrap();

    assert_eq!(quoted, "'/home/alice/keys'");
}

#[test]
fn test_quote_posix_argument_escapes_an_embedded_single_quote() {
    let quoted = quote_posix_argument(Path::new("/tmp/it's")).unwrap();

    assert_eq!(quoted, r"'/tmp/it'\''s'");
}

/// A name carrying shell syntax stays one word.
#[test]
fn test_quote_posix_argument_keeps_a_command_separator_inside_the_word() {
    let quoted = quote_posix_argument(Path::new("/tmp/evil'; touch pwned; x")).unwrap();

    assert_eq!(quoted, r"'/tmp/evil'\''; touch pwned; x'");
}

#[cfg(unix)]
#[test]
fn test_quote_posix_argument_refuses_a_path_that_is_not_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = Path::new(OsStr::from_bytes(b"/tmp/bad\xff"));

    assert_eq!(quote_posix_argument(path), None);
}

#[test]
fn test_quote_posix_argument_refuses_a_path_with_a_newline() {
    let quoted = quote_posix_argument(Path::new("/tmp/first\nWarning: forged"));

    assert_eq!(quoted, None);
}

#[test]
fn test_quote_posix_argument_refuses_a_path_with_other_control_characters() {
    let with_tab = quote_posix_argument(Path::new("/tmp/a\tb"));
    let with_escape = quote_posix_argument(Path::new("/tmp/a\x1bb"));

    assert_eq!(with_tab, None);
    assert_eq!(with_escape, None);
}

/// A bidirectional override sits outside the control block, and the repair is
/// printed on the same line as an already escaped path. Left in the command it
/// would reorder that line, showing a repair for a path other than the one it
/// acts on.
#[test]
fn test_quote_posix_argument_refuses_a_path_with_a_bidirectional_override() {
    let with_override = quote_posix_argument(Path::new("/tmp/\u{202E}secret"));
    let with_isolate = quote_posix_argument(Path::new("/tmp/\u{2066}secret\u{2069}"));

    assert_eq!(with_override, None);
    assert_eq!(with_isolate, None);
}

#[test]
fn test_append_repair_command_says_why_no_command_is_shown_for_a_bidirectional_override() {
    let path = Path::new("/tmp/\u{202E}secret");

    let message = append_repair_command("Insecure permissions", "chmod 0600", path);

    assert!(
        message.contains("cannot be displayed safely"),
        "a missing command must be explained: {message}"
    );
}

#[test]
fn test_format_repair_command_separates_options_from_the_path() {
    let repair = format_repair_command("chmod 0600", Path::new("/tmp/-secret")).unwrap();

    assert_eq!(repair, "chmod 0600 -- '/tmp/-secret'");
}

#[test]
fn test_format_repair_command_names_an_absolute_path() {
    let repair = format_repair_command("chmod 0700", Path::new("relative/dir")).unwrap();

    assert!(
        repair.contains(" -- '/"),
        "the repair must run from anywhere: {repair}"
    );
}

#[test]
fn test_append_repair_command_joins_the_explanation_and_the_command() {
    let message = append_repair_command("Insecure permissions", "chmod 0600", Path::new("/tmp/x"));

    assert_eq!(message, "Insecure permissions; run: chmod 0600 -- '/tmp/x'");
}

#[cfg(unix)]
#[test]
fn test_append_repair_command_says_why_no_command_is_shown_for_undecodable_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = Path::new(OsStr::from_bytes(b"/tmp/bad\xff"));

    let message = append_repair_command("Insecure permissions", "chmod 0600", path);

    assert!(
        message.contains("not valid UTF-8"),
        "a missing command must be explained: {message}"
    );
    assert!(
        !message.contains("run:"),
        "no command must be offered when none can be written: {message}"
    );
}

#[test]
fn test_append_repair_command_says_why_no_command_is_shown_for_a_control_character() {
    let path = Path::new("/tmp/first\nWarning: forged");

    let message = append_repair_command("Insecure permissions", "chmod 0600", path);

    assert!(
        message.contains("cannot be displayed safely"),
        "a missing command must be explained: {message}"
    );
    assert!(
        !message.contains("run:"),
        "no command must be offered when none can be written: {message}"
    );
}

/// The security property this whole module exists for: whatever bytes a path
/// holds, a message built from it never lets an attacker forge a second line
/// on standard error.
#[test]
fn test_append_repair_command_never_contains_a_newline() {
    let path = Path::new("/tmp/first\nWarning: forged");

    let message = append_repair_command("Insecure permissions", "chmod 0600", path);

    assert!(
        !message.contains('\n'),
        "a repair message must stay one line: {message:?}"
    );
}
