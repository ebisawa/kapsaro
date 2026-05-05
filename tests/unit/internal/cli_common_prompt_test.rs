// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{prompt_yes_no_with_mode, prompt_yes_no_with_reader};
use std::io::Cursor;
use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn test_prompt_yes_no_with_reader_accepts_yes() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", false, Cursor::new(b"y\n".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_uses_default_for_empty_input() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", true, Cursor::new(b"\n".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_rejects_non_yes_input() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", false, Cursor::new(b"no\n".to_vec())).unwrap();

    assert!(!accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_accepts_yes_with_carriage_return() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", false, Cursor::new(b"y\r".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_uses_default_for_carriage_return_only() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", true, Cursor::new(b"\r".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_accepts_carriage_return_without_waiting_for_newline() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = prompt_yes_no_with_reader("Proceed?", false, BufReader::new(reader));
        tx.send(result).unwrap();
    });

    writer.write_all(b"y\r").unwrap();

    let accepted = rx
        .recv_timeout(Duration::from_millis(200))
        .expect("prompt should accept carriage return without blocking")
        .unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_mode_uses_confirm_in_interactive_mode() {
    let mut confirm_called = false;

    let accepted = prompt_yes_no_with_mode(
        "Proceed?",
        false,
        true,
        Cursor::new(Vec::<u8>::new()),
        |prompt, default| {
            confirm_called = true;
            assert_eq!(prompt, "Proceed?");
            assert!(!default);
            Ok(true)
        },
    )
    .unwrap();

    assert!(accepted);
    assert!(confirm_called);
}

#[test]
fn test_prompt_yes_no_with_mode_uses_reader_in_non_interactive_mode() {
    let accepted = prompt_yes_no_with_mode(
        "Proceed?",
        false,
        false,
        Cursor::new(b"y\n".to_vec()),
        |_, _| panic!("interactive confirm should not be used"),
    )
    .unwrap();

    assert!(accepted);
}
