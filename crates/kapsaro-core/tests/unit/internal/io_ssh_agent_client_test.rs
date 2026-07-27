// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the ssh-agent client transport.
//! Covers packet framing limits and socket error reporting.

use super::{AgentClient, MAX_AGENT_PACKET_SIZE};
use crate::io::ssh::protocol::wire::encode_ssh_string;
use std::cell::RefCell;
use std::io::{Error, Read, Result as IoResult, Write};
use std::rc::Rc;

#[derive(Default)]
struct FakeStreamState {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
    read_error: bool,
    write_error: bool,
}

#[derive(Clone, Default)]
struct FakeStream {
    state: Rc<RefCell<FakeStreamState>>,
}

impl FakeStream {
    fn with_read_data(read_data: Vec<u8>) -> Self {
        let stream = Self::default();
        stream.state.borrow_mut().read_data = read_data;
        stream
    }

    fn with_read_error() -> Self {
        let stream = Self::default();
        stream.state.borrow_mut().read_error = true;
        stream
    }

    fn with_write_error(read_data: Vec<u8>) -> Self {
        let stream = Self::with_read_data(read_data);
        stream.state.borrow_mut().write_error = true;
        stream
    }

    fn written(&self) -> Vec<u8> {
        self.state.borrow().written.clone()
    }
}

impl Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let mut state = self.state.borrow_mut();
        if state.read_error {
            return Err(Error::other("fake read error"));
        }
        let remaining = state.read_data.len().saturating_sub(state.read_pos);
        if remaining == 0 {
            return Ok(0);
        }
        let count = remaining.min(buf.len());
        let start = state.read_pos;
        let end = start + count;
        buf[..count].copy_from_slice(&state.read_data[start..end]);
        state.read_pos = end;
        Ok(count)
    }
}

impl Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let mut state = self.state.borrow_mut();
        if state.write_error {
            return Err(Error::other("fake write error"));
        }
        state.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn packet(body: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(body.len() as u32).to_be_bytes());
    data.extend_from_slice(body);
    data
}

fn identities_response() -> Vec<u8> {
    let mut body = vec![12];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&encode_ssh_string(b"key-blob"));
    body.extend_from_slice(&encode_ssh_string(b"test-key"));
    packet(&body)
}

#[test]
fn test_list_identities_writes_request_and_reads_response() {
    let stream = FakeStream::with_read_data(identities_response());
    let written = stream.clone();
    let mut client = AgentClient {
        socket: Box::new(stream),
    };

    let identities = client.list_identities().unwrap();

    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].key_blob(), b"key-blob");
    assert_eq!(identities[0].comment(), "test-key");
    assert_eq!(written.written(), vec![0, 0, 0, 1, 11]);
}

#[test]
fn test_list_identities_rejects_oversized_response_packet() {
    let mut response = Vec::new();
    response.extend_from_slice(&((MAX_AGENT_PACKET_SIZE as u32) + 1).to_be_bytes());
    let stream = FakeStream::with_read_data(response);
    let mut client = AgentClient {
        socket: Box::new(stream),
    };

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("exceeds maximum size limit"));
}

#[test]
fn test_list_identities_reports_read_error() {
    let stream = FakeStream::with_read_error();
    let mut client = AgentClient {
        socket: Box::new(stream),
    };

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("ssh-agent read failed"));
}

#[test]
fn test_list_identities_reports_write_error() {
    let stream = FakeStream::with_write_error(identities_response());
    let mut client = AgentClient {
        socket: Box::new(stream),
    };

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("ssh-agent write failed"));
}
