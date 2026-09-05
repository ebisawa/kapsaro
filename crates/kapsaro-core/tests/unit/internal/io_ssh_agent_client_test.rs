// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the ssh-agent client transport.
//! Covers packet framing limits and socket error reporting.

use super::{AgentClient, AgentSocket, DefaultAgentSigner, MAX_AGENT_PACKET_SIZE};
use crate::io::ssh::protocol::wire::encode_ssh_string;
use std::cell::RefCell;
use std::io::{Error, Read, Result as IoResult, Write};
use std::rc::Rc;
use std::time::Duration;

/// Build a client over a fake stream, which needs no deadline of its own.
fn build_test_client(stream: FakeStream) -> AgentClient {
    AgentClient {
        socket: Box::new(stream),
        io_timeout: Duration::from_secs(30),
    }
}

#[derive(Default)]
struct FakeStreamState {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
    read_error: bool,
    write_error: bool,
    /// How long each read pauses, and how few bytes it hands back.
    ///
    /// A zero pause means the stream answers a read in full, which is what
    /// every test but the deadline one wants.
    read_delay: Duration,
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

    /// A stream that answers one byte per read, pausing before each.
    ///
    /// This is the agent that stays just inside a per-syscall bound while never
    /// finishing the exchange.
    fn with_drip_fed_read_data(read_data: Vec<u8>, read_delay: Duration) -> Self {
        let stream = Self::with_read_data(read_data);
        stream.state.borrow_mut().read_delay = read_delay;
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

impl AgentSocket for FakeStream {
    /// The fake stream has no socket options; the deadline is enforced by the
    /// client between reads, which is what these tests exercise.
    fn set_io_timeout(&self, _timeout: Duration) -> IoResult<()> {
        Ok(())
    }
}

impl Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let read_delay = self.state.borrow().read_delay;
        if !read_delay.is_zero() {
            std::thread::sleep(read_delay);
        }
        let mut state = self.state.borrow_mut();
        if state.read_error {
            return Err(Error::other("fake read error"));
        }
        let remaining = state.read_data.len().saturating_sub(state.read_pos);
        if remaining == 0 {
            return Ok(0);
        }
        let count = if read_delay.is_zero() {
            remaining.min(buf.len())
        } else {
            1
        };
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
    body.extend_from_slice(&encode_ssh_string(b"key-blob").unwrap());
    body.extend_from_slice(&encode_ssh_string(b"test-key").unwrap());
    packet(&body)
}

#[test]
fn test_list_identities_writes_request_and_reads_response() {
    let stream = FakeStream::with_read_data(identities_response());
    let written = stream.clone();
    let mut client = build_test_client(stream);

    let identities = client.list_identities().unwrap();

    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].key_blob(), b"key-blob");
    assert_eq!(written.written(), vec![0, 0, 0, 1, 11]);
}

#[test]
fn test_list_identities_rejects_oversized_response_packet() {
    let mut response = Vec::new();
    response.extend_from_slice(&((MAX_AGENT_PACKET_SIZE as u32) + 1).to_be_bytes());
    let stream = FakeStream::with_read_data(response);
    let mut client = build_test_client(stream);

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("exceeds maximum size limit"));
}

#[test]
fn test_list_identities_reports_read_error() {
    let stream = FakeStream::with_read_error();
    let mut client = build_test_client(stream);

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("ssh-agent read failed"));
}

#[test]
fn test_list_identities_reports_write_error() {
    let stream = FakeStream::with_write_error(identities_response());
    let mut client = build_test_client(stream);

    let error = client.list_identities().unwrap_err();

    assert!(error.to_string().contains("ssh-agent write failed"));
}

#[cfg(target_family = "unix")]
#[test]
#[serial_test::serial]
fn test_default_signer_connects_to_the_fixed_socket_after_the_environment_changes() {
    use crate::test_utils::EnvGuard;
    use std::os::unix::net::UnixListener;

    let _guard = EnvGuard::new(&["SSH_AUTH_SOCK"]);
    let temp = tempfile::TempDir::new().unwrap();
    let fixed_socket = temp.path().join("fixed.sock");
    let listener = UnixListener::bind(&fixed_socket).unwrap();
    let signer = DefaultAgentSigner::new(fixed_socket.clone());
    std::env::set_var("SSH_AUTH_SOCK", temp.path().join("replacement.sock"));

    let (_client, connected_path) = signer.connect_client().unwrap();
    let (_stream, _) = listener.accept().unwrap();

    assert_eq!(connected_path, fixed_socket);
}

/// An agent that accepts the connection and then answers nothing would hold the
/// command forever, so the read gives up and says what it was waiting for.
#[cfg(target_family = "unix")]
#[test]
fn test_list_identities_reports_a_silent_agent_as_a_timeout_error() {
    use std::os::unix::net::UnixListener;

    let temp = tempfile::TempDir::new().unwrap();
    let socket_path = temp.path().join("silent.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    // Hold the accepted connection open for the length of the test: dropping it
    // would close the socket and end the read with EOF rather than a timeout.
    let accepted = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));

    let mut client =
        AgentClient::connect_with_timeout(&socket_path, Duration::from_millis(200)).unwrap();
    let error = client.list_identities().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("ssh-agent did not respond within"),
        "unexpected message: {error}"
    );
    drop(accepted.join().unwrap());
}

/// An agent that answers a byte at a time, each inside a per-syscall bound,
/// never trips one. The deadline covers the whole request, so the exchange is
/// cut short even though every individual read returns promptly.
#[test]
fn test_list_identities_reports_a_drip_feeding_agent_as_a_timeout_error() {
    let stream =
        FakeStream::with_drip_fed_read_data(identities_response(), Duration::from_millis(10));
    let mut client = AgentClient {
        socket: Box::new(stream),
        io_timeout: Duration::from_millis(30),
    };

    let error = client.list_identities().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("ssh-agent did not respond within"),
        "unexpected message: {error}"
    );
}
