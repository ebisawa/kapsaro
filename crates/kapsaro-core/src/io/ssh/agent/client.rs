// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent client for signing operations

use super::protocol::{
    build_request_identities, build_sign_request, parse_identities_response, parse_sign_response,
    MAX_AGENT_PACKET_SIZE,
};
use super::traits::AgentSigner;
use super::validation::{find_key_in_agent, validate_agent_has_keys, validate_key_present};
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::support::limits::SSH_AGENT_IO_TIMEOUT;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Default ssh-agent signer bound to one caller-selected socket.
pub struct DefaultAgentSigner {
    socket_path: PathBuf,
}

impl AgentSigner for DefaultAgentSigner {
    fn sign(&self, ssh_pubkey: &str, message: &[u8]) -> Result<Ed25519RawSignature> {
        let public_key_blob = decode_ssh_public_key_blob(ssh_pubkey)?;
        let (mut client, socket_path) = self.connect_client()?;
        self.validate_target_key(&mut client, &public_key_blob, &socket_path)?;
        client.sign(&public_key_blob, message)
    }
}

impl DefaultAgentSigner {
    /// Bind a signer to the socket selected before the operation starts.
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn connect_client(&self) -> Result<(AgentClient, std::path::PathBuf)> {
        let client = AgentClient::connect(&self.socket_path)?;
        Ok((client, self.socket_path.clone()))
    }

    fn validate_target_key(
        &self,
        client: &mut AgentClient,
        public_key_blob: &[u8],
        socket_path: &Path,
    ) -> Result<()> {
        let identities = client.list_identities()?;
        validate_agent_has_keys(&identities, socket_path)?;
        let target_key_present = find_key_in_agent(&identities, public_key_blob)?;
        validate_key_present(target_key_present, socket_path)
    }
}

/// A byte stream to the agent whose next operation can be given a time bound.
///
/// The bound has to be reset before every syscall rather than once at connect
/// time, because the deadline it enforces belongs to a whole request and each
/// syscall may only have what is left of it.
trait AgentSocket: Read + Write {
    fn set_io_timeout(&self, timeout: Duration) -> std::io::Result<()>;
}

#[cfg(target_family = "unix")]
impl AgentSocket for std::os::unix::net::UnixStream {
    fn set_io_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

struct AgentClient {
    socket: Box<dyn AgentSocket>,
    io_timeout: Duration,
}

impl AgentClient {
    fn connect(path: &Path) -> Result<Self> {
        Self::connect_with_timeout(path, SSH_AGENT_IO_TIMEOUT)
    }

    /// Open the socket that every later request is bounded against.
    ///
    /// Connecting itself is not bounded: `UnixStream::connect` takes no timeout,
    /// and a Unix socket either has a listener or is refused at once, so there
    /// is no blocking handshake to cut short. The bound starts at the first
    /// request.
    ///
    /// The bound is a parameter so a test can reach the timeout without waiting
    /// out the one production uses.
    fn connect_with_timeout(path: &Path, io_timeout: Duration) -> Result<Self> {
        Ok(Self {
            socket: connect_socket(path)?,
            io_timeout,
        })
    }

    fn list_identities(&mut self) -> Result<Vec<super::validation::AgentIdentity>> {
        let deadline = self.open_request();
        self.save_packet(&build_request_identities(), deadline)?;
        let response = self.load_packet(deadline)?;
        parse_identities_response(&response)
    }

    fn sign(&mut self, public_key_blob: &[u8], message: &[u8]) -> Result<Ed25519RawSignature> {
        let deadline = self.open_request();
        self.save_packet(&build_sign_request(public_key_blob, message)?, deadline)?;
        let response = self.load_packet(deadline)?;
        parse_sign_response(&response)
    }

    /// The instant by which the request starting now has to be finished.
    ///
    /// The bound covers the exchange rather than one syscall. An agent that
    /// answers a byte at a time, each just inside a per-syscall bound, would
    /// otherwise hold the command open without ever tripping one.
    fn open_request(&self) -> Instant {
        Instant::now() + self.io_timeout
    }

    fn save_packet(&mut self, body: &[u8], deadline: Instant) -> Result<()> {
        let len = u32::try_from(body.len()).map_err(|_| {
            crate::Error::from(SshError::build_operation_failed_error(
                "ssh-agent request exceeds maximum encodable size",
            ))
        })?;
        self.save_bytes(&len.to_be_bytes(), deadline)?;
        self.save_bytes(body, deadline)
    }

    fn load_packet(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.load_exact_bytes(&mut len_buf, deadline)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_AGENT_PACKET_SIZE {
            return Err(crate::Error::from(SshError::build_operation_failed_error(
                format!(
                    "ssh-agent response exceeds maximum size limit ({} bytes > {} bytes)",
                    len, MAX_AGENT_PACKET_SIZE
                ),
            )));
        }
        let mut body = vec![0u8; len];
        self.load_exact_bytes(&mut body, deadline)?;
        Ok(body)
    }

    fn save_bytes(&mut self, bytes: &[u8], deadline: Instant) -> Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            self.arm_socket(deadline)?;
            match self.socket.write(&bytes[written..]) {
                Ok(0) => return Err(build_disconnected_error("accepting the request")),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(build_write_error(error, self.io_timeout)),
            }
        }
        Ok(())
    }

    fn load_exact_bytes(&mut self, bytes: &mut [u8], deadline: Instant) -> Result<()> {
        let mut filled = 0;
        while filled < bytes.len() {
            self.arm_socket(deadline)?;
            match self.socket.read(&mut bytes[filled..]) {
                Ok(0) => return Err(build_disconnected_error("sending the response")),
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(build_read_error(error, self.io_timeout)),
            }
        }
        Ok(())
    }

    /// Bound the next syscall by whatever is left of the request's deadline.
    fn arm_socket(&self, deadline: Instant) -> Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(build_agent_timeout_error(self.io_timeout));
        }
        self.socket
            .set_io_timeout(remaining)
            .map_err(build_timeout_setup_error)
    }
}

#[cfg(target_family = "unix")]
fn connect_socket(path: &Path) -> Result<Box<dyn AgentSocket>> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(path).map_err(|e| build_connect_error(path, e))?;
    Ok(Box::new(stream) as Box<dyn AgentSocket>)
}

/// Report an agent that ended the exchange partway through a packet.
fn build_disconnected_error(stage: &str) -> crate::Error {
    crate::Error::from(SshError::build_operation_failed_error(format!(
        "ssh-agent closed the connection while {}",
        stage
    )))
}

fn build_timeout_setup_error(error: std::io::Error) -> crate::Error {
    crate::Error::from(SshError::build_operation_failed_error_with_source(
        format!("ssh-agent socket deadline could not be set: {}", error),
        error,
    ))
}

fn build_write_error(error: std::io::Error, io_timeout: Duration) -> crate::Error {
    if let Some(timeout_error) = build_expired_deadline_error(&error, io_timeout) {
        return timeout_error;
    }
    crate::Error::from(SshError::build_operation_failed_error_with_source(
        format!("ssh-agent write failed: {}", error),
        error,
    ))
}

fn build_read_error(error: std::io::Error, io_timeout: Duration) -> crate::Error {
    if let Some(timeout_error) = build_expired_deadline_error(&error, io_timeout) {
        return timeout_error;
    }
    crate::Error::from(SshError::build_operation_failed_error_with_source(
        format!("ssh-agent read failed: {}", error),
        error,
    ))
}

/// Name a socket deadline that expired as the agent failing to answer.
///
/// A read that hit `SO_RCVTIMEO` is reported as `WouldBlock` on some platforms
/// and `TimedOut` on others, and both mean the same thing here. The raw kind
/// would send the operator looking for a transport fault instead of at the
/// agent.
fn build_expired_deadline_error(
    error: &std::io::Error,
    io_timeout: Duration,
) -> Option<crate::Error> {
    if !matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        return None;
    }
    Some(build_agent_timeout_error(io_timeout))
}

/// Report the whole request as having outlived its bound.
fn build_agent_timeout_error(io_timeout: Duration) -> crate::Error {
    crate::Error::from(SshError::build_operation_failed_error(format!(
        "ssh-agent did not respond within {} seconds",
        io_timeout.as_secs_f32()
    )))
}

fn build_connect_error(path: &Path, error: std::io::Error) -> crate::Error {
    crate::Error::from(SshError::build_operation_failed_error_with_source(
        format!(
            "ssh-agent connect failed for {}: {}",
            format_path_relative_to_cwd(path),
            error
        ),
        error,
    ))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_agent_client_test.rs"]
mod io_ssh_agent_client_test;
