// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent client for signing operations

use super::protocol::{
    build_request_identities, build_sign_request, parse_identities_response, parse_sign_response,
    MAX_AGENT_PACKET_SIZE,
};
use super::socket::resolve_agent_socket_path;
use super::traits::AgentSigner;
use super::validation::{find_key_in_agent, validate_agent_has_keys, validate_key_present};
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;
use std::io::{Read, Write};
use std::path::Path;

/// Default ssh-agent signer that communicates with a real ssh-agent.
pub struct DefaultAgentSigner;

impl AgentSigner for DefaultAgentSigner {
    fn sign(&self, ssh_pubkey: &str, message: &[u8]) -> Result<Ed25519RawSignature> {
        let public_key_blob = decode_ssh_public_key_blob(ssh_pubkey)?;
        let (mut client, socket_path) = self.connect_client()?;
        self.validate_target_key(&mut client, &public_key_blob, &socket_path)?;
        client.sign(&public_key_blob, message)
    }
}

impl DefaultAgentSigner {
    fn connect_client(&self) -> Result<(AgentClient, std::path::PathBuf)> {
        let socket_path = resolve_agent_socket_path()?;
        let client = AgentClient::connect(&socket_path)?;
        Ok((client, socket_path))
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

trait ReadWrite: Read + Write {}

impl<T> ReadWrite for T where T: Read + Write {}

struct AgentClient {
    socket: Box<dyn ReadWrite>,
}

impl AgentClient {
    fn connect(path: &Path) -> Result<Self> {
        Ok(Self {
            socket: connect_socket(path)?,
        })
    }

    fn list_identities(&mut self) -> Result<Vec<super::validation::AgentIdentity>> {
        self.write_packet(&build_request_identities())?;
        let response = self.read_packet()?;
        parse_identities_response(&response)
    }

    fn sign(&mut self, public_key_blob: &[u8], message: &[u8]) -> Result<Ed25519RawSignature> {
        self.write_packet(&build_sign_request(public_key_blob, message))?;
        let response = self.read_packet()?;
        parse_sign_response(&response)
    }

    fn write_packet(&mut self, body: &[u8]) -> Result<()> {
        let len = u32::try_from(body.len()).map_err(|_| {
            crate::Error::from(SshError::operation_failed(
                "ssh-agent request exceeds maximum encodable size",
            ))
        })?;
        self.write_all(&len.to_be_bytes())?;
        self.write_all(body)
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_AGENT_PACKET_SIZE {
            return Err(crate::Error::from(SshError::operation_failed(format!(
                "ssh-agent response exceeds maximum size limit ({} bytes > {} bytes)",
                len, MAX_AGENT_PACKET_SIZE
            ))));
        }
        let mut body = vec![0u8; len];
        self.read_exact(&mut body)?;
        Ok(body)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.socket.write_all(bytes).map_err(map_write_error)
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        self.socket.read_exact(bytes).map_err(map_read_error)
    }
}

#[cfg(target_family = "unix")]
fn connect_socket(path: &Path) -> Result<Box<dyn ReadWrite>> {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(path)
        .map(|stream| Box::new(stream) as Box<dyn ReadWrite>)
        .map_err(|e| map_connect_error(path, e))
}

#[cfg(target_family = "windows")]
fn connect_socket(path: &Path) -> Result<Box<dyn ReadWrite>> {
    use std::fs::OpenOptions;

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|file| Box::new(file) as Box<dyn ReadWrite>)
        .map_err(|e| map_connect_error(path, e))
}

fn map_write_error(error: std::io::Error) -> crate::Error {
    crate::Error::from(SshError::operation_failed_with_source(
        format!("ssh-agent write failed: {}", error),
        error,
    ))
}

fn map_read_error(error: std::io::Error) -> crate::Error {
    crate::Error::from(SshError::operation_failed_with_source(
        format!("ssh-agent read failed: {}", error),
        error,
    ))
}

fn map_connect_error(path: &Path, error: std::io::Error) -> crate::Error {
    crate::Error::from(SshError::operation_failed_with_source(
        format!(
            "ssh-agent connect failed for {}: {}",
            display_path_relative_to_cwd(path),
            error
        ),
        error,
    ))
}
