// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI-owned environment and configuration resolution.
//! Produces explicit paths and policy values before invoking the public API.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cli::common::presentation::{format_path_relative_to_cwd, validate_github_login};
use crate::cli::options::{CommonOptions, ToCommonOptions};
use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::doctor::{DoctorWorkspaceResolution, DoctorWorkspaceSource};
use kapsaro_core::api::key::MemberHandle;
use kapsaro_core::api::ssh::{resolve_ssh_agent_socket, SshSigningInputs, SshSigningMethod};
use kapsaro_core::api::workspace::select_workspace_creation_path;
use kapsaro_core::api::workspace::{detect_workspace_path, validate_workspace_path};
use kapsaro_core::{Error, ErrorKind, Result};
use tracing::debug;

const ENV_HOME: &str = "KAPSARO_HOME";
const ENV_WORKSPACE: &str = "KAPSARO_WORKSPACE";
const ENV_ALLOW_EXPIRED_KEY: &str = "KAPSARO_ALLOW_EXPIRED_KEY";
const ENV_ALLOW_NON_MEMBER: &str = "KAPSARO_ALLOW_NON_MEMBER";
const ENV_MEMBER_HANDLE: &str = "KAPSARO_MEMBER_HANDLE";
const ENV_GITHUB_USER: &str = "KAPSARO_GITHUB_USER";
const ENV_SSH_IDENTITY: &str = "KAPSARO_SSH_IDENTITY";
const ENV_SSH_SIGNING_METHOD: &str = "KAPSARO_SSH_SIGNING_METHOD";

/// Inputs selected once by the CLI for one command invocation.
pub(crate) struct CliContext {
    common: CommonOptions,
    base_dir: OnceCell<Option<PathBuf>>,
    local_state: OnceCell<Option<LocalStateSession>>,
    current_dir: OnceCell<PathBuf>,
    process_home: OnceCell<Option<PathBuf>>,
    agent_socket: OnceCell<Option<PathBuf>>,
}

impl CliContext {
    pub(crate) fn resolve(common: &impl ToCommonOptions) -> Result<Self> {
        Ok(Self {
            common: common.to_common_options(),
            base_dir: OnceCell::new(),
            local_state: OnceCell::new(),
            current_dir: OnceCell::new(),
            process_home: OnceCell::new(),
            agent_socket: OnceCell::new(),
        })
    }

    pub(crate) fn base_dir(&self) -> Result<&Path> {
        self.optional_base_dir()?.ok_or_else(home_required_error)
    }

    pub(crate) fn local_state(&self) -> Result<&LocalStateSession> {
        self.optional_local_state()?.ok_or_else(home_required_error)
    }

    pub(crate) fn optional_local_state(&self) -> Result<Option<&LocalStateSession>> {
        if self.local_state.get().is_none() {
            let local_state = self
                .optional_base_dir()?
                .map(|base_dir| LocalStateSession::open(base_dir.to_path_buf()))
                .transpose()?;
            if let Some(local_state) = &local_state {
                debug!(
                    "[CTX] paths: base_dir={}, keystore_root={}",
                    format_path_relative_to_cwd(local_state.base_dir()),
                    format_path_relative_to_cwd(&local_state.base_dir().join("keys"))
                );
            }
            let _ = self.local_state.set(local_state);
        }
        Ok(self
            .local_state
            .get()
            .expect("local state is fixed after successful resolution")
            .as_ref())
    }

    pub(crate) fn into_optional_local_state(self) -> Result<Option<LocalStateSession>> {
        if self.local_state.get().is_none() {
            let _ = self.optional_local_state()?;
        }
        Ok(self
            .local_state
            .into_inner()
            .expect("local state is fixed after successful resolution"))
    }

    pub(crate) fn workspace_path(&self) -> Result<PathBuf> {
        if let Some(path) = self.selected_workspace_path()? {
            return validate_workspace_path(&path);
        }
        detect_workspace_path(self.current_dir()?).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                workspace_required_error()
            } else {
                error
            }
        })
    }

    pub(crate) fn registration_workspace_path(&self) -> Result<PathBuf> {
        if let Some(path) = self.selected_workspace_path()? {
            return Ok(path);
        }
        select_workspace_creation_path(self.current_dir()?)
    }

    pub(crate) fn doctor_workspace_resolution(&self) -> DoctorWorkspaceResolution {
        self.try_doctor_workspace_resolution()
            .unwrap_or_else(DoctorWorkspaceResolution::Failure)
    }

    fn try_doctor_workspace_resolution(&self) -> Result<DoctorWorkspaceResolution> {
        if let Some(path) = &self.common.workspace {
            return self.doctor_selection(path, DoctorWorkspaceSource::Cli);
        }
        if let Some(path) = optional_env_path(ENV_WORKSPACE)? {
            return self.doctor_selection(&path, DoctorWorkspaceSource::Environment);
        }
        if let Some(path) = self.configured_workspace_path()? {
            return self.doctor_selection(&path, DoctorWorkspaceSource::Config);
        }
        match detect_workspace_path(self.current_dir()?) {
            Ok(path) => Ok(DoctorWorkspaceResolution::Selection {
                path,
                source: DoctorWorkspaceSource::AutoDetect,
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Ok(DoctorWorkspaceResolution::Unresolved)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn allow_expired_key(&self, cli_value: bool) -> Result<bool> {
        self.resolve_yes_no(cli_value, ENV_ALLOW_EXPIRED_KEY, "allow_expired_key")
    }

    pub(crate) fn allow_non_member(&self, cli_value: bool) -> Result<bool> {
        self.resolve_yes_no(cli_value, ENV_ALLOW_NON_MEMBER, "allow_non_member")
    }

    pub(crate) fn strict_key_checking(&self) -> bool {
        std::env::var("KAPSARO_STRICT_KEY_CHECKING")
            .map(|value| !value.eq_ignore_ascii_case("no"))
            .unwrap_or(true)
    }

    pub(crate) fn member_handle(&self, explicit: Option<String>) -> Result<Option<String>> {
        if let Some(member_handle) = self.resolve_member_handle_override(explicit)? {
            return Ok(Some(member_handle));
        }
        let Some(local_state) = self.optional_local_state()? else {
            return Ok(None);
        };
        if let Some(value) = local_state.load_config()?.get("member_handle").cloned() {
            return MemberHandle::try_from(value).map(|handle| Some(handle.into_string()));
        }
        let Some(keys) = local_state.open_optional_key_store()? else {
            return Ok(None);
        };
        let members = keys.list_members()?;
        Ok((members.len() == 1).then(|| members[0].as_str().to_string()))
    }

    pub(crate) fn resolve_member_handle_override(
        &self,
        explicit: Option<String>,
    ) -> Result<Option<String>> {
        explicit
            .or(optional_env(ENV_MEMBER_HANDLE)?)
            .map(MemberHandle::try_from)
            .transpose()
            .map(|handle| handle.map(MemberHandle::into_string))
    }

    pub(crate) fn github_user(&self, explicit: Option<String>) -> Result<Option<String>> {
        let selected = match explicit {
            Some(value) => Some(value),
            None => match optional_env(ENV_GITHUB_USER)? {
                Some(value) => Some(value),
                None => self
                    .optional_local_state()?
                    .map(LocalStateSession::load_config)
                    .transpose()?
                    .and_then(|config| config.get("github_user").cloned()),
            },
        };
        if let Some(login) = selected.as_deref() {
            validate_github_login(login)?;
        }
        Ok(selected)
    }

    pub(crate) fn ssh_signing_inputs(&self) -> Result<SshSigningInputs> {
        let (method, identity, agent_socket) = self.resolve_ssh_method_inputs()?;
        let config = self
            .optional_local_state()?
            .map(LocalStateSession::load_config)
            .transpose()?;
        let ssh_keygen = config
            .and_then(|values| values.get("ssh_keygen_command"))
            .cloned()
            .unwrap_or_else(|| "ssh-keygen".to_string());
        let ssh_add = config
            .and_then(|values| values.get("ssh_add_command"))
            .cloned()
            .unwrap_or_else(|| "ssh-add".to_string());
        Ok(SshSigningInputs::new(
            method,
            identity,
            agent_socket,
            ssh_keygen,
            ssh_add,
        ))
    }

    fn resolve_ssh_method_inputs(
        &self,
    ) -> Result<(SshSigningMethod, Option<PathBuf>, Option<PathBuf>)> {
        let Some(method) = self.select_ssh_signing_method()? else {
            let agent_socket = self.ssh_agent_socket()?.cloned();
            let method = if agent_socket.is_some() {
                SshSigningMethod::SshAgent
            } else {
                SshSigningMethod::SshKeygen
            };
            let identity = self.ssh_identity(method)?;
            return Ok((method, identity, agent_socket));
        };
        let identity = self.ssh_identity(method)?;
        let agent_socket = if method == SshSigningMethod::SshAgent
            || identity.as_deref().is_some_and(is_ssh_public_identity)
        {
            self.ssh_agent_socket()?.cloned()
        } else {
            None
        };
        Ok((method, identity, agent_socket))
    }

    fn resolve_yes_no(&self, cli_value: bool, env_key: &str, config_key: &str) -> Result<bool> {
        if cli_value {
            return Ok(true);
        }
        let value = match optional_env(env_key)? {
            Some(value) => value,
            None => self
                .optional_local_state()?
                .map(LocalStateSession::load_config)
                .transpose()?
                .and_then(|config| config.get(config_key).cloned())
                .unwrap_or_else(|| "no".to_string()),
        };
        parse_yes_no(config_key, &value)
    }

    fn selected_workspace_path(&self) -> Result<Option<PathBuf>> {
        if let Some(path) = &self.common.workspace {
            return Ok(Some(path.clone()));
        }
        if let Some(path) = optional_env_path(ENV_WORKSPACE)? {
            return Ok(Some(path));
        }
        self.configured_workspace_path()
    }

    fn select_ssh_signing_method(&self) -> Result<Option<SshSigningMethod>> {
        if let Some(method) = self.common.ssh_signing_method() {
            return Ok(Some(method));
        }
        let configured = match optional_env(ENV_SSH_SIGNING_METHOD)? {
            Some(value) => value,
            None => self
                .optional_local_state()?
                .map(LocalStateSession::load_config)
                .transpose()?
                .and_then(|config| config.get("ssh_signing_method").cloned())
                .unwrap_or_else(|| "auto".to_string()),
        };
        match configured.as_str() {
            "ssh-agent" => Ok(Some(SshSigningMethod::SshAgent)),
            "ssh-keygen" => Ok(Some(SshSigningMethod::SshKeygen)),
            "auto" => Ok(None),
            _ => Err(Error::build_invalid_argument_error(format!(
                "Invalid signing method '{configured}'. Expected 'auto', 'ssh-agent', or 'ssh-keygen'"
            ))),
        }
    }

    fn ssh_identity(&self, method: SshSigningMethod) -> Result<Option<PathBuf>> {
        if let Some(path) = &self.common.identity {
            return Ok(Some(path.clone()));
        }
        if let Some(path) = optional_env(ENV_SSH_IDENTITY)? {
            return expand_tilde(&path, self.process_home()?).map(Some);
        }
        if let Some(path) = self
            .optional_local_state()?
            .map(LocalStateSession::load_config)
            .transpose()?
            .and_then(|config| config.get("ssh_identity"))
        {
            return expand_tilde(path, self.process_home()?).map(Some);
        }
        match method {
            SshSigningMethod::SshAgent => Ok(None),
            SshSigningMethod::SshKeygen => self
                .process_home()?
                .map(|home| Some(home.join(".ssh").join("id_ed25519")))
                .ok_or_else(|| Error::build_config_error("HOME environment variable not set")),
        }
    }

    fn optional_base_dir(&self) -> Result<Option<&Path>> {
        if self.base_dir.get().is_none() {
            let base_dir = if let Some(path) = &self.common.home {
                Some(path.clone())
            } else if let Some(path) = optional_env_path(ENV_HOME)? {
                Some(path)
            } else {
                self.process_home()?
                    .map(|path| path.join(".config").join("kapsaro"))
            };
            let _ = self.base_dir.set(base_dir);
        }
        Ok(self
            .base_dir
            .get()
            .expect("base directory is fixed after successful resolution")
            .as_deref())
    }

    fn process_home(&self) -> Result<Option<&Path>> {
        if self.process_home.get().is_none() {
            let _ = self.process_home.set(optional_env_path("HOME")?);
        }
        Ok(self
            .process_home
            .get()
            .expect("process home is fixed after successful resolution")
            .as_deref())
    }

    fn current_dir(&self) -> Result<&Path> {
        if self.current_dir.get().is_none() {
            let current_dir = std::env::current_dir().map_err(|error| {
                Error::build_config_error(format!("Failed to get current directory: {error}"))
            })?;
            let _ = self.current_dir.set(current_dir);
        }
        Ok(self
            .current_dir
            .get()
            .expect("current directory is fixed after successful resolution"))
    }

    fn configured_workspace_path(&self) -> Result<Option<PathBuf>> {
        self.optional_local_state()?
            .map(LocalStateSession::load_config)
            .transpose()?
            .and_then(|config| config.get("workspace"))
            .map(|path| expand_tilde(path, self.process_home()?).map(Some))
            .unwrap_or(Ok(None))
    }

    fn doctor_selection(
        &self,
        path: &Path,
        source: DoctorWorkspaceSource,
    ) -> Result<DoctorWorkspaceResolution> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.current_dir()?.join(path)
        };
        Ok(DoctorWorkspaceResolution::Selection { path, source })
    }

    fn ssh_agent_socket(&self) -> Result<Option<&PathBuf>> {
        if self.agent_socket.get().is_none() {
            let ssh_auth_sock = optional_env_path("SSH_AUTH_SOCK")?;
            let mut expansion_values = environment_expansion_values();
            match self.process_home()? {
                Some(home) => {
                    expansion_values.insert("HOME".to_string(), home.display().to_string());
                }
                None => {
                    expansion_values.remove("HOME");
                }
            }
            let socket =
                resolve_ssh_agent_socket(self.process_home()?, ssh_auth_sock, &expansion_values)?;
            let _ = self.agent_socket.set(socket);
        }
        Ok(self
            .agent_socket
            .get()
            .expect("agent socket is fixed after successful resolution")
            .as_ref())
    }
}

fn optional_env_path(key: &str) -> Result<Option<PathBuf>> {
    optional_env(key).map(|value| value.map(PathBuf::from))
}

fn is_ssh_public_identity(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("pub")
}

fn optional_env(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::build_config_error(format!(
            "{key} environment variable contains invalid UTF-8"
        ))),
    }
}

fn expand_tilde(value: &str, process_home: Option<&Path>) -> Result<PathBuf> {
    if value == "~" {
        return process_home
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::build_config_error("HOME environment variable not set"));
    }
    if let Some(suffix) = value.strip_prefix("~/") {
        let home = process_home
            .ok_or_else(|| Error::build_config_error("HOME environment variable not set"))?;
        return Ok(home.join(suffix));
    }
    Ok(PathBuf::from(value))
}

fn environment_expansion_values() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

fn home_required_error() -> Error {
    Error::build_config_error("HOME environment variable not set")
}

fn parse_yes_no(key: &str, value: &str) -> Result<bool> {
    if value.eq_ignore_ascii_case("yes") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("no") {
        return Ok(false);
    }
    Err(Error::build_config_error_with_rule(
        "E_CONFIG_VALUE_INVALID",
        format!("Invalid {key} value '{value}'. Expected 'yes' or 'no'."),
    ))
}

fn workspace_required_error() -> Error {
    Error::build_not_found_error(
        "workspace not found.\n\
         Reason: This command requires a Kapsaro workspace, but no workspace could be resolved.\n\
         Action: Initialize a workspace or select an existing one.\n\
         Options:\n\
         1. Run kapsaro init in a Git repository.\n\
         2. Use --workspace <path> to select a workspace.",
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_context_test.rs"]
mod cli_common_context_test;
