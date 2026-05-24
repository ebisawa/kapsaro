// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::kv::query::{execute_kv_env_command, KvReadCommand};
use crate::io::process::execute_command_with_env;
use crate::{Error, Result};

pub fn execute_run_command(
    command: &KvReadCommand,
    command_args: &[String],
    debug: bool,
) -> Result<i32> {
    let env_vars = execute_kv_env_command(command, debug)?;
    let (command, args) = split_command_args(command_args)?;
    execute_command_with_env(&command, &args, &env_vars)
}

fn split_command_args(command_args: &[String]) -> Result<(String, Vec<String>)> {
    let (command, args) = command_args
        .split_first()
        .ok_or_else(|| Error::build_config_error("No command specified".to_string()))?;
    Ok((command.clone(), args.to_vec()))
}
