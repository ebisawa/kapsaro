// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! import command - import .env file into kv-enc secrets

use clap::Args;

use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::mutation::import_kv_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::output::json::print_json_output;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::support::fs::load_text;
use crate::Result;

#[derive(Args)]
pub struct ImportArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// File to import (.env format)
    pub filename: String,
}

pub fn run(args: ImportArgs) -> Result<()> {
    let content = load_text(std::path::Path::new(&args.filename))?;
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member_id.clone())?;
    let (outcome, entry_count) = import_kv_command(
        options,
        args.member_id.clone(),
        args.name.as_deref(),
        &content,
        None,
        ssh_ctx,
    )?;
    if let Some(message) = outcome.message {
        if !args.common.quiet {
            eprintln!("{}", message);
        }
    } else if !args.common.quiet {
        eprintln!("Imported {} entries", entry_count);
    }

    if args.common.json {
        let file_name = args.name.as_deref().unwrap_or("default");
        print_json_output(&serde_json::json!({
            "imported": entry_count,
            "file": file_name,
        }))?;
    }

    Ok(())
}
