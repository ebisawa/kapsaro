// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use console::Style;

use crate::app::context::options::CommonCommandOptions;
use crate::feature::inspect::build_inspect_view;
use crate::feature::inspect::verification::{
    build_online_verification_section, build_signature_verification_section,
    OnlineVerificationDisplay,
};
use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::signature::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncryptedContent;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationResult as OnlineVerificationResult;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::encrypted_file_read_limit;
use crate::support::path::display_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

pub(crate) struct InspectCommand {
    pub input_display: String,
    pub rendered: String,
}

pub(crate) fn build_inspect_file_command(
    options: &CommonCommandOptions,
    input_path: &Path,
) -> Result<InspectCommand> {
    let content = load_inspect_content(input_path)?;
    let inspect_output = build_inspect_view(&content)?;
    let signature_report = build_signature_report(&content, options.verbose)?;
    let mut sections = inspect_output.sections;
    sections.push(build_signature_verification_section(&signature_report));

    if let Some(section) = build_online_section(options, &signature_report) {
        sections.push(section);
    }

    Ok(InspectCommand {
        input_display: display_path_relative_to_cwd(input_path),
        rendered: render_inspect_output(&inspect_output.title, &sections),
    })
}

fn load_inspect_content(input_path: &Path) -> Result<EncryptedContent> {
    EncryptedContent::detect(load_text_with_limit(
        input_path,
        encrypted_file_read_limit(input_path),
        "encrypted artifact",
    )?)
}

fn build_signature_report(
    content: &EncryptedContent,
    debug: bool,
) -> Result<SignatureVerificationReport> {
    Ok(match content {
        EncryptedContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            verify_file_document_report(&doc, debug)
        }
        EncryptedContent::KvEnc(kv_content) => {
            verify_kv_document_report(kv_content.as_str(), debug)
        }
    })
}

fn build_online_section(
    options: &CommonCommandOptions,
    report: &SignatureVerificationReport,
) -> Option<crate::feature::inspect::InspectSection> {
    let public_key = report.signer_public_key.as_ref()?;
    if !report.verified {
        return None;
    }

    let binding_claims = public_key.protected.binding_claims.as_ref()?;
    let github = match binding_claims.github_account.as_ref() {
        Some(github) => github,
        None => {
            return Some(build_online_verification_section(
                &OnlineVerificationDisplay::NoSupportedBinding,
                None,
                None,
            ));
        }
    };

    let result = match block_on_result(verify_github_account(public_key, options.verbose, None)) {
        Ok(result) => result,
        Err(err) => OnlineVerificationResult::failed(
            &public_key.protected.member_id,
            err.user_message().to_string(),
            None,
            true,
        ),
    };
    let verified_github = result.verified_github.clone();
    let github_login = verified_github
        .as_ref()
        .map(|verified| verified.login.as_str())
        .or(Some(github.login.as_str()));
    let github_id = verified_github
        .as_ref()
        .map(|verified| verified.id)
        .or(Some(github.id));
    Some(build_online_verification_section(
        &OnlineVerificationDisplay::GithubResult(result),
        github_login,
        github_id,
    ))
}

fn render_inspect_output(
    title: &str,
    sections: &[crate::feature::inspect::InspectSection],
) -> String {
    let title_style = Style::new().bold();
    let section_style = Style::new().bold();

    let mut out = String::new();
    out.push_str(&format!("{}\n", title_style.apply_to(title)));
    out.push('\n');
    for (index, section) in sections.iter().enumerate() {
        out.push_str(&format!("{}\n", section_style.apply_to(&section.title)));
        for line in &section.lines {
            out.push_str(&colorize_inspect_line(line));
            out.push('\n');
        }
        if index + 1 != sections.len() {
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

fn colorize_inspect_line(line: &str) -> String {
    let ok_style = Style::new().green().for_stdout();
    let ng_style = Style::new().red().for_stdout();
    let warning_style = Style::new().yellow().for_stdout();
    let is_disclosed_warning =
        line.contains("\u{26a0} DISCLOSED \u{2014} Secret may need rotation");
    if line.contains("\u{2714} OK") {
        line.replace(
            "\u{2714} OK",
            &format!("{}", ok_style.apply_to("\u{2714} OK")),
        )
    } else if line.contains("\u{2718} FAILED") {
        line.replace(
            "\u{2718} FAILED",
            &format!("{}", ng_style.apply_to("\u{2718} FAILED")),
        )
    } else if line.trim_start().starts_with("Warning:") || is_disclosed_warning {
        warning_style.apply_to(line).to_string()
    } else {
        line.to_string()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/app_file_inspect_test.rs"]
mod tests;
