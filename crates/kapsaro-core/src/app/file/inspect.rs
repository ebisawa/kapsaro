// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Coordinates the inspect file use case for CLI-facing callers.
// Keeps public command DTOs and compatibility re-exports at the module root.

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::feature::inspect::verification::build_signature_verification_section;
use crate::feature::inspect::{
    build_inspect_view, InspectOutput as FeatureInspectOutput,
    InspectSection as FeatureInspectSection,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

mod collection;
mod json;

pub use json::{FileEncInspectJsonOutput, InspectJsonOutput, KvEncInspectJsonOutput};

use collection::{build_online_output, build_signature_report, load_inspect_content};
use json::build_inspect_json_output;

pub struct InspectCommand {
    pub input_display: String,
    pub output: InspectOutput,
    pub json_output: InspectJsonOutput,
}

/// Online verification display variants.
pub enum OnlineVerificationDisplay {
    /// GitHub verification result available.
    GithubResult(crate::io::verify_online::VerificationResult),
    /// Binding claims exist but no supported binding is configured.
    NoSupportedBinding,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InspectOutput {
    pub title: String,
    pub sections: Vec<InspectSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InspectSection {
    pub title: String,
    pub lines: Vec<String>,
}

impl From<FeatureInspectOutput> for InspectOutput {
    fn from(output: FeatureInspectOutput) -> Self {
        Self {
            title: output.title,
            sections: output
                .sections
                .into_iter()
                .map(InspectSection::from)
                .collect(),
        }
    }
}

impl From<FeatureInspectSection> for InspectSection {
    fn from(section: FeatureInspectSection) -> Self {
        Self {
            title: section.title,
            lines: section.lines,
        }
    }
}

pub fn execute_inspect_file_command(
    options: &CommonCommandOptions,
    input_path: &Path,
) -> Result<InspectCommand> {
    let content = load_inspect_content(input_path)?;
    let mut inspect_output = InspectOutput::from(build_inspect_view(&content)?);
    let signature_report = build_signature_report(&content, options.debug)?;
    let online_output = build_online_output(options, &signature_report);

    inspect_output
        .sections
        .push(build_signature_verification_section(&signature_report).into());

    if let Some(online) = &online_output {
        inspect_output.sections.push(online.section.clone());
    }

    let json_output = build_inspect_json_output(
        &content,
        &signature_report,
        online_output.as_ref().map(|online| online.json.clone()),
    )?;

    Ok(InspectCommand {
        input_display: format_path_relative_to_cwd(input_path),
        output: inspect_output,
        json_output,
    })
}

pub use collection::build_online_verification_section;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_inspect_verification_test.rs"]
mod feature_inspect_verification_test;
