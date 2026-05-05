// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::inspect::InspectOutput;

use super::InspectCommand;

#[test]
fn test_inspect_command_carries_output_dto() {
    let command = InspectCommand {
        input_display: "secrets.env.enc".to_string(),
        output: InspectOutput {
            title: "secretenv inspect".to_string(),
            sections: Vec::new(),
        },
    };

    assert_eq!(command.input_display, "secrets.env.enc");
    assert_eq!(command.output.title, "secretenv inspect");
    assert!(command.output.sections.is_empty());
}
