// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    build_rewrap_operation_plan, rewrite_with_rewrap_operation_plan, RewrapExecutor, RewrapOptions,
};
use crate::format::token::TokenCodec;
use crate::Result;

fn options(rotate_key: bool, clear_disclosure_history: bool) -> RewrapOptions {
    RewrapOptions {
        rotate_key,
        clear_disclosure_history,
        token_codec: Some(TokenCodec::JsonJcs),
        debug: false,
    }
}

#[test]
fn test_build_rewrap_operation_plan_tracks_common_skeleton_inputs() {
    let current = vec!["alice".to_string(), "carol".to_string()];
    let target = vec!["alice".to_string(), "bob".to_string()];
    let stale = vec!["alice".to_string()];

    let plan = build_rewrap_operation_plan(&current, &target, &stale, &options(true, true));

    assert_eq!(plan.remove_recipients, vec!["carol"]);
    assert_eq!(plan.stale_recipient_handles, vec!["alice"]);
    assert_eq!(plan.add_recipients, vec!["bob"]);
    assert!(plan.rotate_key);
    assert!(plan.clear_disclosure_history);
}

#[derive(Default)]
struct RecordingExecutor {
    calls: Vec<String>,
}

impl RecordingExecutor {
    fn record(&mut self, name: &str, recipients: &[String]) {
        self.calls
            .push(format!("{}:{}", name, recipients.join(",")));
    }
}

impl RewrapExecutor for RecordingExecutor {
    fn current_recipients(&self) -> Vec<String> {
        Vec::new()
    }

    fn add_recipients(&mut self, recipients: &[String]) -> Result<()> {
        self.record("add", recipients);
        Ok(())
    }

    fn rewrite_recipient_wraps(&mut self, recipients: &[String]) -> Result<()> {
        self.record("stale", recipients);
        Ok(())
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        self.record("remove", recipients);
        Ok(())
    }

    fn rotate_key(&mut self) -> Result<()> {
        self.calls.push("rotate".to_string());
        Ok(())
    }

    fn clear_disclosure_history(&mut self) -> Result<()> {
        self.calls.push("clear".to_string());
        Ok(())
    }

    fn finalize(mut self) -> Result<String> {
        self.calls.push("finalize".to_string());
        Ok(self.calls.join("|"))
    }
}

#[test]
fn test_rewrite_with_rewrap_operation_plan_applies_operations_in_common_order() {
    let current = vec!["alice".to_string(), "carol".to_string()];
    let target = vec!["alice".to_string(), "bob".to_string()];
    let stale = vec!["alice".to_string()];
    let plan = build_rewrap_operation_plan(&current, &target, &stale, &options(true, true));

    let result =
        rewrite_with_rewrap_operation_plan(RecordingExecutor::default(), plan, false).unwrap();

    assert_eq!(
        result,
        "remove:carol|stale:alice|add:bob|rotate|clear|finalize"
    );
}

#[test]
fn test_rewrite_with_rewrap_operation_plan_skips_empty_operations() {
    let current = vec!["alice".to_string()];
    let target = vec!["alice".to_string()];
    let stale = Vec::new();
    let plan = build_rewrap_operation_plan(&current, &target, &stale, &options(false, false));

    let result =
        rewrite_with_rewrap_operation_plan(RecordingExecutor::default(), plan, false).unwrap();

    assert_eq!(result, "finalize");
}
