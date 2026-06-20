// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Resource-exhaustion regression tests for the zone parser (PRD SR-005).
//!
//! These assert that adversarial inputs cannot cause pathological runtime or
//! unbounded allocation. They run with `std` available (integration tests are
//! separate std crates) so they can wall-clock the parser without an
//! ASan/libFuzzer confound. Inputs here mirror fuzz-discovered shapes.

use std::time::{Duration, Instant};

use bind9_sdk_core::ZoneFile;

/// No single adversarial input may take longer than this to parse or reject.
/// A correct linear parser handles megabytes in well under this budget; the
/// generous ceiling exists to catch superlinear or non-terminating behavior.
const BUDGET: Duration = Duration::from_secs(5);

fn assert_bounded(label: &str, input: &str) {
    let start = Instant::now();
    // We do not care whether it Ok/Errs — only that it returns promptly and
    // does not hang or exhaust memory.
    let _ = ZoneFile::parse(input);
    let elapsed = start.elapsed();
    assert!(
        elapsed < BUDGET,
        "parsing `{label}` took {elapsed:?}, exceeding {BUDGET:?} (pathological runtime)"
    );
}

#[test]
fn megabyte_of_backslashes_is_bounded() {
    let input = "\\".repeat(1_000_000);
    assert_bounded("1MB backslashes", &input);
}

#[test]
fn megabyte_of_open_parens_is_bounded() {
    let input = "(".repeat(1_000_000);
    assert_bounded("1MB open parens", &input);
}

#[test]
fn many_newlines_in_parens_is_bounded() {
    let mut input = String::from("@ IN SOA ns admin (\n");
    input.push_str(&"\n".repeat(500_000));
    assert_bounded("parenthesized newlines", &input);
}

#[test]
fn long_comment_run_is_bounded() {
    let input = ";".repeat(1_000_000);
    assert_bounded("1MB comment", &input);
}

#[test]
fn huge_single_token_is_bounded() {
    let input = "a".repeat(2_000_000);
    assert_bounded("2MB single token", &input);
}

#[test]
fn many_valid_records_are_bounded() {
    let mut input = String::from("$ORIGIN example.com.\n$TTL 3600\n");
    for i in 0..50_000u32 {
        input.push_str(&format!("host{i} IN A 192.0.2.1\n"));
    }
    assert_bounded("50k records", &input);
}

#[test]
fn oversized_input_is_rejected_before_work() {
    // Inputs beyond the parser's hard size limit (256 MiB) must be rejected
    // up front with a size error (PRD SR-005), not parsed.
    let input = "a".repeat(256 * 1024 * 1024 + 1);
    let start = Instant::now();
    let result = ZoneFile::parse(&input);
    let elapsed = start.elapsed();
    let err = result.expect_err("input exceeding the size limit must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds the maximum"),
        "expected a size-limit error, got: {msg}"
    );
    // Rejection must be immediate — it must not tokenize the oversized input.
    assert!(
        elapsed < BUDGET,
        "size rejection was not prompt: {elapsed:?}"
    );
}
