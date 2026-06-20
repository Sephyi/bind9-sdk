// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! End-to-end CLI tests against the repository's live BIND9 fixture.

use std::process::Command;

const TEST_KEY_SECRET: &str = "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==";

#[test]
#[ignore = "requires live BIND9 statistics-channel on localhost:8053"]
fn zone_list_accepts_stats_url_entirely_from_cli_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_bind9"))
        .args([
            "--server",
            "127.0.0.1",
            "--port",
            "9953",
            "--dns-port",
            "15353",
            "--stats-url",
            "http://127.0.0.1:8053/json/v1",
            "--key-name",
            "rndc-test-key",
            "--key-secret",
            TEST_KEY_SECRET,
            "--output",
            "json",
            "zone",
            "list",
        ])
        .output()
        .expect("failed to execute bind9 CLI");

    assert!(
        output.status.success(),
        "bind9 zone list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("zone list did not emit valid JSON");
    let zones = body["zones"]
        .as_array()
        .expect("zone list JSON is missing the zones array");

    for expected in [
        "example.com.",
        "dnssec.example.com.",
        "transfer.example.com.",
    ] {
        assert!(
            zones.iter().any(|zone| zone["name"] == expected),
            "zone list did not contain {expected}"
        );
    }
}
