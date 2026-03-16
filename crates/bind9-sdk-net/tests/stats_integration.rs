// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for the BIND9 statistics-channel HTTP client.
//!
//! These tests require BIND9 9.20 with statistics-channels enabled on port 8053.
//!
//! Run with:
//!   cargo test -p bind9-sdk-net --test stats_integration -- --ignored
//!
//! See `tests/README.md` for BIND9 setup instructions.

use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_net::stats::StatsHttpClient;

// ---------------------------------------------------------------------------
// Test: fetch server stats — version field must be non-empty.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live BIND9 statistics-channel on localhost:8053"]
async fn stats_fetch_server_stats_has_version() {
    let client = StatsHttpClient::new("http://127.0.0.1:8053/json/v1", Duration::from_secs(5))
        .expect("client construction failed");

    let stats = client
        .fetch_server_stats()
        .await
        .expect("fetch_server_stats failed");

    assert!(
        stats.version.as_deref().is_some_and(|v| !v.is_empty()),
        "expected non-empty version in ServerStats, got {:?}",
        stats.version
    );
}

// ---------------------------------------------------------------------------
// Test: fetch zone stats for example.com — serial must match the zone file.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live BIND9 statistics-channel on localhost:8053"]
async fn stats_fetch_zone_stats_example_com() {
    let client = StatsHttpClient::new("http://127.0.0.1:8053/json/v1", Duration::from_secs(5))
        .expect("client construction failed");

    let zone_name = DomainName::new("example.com.").unwrap();
    let stats = client
        .fetch_zone_stats(&zone_name)
        .await
        .expect("fetch_zone_stats failed");

    // The test zone file sets serial = 2026031601.
    // After dynamic updates in nsupdate tests, the serial may have been
    // incremented — we only check it is >= the initial value.
    let serial = stats.serial.value();
    assert!(
        serial >= 2026031601,
        "serial {serial} is less than initial value 2026031601"
    );
}

// ---------------------------------------------------------------------------
// Test: connect to wrong port → NetError::Connection (not Http — connection
// refused maps to Connection, not Http; Http is for non-2xx status codes).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live BIND9 statistics-channel on localhost:8053"]
async fn stats_wrong_port_returns_connection_error() {
    // Port 19999 should be closed on the test host.
    let client = StatsHttpClient::new("http://127.0.0.1:19999/json/v1", Duration::from_secs(2))
        .expect("client construction failed");

    let err = client
        .fetch_server_stats()
        .await
        .expect_err("expected error connecting to wrong port");

    assert!(
        matches!(err, bind9_sdk_net::error::NetError::Connection(_)),
        "expected NetError::Connection, got {err:?}"
    );
}
