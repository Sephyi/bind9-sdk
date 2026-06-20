// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for rndc wire protocol against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:9953
//! - An rndc key configured in named.conf matching the test key below
//!
//! Run with: `cargo test -p bind9-sdk-net --test rndc_integration -- --ignored`
//!
//! **Note:** BIND9's control channel handles one connection at a time.
//! Tests must run serially (`--test-threads=1`) and include a brief delay
//! to let the server clean up between connections.
//!
//! See `tests/README.md` for BIND9 setup instructions.

use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_net::rndc::RndcConnection;
use bind9_sdk_net::rndc::command::{RndcCommand, ZoneTarget};
use bind9_sdk_net::rndc::dnssec::DnssecStatus;

/// Brief delay to let BIND9's control channel release the previous connection.
///
/// BIND9's rndc handler is single-connection; without this delay,
/// back-to-back tests can get EOF when the server hasn't finished
/// tearing down the previous session.
async fn rndc_settle() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Test rndc key for integration tests.
///
/// This key must match the key configured in the test BIND9 instance's
/// `named.conf`:
///
/// ```conf
/// key "rndc-test-key" {
///     algorithm hmac-sha256;
///     secret "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==";
/// };
/// ```
fn test_key() -> bind9_sdk_core::tsig::TsigKey {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::TsigAlgorithm;

    bind9_sdk_core::tsig::TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .expect("test key must be valid")
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_connect_and_status() {
    rndc_settle().await;
    let addr = "127.0.0.1:9953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::Status)
        .await
        .expect("status command failed");

    assert!(resp.is_success(), "status command failed: {:?}", resp);
    assert!(
        resp.text.contains("version"),
        "status output should contain version info"
    );

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_reload() {
    rndc_settle().await;
    let addr = "127.0.0.1:9953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::Reload { target: None })
        .await
        .expect("reload command failed");

    assert!(resp.is_success(), "reload command failed: {:?}", resp);

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_wrong_key_fails_auth() {
    rndc_settle().await;
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::TsigAlgorithm;

    let addr: std::net::SocketAddr = "127.0.0.1:9953".parse().unwrap();
    let wrong_key = bind9_sdk_core::tsig::TsigKey::new(
        DomainName::new("wrong-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0xBA; 32],
    )
    .unwrap();
    let conn = RndcConnection::connect(addr).await.unwrap();
    let result = conn.authenticate(&wrong_key).await;
    assert!(result.is_err(), "wrong key should fail authentication");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_multiple_commands_on_same_connection() {
    rndc_settle().await;
    let addr = "127.0.0.1:9953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");

    // First command
    let resp1 = conn
        .command(RndcCommand::Status)
        .await
        .expect("first status failed");
    assert!(resp1.is_success());

    // Second command on same connection
    let resp2 = conn
        .command(RndcCommand::Stats)
        .await
        .expect("stats command failed");
    assert!(resp2.is_success());

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_zone_status_returns_requested_zone() {
    rndc_settle().await;
    let addr = "127.0.0.1:9953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::ZoneStatus {
            target: ZoneTarget::new(DomainName::new("example.com.").unwrap()),
        })
        .await
        .expect("zonestatus command failed");

    assert!(resp.is_success(), "zonestatus failed: {resp:?}");
    assert!(
        resp.text.contains("example.com"),
        "zonestatus output should identify the requested zone: {}",
        resp.text
    );
    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_dnssec_status_parses_current_bind_output() {
    rndc_settle().await;
    let addr = "127.0.0.1:9953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::DnssecStatus {
            target: ZoneTarget::new(DomainName::new("dnssec.example.com.").unwrap()),
        })
        .await
        .expect("dnssec status command failed");

    assert!(resp.is_success(), "dnssec status failed: {resp:?}");
    let status = DnssecStatus::parse(&resp.text)
        .unwrap_or_else(|error| panic!("failed to parse {error}; raw output:\n{}", resp.text));
    assert!(!status.policy.is_empty());
    assert!(!status.keys.is_empty());
    conn.close().await.expect("close failed");
}
