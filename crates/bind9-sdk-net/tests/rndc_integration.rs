// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for rndc wire protocol against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:953
//! - An rndc key configured in named.conf matching the test key below
//!
//! Run with: `cargo test -p bind9-sdk-net -- --ignored rndc_integration`
//!
//! See `tests/README.md` for BIND9 setup instructions.

use bind9_sdk_net::rndc::RndcConnection;
use bind9_sdk_net::rndc::command::RndcCommand;

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
    // TODO: Construct TsigKey from base64 once TsigKey::from_base64 is available.
    // For now this is a placeholder that will be filled in when WT-2 is merged.
    todo!("construct test TsigKey -- depends on WT-2 TsigKey::from_base64")
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_connect_and_status() {
    let addr = "127.0.0.1:953".parse().unwrap();
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
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_reload() {
    let addr = "127.0.0.1:953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::Reload)
        .await
        .expect("reload command failed");

    assert!(resp.is_success(), "reload command failed: {:?}", resp);

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_wrong_key_fails_auth() {
    let _addr: std::net::SocketAddr = "127.0.0.1:953".parse().unwrap();
    // TODO: Construct a wrong key to test auth failure.
    // let wrong_key = TsigKey::new(...);
    // let conn = RndcConnection::connect(addr).await.unwrap();
    // let result = conn.authenticate(&wrong_key).await;
    // assert!(result.is_err());
    // assert!(matches!(result.unwrap_err(), NetError::AuthFailed));
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_multiple_commands_on_same_connection() {
    let addr = "127.0.0.1:953".parse().unwrap();
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
