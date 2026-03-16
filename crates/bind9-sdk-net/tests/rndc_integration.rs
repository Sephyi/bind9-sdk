// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for rndc wire protocol against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:9953
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
    let addr = "127.0.0.1:9953".parse().unwrap();
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
#[ignore = "requires live BIND9 on localhost:9953"]
async fn rndc_wrong_key_fails_auth() {
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
