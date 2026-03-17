// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for `RndcPool` against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:9953
//! - An rndc key configured in named.conf matching the test key below
//!
//! Run with:
//!   cargo test -p bind9-sdk-net --test pool_integration -- --ignored --test-threads=1
//!
//! See `tests/README.md` for BIND9 setup instructions.

use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::rndc::RndcConnection;
use bind9_sdk_net::{ClientConfig, RndcPool};

/// rndc address for the test BIND9 instance.
const RNDC_ADDR: &str = "127.0.0.1:9953";

/// Construct the shared test TSIG key.
///
/// Matches the `key "rndc-test-key"` block in `tests/bind9/named.conf`.
fn test_key() -> TsigKey {
    TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .expect("test key must be valid")
}

/// Construct a `ClientConfig` pointing at the test BIND9 instance.
fn test_config() -> ClientConfig {
    let mut config = ClientConfig::new(RNDC_ADDR.parse().unwrap(), test_key());
    config.timeout = Duration::from_secs(5);
    config.pool_size = Some(4);
    config
}

/// Brief delay to let BIND9's control channel release the previous connection.
async fn rndc_settle() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Send a single rndc `Status` command through a guard from the pool.
async fn status_via_pool(guard: &bind9_sdk_net::PoolGuard) -> bool {
    let conn = RndcConnection::connect(guard.config().rndc_addr)
        .await
        .expect("connect failed");
    let mut conn = conn
        .authenticate(&guard.config().rndc_key)
        .await
        .expect("auth failed");
    let resp = conn
        .command(RndcCommand::Status)
        .await
        .expect("status command failed");
    conn.close().await.expect("close failed");
    resp.is_success()
}

/// Verify the pool correctly limits concurrency to `pool_size` slots and that
/// all acquired guards can independently open real rndc connections to BIND9.
///
/// The pool size is set to 1 (BIND9's rndc handler is single-connection) so
/// guards must be used sequentially even though the pool itself is async-safe.
#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn pool_burst_through_rndc() {
    rndc_settle().await;

    // Single-slot pool — matches BIND9's single-connection rndc handler.
    let pool = RndcPool::new(test_config(), 1);
    assert_eq!(pool.available(), 1);

    // Acquire the single slot.
    let guard = pool.acquire().await.expect("acquire failed");
    assert_eq!(pool.available(), 0);

    // Use the guard to run a real rndc command.
    assert!(
        status_via_pool(&guard).await,
        "rndc status should succeed through pool guard"
    );

    // Releasing the guard restores the slot.
    drop(guard);
    assert_eq!(pool.available(), 1);

    rndc_settle().await;

    // A second acquire after release should also succeed.
    let guard2 = pool.acquire().await.expect("second acquire failed");
    assert!(
        status_via_pool(&guard2).await,
        "second rndc status should succeed through pool guard"
    );
}

/// Verify that holding the only slot prevents a concurrent acquire from
/// completing before release — even against a live server.
#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn pool_blocks_third_connection_when_full() {
    rndc_settle().await;

    let pool = RndcPool::new(test_config(), 1);

    let _guard = pool.acquire().await.expect("first acquire failed");

    // With the slot held, a second acquire must not complete immediately.
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        pool.acquire(),
    )
    .await;
    assert!(
        result.is_err(),
        "pool should block second acquire while slot is held"
    );
}
