// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for `RndcLimiter` against a live BIND9 instance.
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
use bind9_sdk_net::rndc::RndcConnection;
use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::{ClientConfig, RndcLimiter, RndcPermit, RndcPool};

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
    config.rndc_max_concurrent = Some(4);
    config
}

/// Brief delay to let BIND9's control channel release the previous connection.
async fn rndc_settle() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Send a single rndc `Status` command through a guard from the pool.
async fn status_via_limiter(guard: &RndcPermit) -> bool {
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

/// Verify the limiter bounds concurrent command cycles and that all acquired
/// permits can independently open real rndc connections to BIND9.
///
/// The pool size is set to 1 (BIND9's rndc handler is single-connection) so
/// guards must be used sequentially even though the pool itself is async-safe.
#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn limiter_burst_through_rndc() {
    rndc_settle().await;

    // Single-slot pool — matches BIND9's single-connection rndc handler.
    let limiter = RndcLimiter::new(test_config(), 1);
    assert_eq!(limiter.available(), 1);

    // Acquire the single slot.
    let guard = limiter.acquire().await.expect("acquire failed");
    assert_eq!(limiter.available(), 0);

    // Use the guard to run a real rndc command.
    assert!(
        status_via_limiter(&guard).await,
        "rndc status should succeed through limiter permit"
    );

    // Releasing the guard restores the slot.
    drop(guard);
    assert_eq!(limiter.available(), 1);

    rndc_settle().await;

    // A second acquire after release should also succeed.
    let guard2 = limiter.acquire().await.expect("second acquire failed");
    assert!(
        status_via_limiter(&guard2).await,
        "second rndc status should succeed through limiter permit"
    );
}

/// Verify that holding the only slot prevents a concurrent acquire from
/// completing before release — even against a live server.
#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn limiter_blocks_second_cycle_when_full() {
    rndc_settle().await;

    let limiter = RndcLimiter::new(test_config(), 1);

    let _guard = limiter.acquire().await.expect("first acquire failed");

    // With the slot held, a second acquire must not complete immediately.
    let result = tokio::time::timeout(Duration::from_millis(100), limiter.acquire()).await;
    assert!(
        result.is_err(),
        "limiter should block second acquire while slot is held"
    );
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn pool_reuses_one_authenticated_connection() {
    rndc_settle().await;

    let pool =
        RndcPool::new(test_config(), 1, Duration::from_secs(30)).expect("pool creation failed");
    assert_eq!(pool.total_connections_created(), 0);

    let first = pool
        .execute(RndcCommand::Status)
        .await
        .expect("first pooled status failed");
    let second = pool
        .execute(RndcCommand::Status)
        .await
        .expect("second pooled status failed");

    assert!(first.is_success());
    assert!(second.is_success());
    assert_eq!(pool.total_connections_created(), 1);
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:9953"]
async fn pool_reconnects_after_idle_expiry() {
    rndc_settle().await;

    let pool =
        RndcPool::new(test_config(), 1, Duration::from_millis(100)).expect("pool creation failed");
    pool.execute(RndcCommand::Status)
        .await
        .expect("initial pooled status failed");
    assert_eq!(pool.total_connections_created(), 1);

    tokio::time::sleep(Duration::from_millis(250)).await;
    pool.execute(RndcCommand::Status)
        .await
        .expect("status after idle expiry failed");
    assert_eq!(pool.total_connections_created(), 2);
}
