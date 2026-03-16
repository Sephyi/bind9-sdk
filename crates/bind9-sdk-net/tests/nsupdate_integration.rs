// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for RFC 2136 nsupdate against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:15353 (DNS) with rndc on localhost:9953
//! - The `example.com` zone configured with `allow-update { key "rndc-test-key"; };`
//!
//! Run with:
//!   cargo test -p bind9-sdk-net --test nsupdate_integration -- --ignored --test-threads=1
//!
//! Tests must run serially (`--test-threads=1`) because they mutate the same zone.
//! See `tests/README.md` for BIND9 setup instructions.

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::protocol::RecordType;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::record::{RecordClass, ResourceRecord, Ttl};
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_core::update::UpdateBuilder;
use bind9_sdk_net::error::NetError;
use bind9_sdk_net::nsupdate::NsUpdateSender;

/// DNS port for the test BIND9 container (mapped from container port 53).
const DNS_PORT: u16 = 15353;

/// Brief delay between tests — BIND9 needs time to process the previous update.
async fn update_settle() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

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

/// Construct the DNS server address.
fn dns_addr() -> SocketAddr {
    format!("127.0.0.1:{DNS_PORT}").parse().unwrap()
}

/// Helper: send a pre-built `UpdateMessage` to BIND9 and return the result.
///
/// The `tsig_key` is passed through to `NsUpdateSender::send()` for TSIG
/// response verification (RFC 8945 §4.5).
async fn send_update(
    msg: &bind9_sdk_core::update::UpdateMessage,
    tsig_key: Option<&TsigKey>,
) -> Result<bind9_sdk_core::update::UpdateResult, NetError> {
    let sender = NsUpdateSender::with_timeout(dns_addr(), Duration::from_secs(5));
    sender.send(msg, tsig_key).await
}

// ---------------------------------------------------------------------------
// Each test is fully self-contained: it creates its own preconditions and
// cleans up after itself. No test depends on another test having run first.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn add_a_record_noerror() {
    update_settle().await;

    let zone = DomainName::new("example.com.").unwrap();
    let key = test_key();
    let name = DomainName::new("add-test.example.com.").unwrap();

    // Add add-test.example.com. 60 IN A 192.0.2.1
    let record = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::A("192.0.2.1".parse().unwrap()),
    };

    let msg = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
        .add_record(record)
        .sign_now(&key)
        .build();

    let result = send_update(&msg, Some(&key)).await.expect("update send failed");

    assert_eq!(
        result.rcode,
        bind9_sdk_core::protocol::Rcode::NoError,
        "expected NOERROR, got {:?}",
        result.rcode
    );

    // Cleanup: delete the record we just added.
    let cleanup = UpdateBuilder::with_id(99, zone, RecordClass::IN)
        .delete_rrset(&name, RecordType::A)
        .sign_now(&key)
        .build();
    let _ = send_update(&cleanup, Some(&key)).await;
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn delete_a_record_noerror() {
    update_settle().await;

    let zone = DomainName::new("example.com.").unwrap();
    let key = test_key();
    let name = DomainName::new("del-test.example.com.").unwrap();

    // Setup: add a record so we have something to delete.
    let record = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::A("192.0.2.99".parse().unwrap()),
    };

    let setup = UpdateBuilder::with_id(10, zone.clone(), RecordClass::IN)
        .add_record(record)
        .sign_now(&key)
        .build();
    send_update(&setup, Some(&key)).await.expect("setup add failed");
    update_settle().await;

    // Now delete it.
    let msg = UpdateBuilder::with_id(11, zone, RecordClass::IN)
        .delete_rrset(&name, RecordType::A)
        .sign_now(&key)
        .build();

    let result = send_update(&msg, Some(&key)).await.expect("update send failed");

    assert_eq!(
        result.rcode,
        bind9_sdk_core::protocol::Rcode::NoError,
        "expected NOERROR after delete, got {:?}",
        result.rcode
    );
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn wrong_key_returns_tsig_rejected() {
    update_settle().await;

    let zone = DomainName::new("example.com.").unwrap();

    // Use a key with wrong material — same name, different bytes.
    let wrong_key = TsigKey::new(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0xDE; 32],
    )
    .unwrap();

    let record = ResourceRecord {
        name: DomainName::new("wrongkey.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::A("192.0.2.9".parse().unwrap()),
    };

    let msg = UpdateBuilder::with_id(3, zone, RecordClass::IN)
        .add_record(record)
        .sign_now(&wrong_key)
        .build();

    let err = send_update(&msg, Some(&wrong_key))
        .await
        .expect_err("expected error with wrong key");

    assert!(
        matches!(err, NetError::TsigRejected { .. }),
        "expected TsigRejected, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn unsatisfied_prerequisite_returns_nxdomain() {
    update_settle().await;

    let zone = DomainName::new("example.com.").unwrap();
    let key = test_key();

    // Require that nonexistent.example.com. has at least one record.
    // This prerequisite will fail because the name does not exist in the zone.
    // NsUpdateSender returns Ok(UpdateResult) — rcode classification into
    // NetError::PrerequisiteFailed happens at the Bind9Client layer, not here.
    let msg = UpdateBuilder::with_id(4, zone, RecordClass::IN)
        .require_name_exists(&DomainName::new("nonexistent.example.com.").unwrap())
        .sign_now(&key)
        .build();

    let result = send_update(&msg, Some(&key))
        .await
        .expect("update send succeeded (rcode carries the error)");

    assert_eq!(
        result.rcode,
        bind9_sdk_core::protocol::Rcode::NxDomain,
        "expected NXDOMAIN for unsatisfied prerequisite, got {:?}",
        result.rcode
    );
}
