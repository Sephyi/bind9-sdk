// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Integration tests for AXFR/IXFR zone transfers against a live BIND9 instance.
//!
//! These tests require a BIND9 server running on `localhost:15353` with the
//! `transfer.example.com` zone configured and the `rndc-test-key` TSIG key.
//!
//! Run with: `cargo test -p bind9-sdk-net --test transfer_integration -- --ignored`

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::transfer::TransferRecord;
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_net::TransferClient;
use tokio_stream::StreamExt;

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn axfr_transfer_example_com() {
    let key = TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .expect("test key must be valid");

    let tcp_stream = tokio::net::TcpStream::connect("127.0.0.1:15353")
        .await
        .expect("failed to connect to BIND9 on localhost:15353");

    let zone = DomainName::new("transfer.example.com.").unwrap();
    let client = TransferClient::new(tcp_stream);
    let stream = client
        .axfr(zone, Some(&key))
        .await
        .expect("AXFR query should succeed");
    tokio::pin!(stream);

    let mut has_soa = false;
    let mut has_ns = false;
    let mut has_a = false;
    let mut record_count = 0;

    while let Some(result) = stream.next().await {
        let record = result.expect("transfer record should be valid");
        record_count += 1;

        match &record {
            TransferRecord::BeginSoa(rr) | TransferRecord::EndSoa(rr) => {
                assert!(
                    matches!(&rr.rdata, RecordData::Soa { .. }),
                    "SOA record should have SOA data"
                );
                has_soa = true;
            }
            TransferRecord::Record(rr) => {
                if matches!(&rr.rdata, RecordData::Ns(_)) {
                    has_ns = true;
                }
                if matches!(&rr.rdata, RecordData::A(_)) {
                    has_a = true;
                }
            }
            _ => {}
        }
    }

    assert!(has_soa, "transfer should contain SOA records");
    assert!(has_ns, "transfer should contain NS records");
    assert!(has_a, "transfer should contain A records");
    // At minimum: 2 SOA + 1 NS + 1 A = 4 records
    assert!(
        record_count >= 4,
        "expected at least 4 records, got {record_count}"
    );
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:15353"]
async fn axfr_transfer_unsigned() {
    let tcp_stream = tokio::net::TcpStream::connect("127.0.0.1:15353")
        .await
        .expect("failed to connect to BIND9 on localhost:15353");

    let zone = DomainName::new("transfer.example.com.").unwrap();
    let client = TransferClient::new(tcp_stream);
    let stream = client
        .axfr(zone, None)
        .await
        .expect("AXFR query should succeed");
    tokio::pin!(stream);

    // Even without TSIG, we should get records (if the zone allows unsigned transfers)
    let first = stream.next().await;
    assert!(first.is_some(), "should receive at least one record");
}
