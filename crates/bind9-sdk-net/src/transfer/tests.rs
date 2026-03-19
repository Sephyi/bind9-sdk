// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Tests for the zone transfer client.

use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_stream::StreamExt;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::transfer::TransferRecord;

use super::TransferClient;

/// A mock TCP stream backed by an in-memory buffer.
///
/// Reads from `read_buf` and discards writes (captures them in `write_buf`).
struct MockTcpStream {
    read_buf: Cursor<Vec<u8>>,
    write_buf: Vec<u8>,
}

impl MockTcpStream {
    fn new(read_data: Vec<u8>) -> Self {
        Self {
            read_buf: Cursor::new(read_data),
            write_buf: Vec::new(),
        }
    }
}

impl AsyncRead for MockTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read_buf).poll_read(cx, buf)
    }
}

impl AsyncWrite for MockTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Build a minimal AXFR response as DNS TCP messages (with 2-byte length prefix).
///
/// Structure: one message containing SOA, A record, closing SOA.
fn build_mock_axfr_response() -> Vec<u8> {
    let mut msg = Vec::new();

    // DNS Header: QR=1, RCODE=0, QDCOUNT=0, ANCOUNT=3
    msg.extend_from_slice(&[0x00, 0x01]); // ID
    msg.extend_from_slice(&[0x84, 0x00]); // Flags: QR=1, AA=1
    msg.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT = 0
    msg.extend_from_slice(&3u16.to_be_bytes()); // ANCOUNT = 3
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    let zone = DomainName::new("example.com.").unwrap();
    let ns1 = DomainName::new("ns1.example.com.").unwrap();
    let admin = DomainName::new("admin.example.com.").unwrap();

    // Record 1: SOA (opening)
    append_soa_record(
        &mut msg, &zone, &ns1, &admin, 2024010101, 3600, 900, 604800, 86400,
    );

    // Record 2: A record for "host.example.com."
    let host = DomainName::new("host.example.com.").unwrap();
    append_a_record(&mut msg, &host, 300, [192, 0, 2, 1]);

    // Record 3: SOA (closing — same serial)
    append_soa_record(
        &mut msg, &zone, &ns1, &admin, 2024010101, 3600, 900, 604800, 86400,
    );

    // Wrap in TCP framing: 2-byte length prefix
    let mut tcp_msg = Vec::new();
    tcp_msg.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    tcp_msg.extend_from_slice(&msg);

    tcp_msg
}

/// Append a SOA resource record in wire format to `buf`.
#[allow(clippy::too_many_arguments)]
fn append_soa_record(
    buf: &mut Vec<u8>,
    name: &DomainName,
    mname: &DomainName,
    rname: &DomainName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) {
    name.write_wire(buf);
    buf.extend_from_slice(&6u16.to_be_bytes()); // TYPE = SOA
    buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    buf.extend_from_slice(&3600u32.to_be_bytes()); // TTL

    // RDATA
    let mut rdata = Vec::new();
    mname.write_wire(&mut rdata);
    rname.write_wire(&mut rdata);
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&refresh.to_be_bytes());
    rdata.extend_from_slice(&retry.to_be_bytes());
    rdata.extend_from_slice(&expire.to_be_bytes());
    rdata.extend_from_slice(&minimum.to_be_bytes());

    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rdata);
}

/// Append an A resource record in wire format to `buf`.
fn append_a_record(buf: &mut Vec<u8>, name: &DomainName, ttl: u32, addr: [u8; 4]) {
    name.write_wire(buf);
    buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    buf.extend_from_slice(&ttl.to_be_bytes()); // TTL
    buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    buf.extend_from_slice(&addr);
}

#[tokio::test]
async fn transfer_client_mock_axfr() {
    let response_data = build_mock_axfr_response();
    let mock = MockTcpStream::new(response_data);
    let client = TransferClient::new(mock);
    let zone = DomainName::new("example.com.").unwrap();

    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);

    // First record: opening SOA
    let first = stream.next().await.unwrap().unwrap();
    assert!(
        matches!(&first, TransferRecord::BeginSoa(rr) if matches!(&rr.rdata, RecordData::Soa { serial, .. } if serial.value() == 2024010101)),
        "expected BeginSoa, got {first:?}"
    );

    // Second record: A record
    let second = stream.next().await.unwrap().unwrap();
    assert!(
        matches!(&second, TransferRecord::Record(rr) if matches!(&rr.rdata, RecordData::A(_))),
        "expected Record(A), got {second:?}"
    );

    // Third record: closing SOA
    let third = stream.next().await.unwrap().unwrap();
    assert!(
        matches!(&third, TransferRecord::EndSoa(_)),
        "expected EndSoa, got {third:?}"
    );

    // Stream should be exhausted
    let end = stream.next().await;
    assert!(end.is_none(), "stream should end after closing SOA");
}

#[tokio::test]
async fn transfer_client_mock_axfr_multi_message() {
    // Build two TCP messages: first has SOA + A record, second has closing SOA
    let zone = DomainName::new("example.com.").unwrap();
    let ns1 = DomainName::new("ns1.example.com.").unwrap();
    let admin = DomainName::new("admin.example.com.").unwrap();
    let host = DomainName::new("host.example.com.").unwrap();

    // Message 1: SOA + A
    let mut msg1 = Vec::new();
    msg1.extend_from_slice(&[0x00, 0x01, 0x84, 0x00]); // Header flags
    msg1.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    msg1.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT = 2
    msg1.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg1.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    append_soa_record(
        &mut msg1, &zone, &ns1, &admin, 2024010101, 3600, 900, 604800, 86400,
    );
    append_a_record(&mut msg1, &host, 300, [192, 0, 2, 1]);

    // Message 2: closing SOA
    let mut msg2 = Vec::new();
    msg2.extend_from_slice(&[0x00, 0x01, 0x84, 0x00]);
    msg2.extend_from_slice(&0u16.to_be_bytes());
    msg2.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    msg2.extend_from_slice(&0u16.to_be_bytes());
    msg2.extend_from_slice(&0u16.to_be_bytes());
    append_soa_record(
        &mut msg2, &zone, &ns1, &admin, 2024010101, 3600, 900, 604800, 86400,
    );

    // Combine with TCP framing
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(msg1.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&msg1);
    tcp_data.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&msg2);

    let mock = MockTcpStream::new(tcp_data);
    let client = TransferClient::new(mock);

    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);

    let first = stream.next().await.unwrap().unwrap();
    assert!(matches!(first, TransferRecord::BeginSoa(_)));

    let second = stream.next().await.unwrap().unwrap();
    assert!(matches!(second, TransferRecord::Record(_)));

    let third = stream.next().await.unwrap().unwrap();
    assert!(matches!(third, TransferRecord::EndSoa(_)));

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn transfer_client_error_on_rcode() {
    // Build a response with RCODE=5 (REFUSED)
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x00, 0x01]); // ID
    msg.extend_from_slice(&[0x84, 0x05]); // Flags: QR=1, AA=1, RCODE=5
    msg.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&msg);

    let mock = MockTcpStream::new(tcp_data);
    let client = TransferClient::new(mock);
    let zone = DomainName::new("example.com.").unwrap();

    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);
    let result = stream.next().await.unwrap();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("RCODE 5"));
}

#[tokio::test]
async fn transfer_rejects_non_localhost_without_tls() {
    let addr: std::net::SocketAddr = "10.0.0.1:53".parse().unwrap();
    let result = super::TransferClient::connect(addr, None).await;
    assert!(matches!(result, Err(crate::NetError::TlsRequired { .. })));
}

#[tokio::test]
async fn transfer_allows_localhost_without_tls() {
    // This will fail to connect (no server), but should NOT get TlsRequired error
    let addr: std::net::SocketAddr = "127.0.0.1:59999".parse().unwrap();
    let result = super::TransferClient::connect(addr, None).await;
    // Should be a connection error, not TlsRequired
    match result {
        Err(crate::NetError::TlsRequired { .. }) => panic!("localhost should not require TLS"),
        Err(_) => {} // Connection refused is expected
        Ok(_) => panic!("should not connect to non-existent server"),
    }
}

#[test]
fn mock_tcp_stream_implements_required_traits() {
    fn assert_async_read_write<T: AsyncRead + AsyncWrite + Unpin>() {}
    assert_async_read_write::<MockTcpStream>();
}
