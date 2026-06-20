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
use bind9_sdk_core::record::{RecordClass, ResourceRecord, Serial, Ttl};
use bind9_sdk_core::transfer::{IxfrEvent, TransferRecord};
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey, TsigRecord};

use super::{IxfrState, TransferClient, XfrTsigVerifier};

/// A mock TCP stream backed by an in-memory buffer.
///
/// Reads from `read_buf` and discards writes (captures them in `write_buf`).
struct MockTcpStream {
    read_buf: Cursor<Vec<u8>>,
    write_buf: Vec<u8>,
    response_ids_patched: bool,
}

impl MockTcpStream {
    fn new(read_data: Vec<u8>) -> Self {
        Self {
            read_buf: Cursor::new(read_data),
            write_buf: Vec::new(),
            response_ids_patched: false,
        }
    }

    fn patch_response_ids(&mut self) {
        if self.response_ids_patched || self.write_buf.len() < 4 {
            return;
        }
        let query_id = [self.write_buf[2], self.write_buf[3]];
        let data = self.read_buf.get_mut();
        let mut offset = 0;
        while offset + 4 <= data.len() {
            let message_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            if offset + 2 + message_len > data.len() {
                break;
            }
            data[offset + 2..offset + 4].copy_from_slice(&query_id);
            offset += 2 + message_len;
        }
        self.response_ids_patched = true;
    }
}

impl AsyncRead for MockTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.patch_response_ids();
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
    build_mock_axfr_response_with_serials(2024010101, 2024010101)
}

fn build_mock_axfr_response_with_serials(opening_serial: u32, closing_serial: u32) -> Vec<u8> {
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
        &mut msg,
        &zone,
        &ns1,
        &admin,
        opening_serial,
        3600,
        900,
        604800,
        86400,
    );

    // Record 2: A record for "host.example.com."
    let host = DomainName::new("host.example.com.").unwrap();
    append_a_record(&mut msg, &host, 300, [192, 0, 2, 1]);

    // Record 3: SOA (closing — same serial)
    append_soa_record(
        &mut msg,
        &zone,
        &ns1,
        &admin,
        closing_serial,
        3600,
        900,
        604800,
        86400,
    );

    // Wrap in TCP framing: 2-byte length prefix
    let mut tcp_msg = Vec::new();
    tcp_msg.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    tcp_msg.extend_from_slice(&msg);

    tcp_msg
}

fn build_mock_ixfr_response() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x00, 0x01]);
    msg.extend_from_slice(&[0x84, 0x00]);
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&6u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());

    let zone = DomainName::new("example.com.").unwrap();
    let ns1 = DomainName::new("ns1.example.com.").unwrap();
    let admin = DomainName::new("admin.example.com.").unwrap();
    let host = DomainName::new("host.example.com.").unwrap();
    append_soa_record(&mut msg, &zone, &ns1, &admin, 3, 3600, 900, 604800, 86400);
    append_soa_record(&mut msg, &zone, &ns1, &admin, 1, 3600, 900, 604800, 86400);
    append_a_record(&mut msg, &host, 300, [192, 0, 2, 1]);
    append_soa_record(&mut msg, &zone, &ns1, &admin, 3, 3600, 900, 604800, 86400);
    append_a_record(&mut msg, &host, 300, [192, 0, 2, 2]);
    append_soa_record(&mut msg, &zone, &ns1, &admin, 3, 3600, 900, 604800, 86400);

    let mut tcp_msg = Vec::new();
    tcp_msg.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    tcp_msg.extend_from_slice(&msg);
    tcp_msg
}

fn append_trailing_answer(mut tcp_message: Vec<u8>) -> Vec<u8> {
    let answer_count = u16::from_be_bytes([tcp_message[8], tcp_message[9]]);
    tcp_message[8..10].copy_from_slice(&(answer_count + 1).to_be_bytes());
    append_a_record(
        &mut tcp_message,
        &DomainName::new("trailing.example.com.").unwrap(),
        300,
        [192, 0, 2, 200],
    );
    let dns_length = u16::try_from(tcp_message.len() - 2).unwrap();
    tcp_message[..2].copy_from_slice(&dns_length.to_be_bytes());
    tcp_message
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
async fn transfer_client_rejects_mismatched_closing_soa() {
    let response_data = build_mock_axfr_response_with_serials(2024010101, 2024010102);
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();
    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);

    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        TransferRecord::BeginSoa(_)
    ));
    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        TransferRecord::Record(_)
    ));
    let error = stream.next().await.unwrap().unwrap_err();

    assert!(
        error.to_string().contains("closing SOA")
            && error.to_string().contains("2024010101")
            && error.to_string().contains("2024010102")
    );
}

#[tokio::test]
async fn transfer_client_rejects_answers_after_closing_soa() {
    let response_data = append_trailing_answer(build_mock_axfr_response());
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();
    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);

    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        TransferRecord::BeginSoa(_)
    ));
    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        TransferRecord::Record(_)
    ));
    let error = stream.next().await.unwrap().unwrap_err();

    assert!(error.to_string().contains("after closing SOA"));
}

#[tokio::test]
async fn transfer_client_mock_ixfr_emits_typed_delta_events() {
    let client = TransferClient::new(MockTcpStream::new(build_mock_ixfr_response()));
    let zone = DomainName::new("example.com.").unwrap();
    let stream = client.ixfr(zone, Serial::new(1), None).await.unwrap();
    tokio::pin!(stream);
    let mut events = Vec::new();

    while let Some(event) = stream.next().await {
        events.push(event.unwrap());
    }

    assert!(matches!(events[0], IxfrEvent::CurrentSoa(_)));
    assert!(matches!(events[1], IxfrEvent::DeleteSoa(_)));
    assert!(matches!(events[2], IxfrEvent::Deleted(_)));
    assert!(matches!(events[3], IxfrEvent::AddSoa(_)));
    assert!(matches!(events[4], IxfrEvent::Added(_)));
    assert!(matches!(events[5], IxfrEvent::EndSoa(_)));
}

#[tokio::test]
async fn transfer_client_rejects_answers_after_ixfr_completion() {
    let response_data = append_trailing_answer(build_mock_ixfr_response());
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();
    let stream = client.ixfr(zone, Serial::new(1), None).await.unwrap();
    tokio::pin!(stream);

    let mut terminal_error = None;
    while let Some(event) = stream.next().await {
        if let Err(error) = event {
            terminal_error = Some(error);
            break;
        }
    }

    let error = terminal_error.expect("trailing IXFR answer must be rejected");
    assert!(error.to_string().contains("after IXFR completion"));
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
async fn signed_transfer_client_rejects_unsigned_response() {
    let response_data = build_mock_axfr_response();
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();

    let stream = client.axfr(zone, Some(&key)).await.unwrap();
    tokio::pin!(stream);
    let error = stream.next().await.unwrap().unwrap_err();

    assert!(
        error.to_string().contains("first response") && error.to_string().contains("TSIG"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn transfer_client_rejects_non_authoritative_response() {
    let mut response_data = build_mock_axfr_response();
    response_data[4] &= !0x04;
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();

    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);
    let error = stream.next().await.unwrap().unwrap_err();

    assert!(error.to_string().contains("authoritative"));
}

#[tokio::test]
async fn transfer_client_rejects_truncated_response() {
    let mut response_data = build_mock_axfr_response();
    response_data[4] |= 0x02;
    let client = TransferClient::new(MockTcpStream::new(response_data));
    let zone = DomainName::new("example.com.").unwrap();

    let stream = client.axfr(zone, None).await.unwrap();
    tokio::pin!(stream);
    let error = stream.next().await.unwrap().unwrap_err();

    assert!(error.to_string().contains("truncated"));
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

#[tokio::test]
async fn transfer_tls_rejects_invalid_server_name_before_connecting() {
    let addr: std::net::SocketAddr = "192.0.2.1:853".parse().unwrap();
    let tls = crate::TlsConfig::new().unwrap();

    let result = super::TransferClient::connect_tls(addr, "", &tls).await;

    assert!(matches!(result, Err(crate::NetError::Tls(_))));
}

#[tokio::test]
async fn transfer_tls_performs_verified_axfr_over_tls() {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let client_tls = crate::TlsConfig::with_root_certificates([cert.der().clone()]).unwrap();
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config))
            .accept(tcp)
            .await
            .unwrap();
        let query_len = tls.read_u16().await.unwrap() as usize;
        let mut query = vec![0u8; query_len];
        tls.read_exact(&mut query).await.unwrap();

        let mut response = build_mock_axfr_response()[2..].to_vec();
        response[0..2].copy_from_slice(&query[0..2]);
        tls.write_u16(response.len() as u16).await.unwrap();
        tls.write_all(&response).await.unwrap();
        tls.shutdown().await.unwrap();
    });

    let client = super::TransferClient::connect_tls(addr, "localhost", &client_tls)
        .await
        .unwrap();
    let stream = client
        .axfr(DomainName::new("example.com.").unwrap(), None)
        .await
        .unwrap();
    tokio::pin!(stream);
    let mut count = 0;
    while let Some(record) = stream.next().await {
        record.unwrap();
        count += 1;
    }

    assert_eq!(count, 3);
    server.await.unwrap();
}

#[test]
fn mock_tcp_stream_implements_required_traits() {
    fn assert_async_read_write<T: AsyncRead + AsyncWrite + Unpin>() {}
    assert_async_read_write::<MockTcpStream>();
}

#[test]
fn signed_transfer_rejects_unsigned_first_response() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let response = build_mock_axfr_response();
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(vec![0x11; 32]));

    let error = verifier.verify_message(&response[2..]).unwrap_err();

    assert!(
        error.to_string().contains("first response") && error.to_string().contains("TSIG"),
        "unexpected error: {error}"
    );
}

fn sign_first_transfer_response(
    mut unsigned: Vec<u8>,
    key: &TsigKey,
    request_mac: &[u8],
) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tsig = TsigRecord::new(key, &unsigned, now, Some(request_mac)).unwrap();
    unsigned[10..12].copy_from_slice(&1u16.to_be_bytes());
    unsigned.extend_from_slice(&tsig.wire_bytes);
    unsigned
}

#[test]
fn signed_transfer_accepts_valid_first_response() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let request_mac = vec![0x11; 32];
    let unsigned = build_mock_axfr_response()[2..].to_vec();
    let signed = sign_first_transfer_response(unsigned.clone(), &key, &request_mac);
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(request_mac));

    let authenticated = verifier.verify_message(&signed).unwrap();

    assert_eq!(authenticated, unsigned);
}

#[test]
fn signed_transfer_rejects_tampered_first_response() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let request_mac = vec![0x11; 32];
    let unsigned = build_mock_axfr_response()[2..].to_vec();
    let mut signed = sign_first_transfer_response(unsigned, &key, &request_mac);
    let address_offset = signed
        .windows(4)
        .position(|bytes| bytes == [192, 0, 2, 1])
        .unwrap();
    signed[address_offset + 3] ^= 0x01;
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(request_mac));

    let error = verifier.verify_message(&signed).unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

fn empty_authoritative_response(id: u16) -> Vec<u8> {
    let mut message = Vec::with_capacity(12);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x84, 0x00]);
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message
}

fn sign_continuation_response(
    mut current: Vec<u8>,
    prior_mac: &[u8],
    covered_messages: &[&[u8]],
    key: &TsigKey,
) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fudge = 300u16;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior_mac);
    for message in covered_messages {
        mac_input.extend_from_slice(message);
    }
    mac_input.extend_from_slice(&now.to_be_bytes()[2..]);
    mac_input.extend_from_slice(&fudge.to_be_bytes());
    let mac = key.sign(&mac_input).unwrap();

    let mut tsig = Vec::new();
    key.name().write_wire_canonical(&mut tsig);
    tsig.extend_from_slice(&250u16.to_be_bytes());
    tsig.extend_from_slice(&255u16.to_be_bytes());
    tsig.extend_from_slice(&0u32.to_be_bytes());
    let rdlength_offset = tsig.len();
    tsig.extend_from_slice(&0u16.to_be_bytes());
    let rdata_start = tsig.len();
    DomainName::new(key.algorithm().dns_name())
        .unwrap()
        .write_wire_canonical(&mut tsig);
    tsig.extend_from_slice(&now.to_be_bytes()[2..]);
    tsig.extend_from_slice(&fudge.to_be_bytes());
    tsig.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    tsig.extend_from_slice(&mac);
    tsig.extend_from_slice(&u16::from_be_bytes([current[0], current[1]]).to_be_bytes());
    tsig.extend_from_slice(&0u16.to_be_bytes());
    tsig.extend_from_slice(&0u16.to_be_bytes());
    let rdlength = (tsig.len() - rdata_start) as u16;
    tsig[rdlength_offset..rdlength_offset + 2].copy_from_slice(&rdlength.to_be_bytes());

    current[10..12].copy_from_slice(&1u16.to_be_bytes());
    current.extend_from_slice(&tsig);
    current
}

#[test]
fn signed_transfer_accepts_chained_signature_after_unsigned_intermediary() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let request_mac = vec![0x11; 32];
    let first_unsigned = empty_authoritative_response(1);
    let first_signed = sign_first_transfer_response(first_unsigned, &key, &request_mac);
    let first_tsig_offset = first_signed
        .windows(2)
        .rposition(|bytes| bytes == 250u16.to_be_bytes())
        .unwrap();
    let first_tsig_name_offset = first_tsig_offset - key.name().wire_len();
    let first_tsig = TsigRecord::parse_from_wire(&first_signed[first_tsig_name_offset..]).unwrap();
    let intermediary = empty_authoritative_response(1);
    let final_unsigned = empty_authoritative_response(1);
    let final_signed = sign_continuation_response(
        final_unsigned.clone(),
        &first_tsig.mac,
        &[&intermediary, &final_unsigned],
        &key,
    );
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(request_mac));

    verifier.verify_message(&first_signed).unwrap();
    verifier.verify_message(&intermediary).unwrap();
    assert_eq!(
        verifier.verify_message(&final_signed).unwrap(),
        final_unsigned
    );
    verifier.finish().unwrap();
}

#[test]
fn signed_transfer_rejects_more_than_99_unsigned_intermediaries() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let request_mac = vec![0x11; 32];
    let first = sign_first_transfer_response(empty_authoritative_response(1), &key, &request_mac);
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(request_mac));
    verifier.verify_message(&first).unwrap();

    for _ in 0..99 {
        verifier
            .verify_message(&empty_authoritative_response(1))
            .unwrap();
    }
    let error = verifier
        .verify_message(&empty_authoritative_response(1))
        .unwrap_err();

    assert!(error.to_string().contains("99"));
}

#[test]
fn signed_transfer_requires_final_message_signature() {
    let key = TsigKey::new(
        DomainName::new("transfer-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0x5A; 32],
    )
    .unwrap();
    let request_mac = vec![0x11; 32];
    let first = sign_first_transfer_response(empty_authoritative_response(1), &key, &request_mac);
    let mut verifier = XfrTsigVerifier::new(1, Some(&key), Some(request_mac));
    verifier.verify_message(&first).unwrap();
    verifier
        .verify_message(&empty_authoritative_response(1))
        .unwrap();

    let error = verifier.finish().unwrap_err();

    assert!(error.to_string().contains("final") && error.to_string().contains("TSIG"));
}

fn soa_resource_record(serial: u32) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::new("example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(3600).unwrap(),
        rdata: RecordData::Soa {
            mname: DomainName::new("ns1.example.com.").unwrap(),
            rname: DomainName::new("admin.example.com.").unwrap(),
            serial: Serial::new(serial),
            refresh: Ttl::new(3600).unwrap(),
            retry: Ttl::new(900).unwrap(),
            expire: Ttl::new(604800).unwrap(),
            minimum: Ttl::new(86400).unwrap(),
        },
    }
}

fn a_resource_record(last_octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::new("host.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, last_octet)),
    }
}

#[test]
fn ixfr_state_emits_ordered_delete_and_add_events() {
    let mut state = IxfrState::new(DomainName::new("example.com.").unwrap(), Serial::new(1));
    let records = [
        soa_resource_record(3),
        soa_resource_record(1),
        a_resource_record(1),
        soa_resource_record(2),
        a_resource_record(2),
        soa_resource_record(2),
        a_resource_record(3),
        soa_resource_record(3),
        a_resource_record(4),
        soa_resource_record(3),
    ];
    let mut events = Vec::new();

    for record in records {
        events.extend(state.push(record).unwrap());
    }

    assert!(matches!(events[0], IxfrEvent::CurrentSoa(_)));
    assert!(matches!(events[1], IxfrEvent::DeleteSoa(_)));
    assert!(matches!(events[2], IxfrEvent::Deleted(_)));
    assert!(matches!(events[3], IxfrEvent::AddSoa(_)));
    assert!(matches!(events[4], IxfrEvent::Added(_)));
    assert!(matches!(events[5], IxfrEvent::DeleteSoa(_)));
    assert!(matches!(events[6], IxfrEvent::Deleted(_)));
    assert!(matches!(events[7], IxfrEvent::AddSoa(_)));
    assert!(matches!(events[8], IxfrEvent::Added(_)));
    assert!(matches!(events[9], IxfrEvent::EndSoa(_)));
    assert!(state.is_complete());
}

#[test]
fn ixfr_state_reports_axfr_fallback() {
    let mut state = IxfrState::new(DomainName::new("example.com.").unwrap(), Serial::new(1));
    let records = [
        soa_resource_record(3),
        a_resource_record(1),
        soa_resource_record(3),
    ];
    let mut events = Vec::new();

    for record in records {
        events.extend(state.push(record).unwrap());
    }

    assert!(matches!(
        events.as_slice(),
        [
            IxfrEvent::AxfrFallback(TransferRecord::BeginSoa(_)),
            IxfrEvent::AxfrFallback(TransferRecord::Record(_)),
            IxfrEvent::AxfrFallback(TransferRecord::EndSoa(_))
        ]
    ));
    assert!(state.is_complete());
}

#[test]
fn ixfr_state_reports_no_change_after_single_soa() {
    let mut state = IxfrState::new(DomainName::new("example.com.").unwrap(), Serial::new(3));
    assert!(state.push(soa_resource_record(3)).unwrap().is_empty());

    let events = state.finish().unwrap();

    assert!(matches!(events.as_slice(), [IxfrEvent::NoChange(_)]));
}

#[test]
fn ixfr_state_rejects_unexpected_base_serial() {
    let mut state = IxfrState::new(DomainName::new("example.com.").unwrap(), Serial::new(1));
    state.push(soa_resource_record(3)).unwrap();

    let error = state.push(soa_resource_record(2)).unwrap_err();

    assert!(error.to_string().contains("expected 1") && error.to_string().contains("got 2"));
}

#[test]
fn ixfr_state_rejects_undefined_rfc1982_serial_ordering() {
    let mut state = IxfrState::new(DomainName::new("example.com.").unwrap(), Serial::new(1));
    state
        .push(soa_resource_record(1u32.wrapping_add(1 << 31)))
        .unwrap();

    let error = state.push(soa_resource_record(1)).unwrap_err();

    assert!(error.to_string().contains("undefined") && error.to_string().contains("RFC 1982"));
}
