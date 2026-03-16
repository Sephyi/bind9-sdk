// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! RFC 2136 dynamic update sender (UDP with TCP fallback).
//!
//! Sends `UpdateMessage` bytes to a DNS server. If the UDP response has the
//! TC (truncated) bit set, automatically retries over TCP with the standard
//! 2-byte length prefix.

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::protocol::Rcode;
use bind9_sdk_core::tsig::{TsigKey, TsigRecord};
use bind9_sdk_core::update::{UpdateMessage, UpdateResult};

use crate::error::NetError;

/// Minimum DNS message header size in bytes.
const DNS_HEADER_SIZE: usize = 12;

/// Bit mask for the TC (truncated) flag in the DNS header flags (byte 2, bit 1).
const TC_FLAG_MASK: u8 = 0x02;

/// Default timeout for nsupdate operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse a DNS response header to extract the message ID and RCODE.
///
/// The response must be at least 12 bytes (DNS header size).
fn parse_dns_response(response: &[u8]) -> Result<UpdateResult, NetError> {
    if response.len() < DNS_HEADER_SIZE {
        return Err(NetError::Protocol(format!(
            "DNS response too short: {} bytes, need at least {DNS_HEADER_SIZE}",
            response.len()
        )));
    }

    let id = u16::from_be_bytes([response[0], response[1]]);
    // RCODE is the low 4 bits of byte 3
    let rcode_value = u16::from(response[3] & 0x0F);
    let rcode = Rcode::from_value(rcode_value);

    Ok(UpdateResult { rcode, id })
}

/// Check whether a DNS response has the TC (truncated) bit set.
///
/// Returns false if the response is too short to contain the flags.
fn is_truncated(response: &[u8]) -> bool {
    if response.len() < DNS_HEADER_SIZE {
        return false;
    }
    // TC bit is bit 1 of the third byte (byte index 2)
    response[2] & TC_FLAG_MASK != 0
}

/// TSIG record type value (RFC 8945).
const TSIG_TYPE: u16 = 250;

/// Skip an uncompressed or compressed DNS name in wire format.
///
/// Advances `pos` past the name. Returns `Err` if the wire is truncated.
fn skip_wire_name(wire: &[u8], pos: &mut usize) -> Result<(), NetError> {
    loop {
        if *pos >= wire.len() {
            return Err(NetError::Protocol("truncated DNS name in response".into()));
        }
        let len = wire[*pos] as usize;
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        // Compression pointer: top 2 bits set
        if len & 0xC0 == 0xC0 {
            *pos += 2;
            return Ok(());
        }
        *pos += 1 + len;
    }
}

/// Find the start offset of a TSIG record in a DNS response.
///
/// Scans through the question, answer, authority, and additional sections
/// to find the last additional record. If it has TYPE=250 (TSIG), returns
/// the offset where the TSIG record starts and the message bytes before it.
///
/// Returns `None` if no TSIG is found.
fn find_tsig_in_response(wire: &[u8]) -> Result<Option<usize>, NetError> {
    if wire.len() < DNS_HEADER_SIZE {
        return Ok(None);
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;


    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    if arcount == 0 {
        return Ok(None);
    }

    let mut pos = DNS_HEADER_SIZE;

    // Skip question section
    for _ in 0..qdcount {
        skip_wire_name(wire, &mut pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > wire.len() {
            return Err(NetError::Protocol("truncated question section".into()));
        }
    }

    // Skip answer + authority sections (RRs)
    for _ in 0..(ancount + nscount) {
        skip_wire_name(wire, &mut pos)?;
        if pos + 10 > wire.len() {
            return Err(NetError::Protocol("truncated RR in response".into()));
        }
        let rdlength = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if pos > wire.len() {
            return Err(NetError::Protocol("truncated RDATA in response".into()));
        }
    }

    // Scan additional section — look for TSIG in the last record
    let mut last_rr_start = None;
    let mut last_rr_type = 0u16;
    for _ in 0..arcount {
        let rr_start = pos;
        skip_wire_name(wire, &mut pos)?;
        if pos + 10 > wire.len() {
            return Err(NetError::Protocol("truncated additional RR".into()));
        }
        let rtype = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        let rdlength = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if pos > wire.len() {
            return Err(NetError::Protocol("truncated additional RDATA".into()));
        }
        last_rr_start = Some(rr_start);
        last_rr_type = rtype;
    }

    if last_rr_type == TSIG_TYPE {
        Ok(last_rr_start)
    } else {
        Ok(None)
    }
}

/// Sends RFC 2136 dynamic update messages over UDP with TCP fallback.
///
/// The sender transmits `UpdateMessage` bytes to a DNS server. If the
/// UDP response has the TC (truncated) bit set, it automatically retries
/// over TCP with the standard 2-byte length prefix.
pub struct NsUpdateSender {
    server: SocketAddr,
    timeout: Duration,
}

impl NsUpdateSender {
    /// Create a new sender targeting the given DNS server address.
    ///
    /// Uses a default timeout of 5 seconds.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a sender with a custom timeout.
    pub fn with_timeout(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }

    /// Send an RFC 2136 dynamic update message and return the server's response.
    ///
    /// 1. Sends the message bytes over UDP.
    /// 2. Waits for a response (with timeout).
    /// 3. If the response has the TC (truncated) bit, retries over TCP.
    /// 4. Parses the response header and returns `UpdateResult`.
    /// 5. If a TSIG key is provided and the request was signed, verifies the
    ///    response TSIG per RFC 8945 §4.5.
    pub async fn send(
        &self,
        update: &UpdateMessage,
        tsig_key: Option<&TsigKey>,
    ) -> Result<UpdateResult, NetError> {
        let wire = update.as_bytes();

        // Attempt UDP first
        let udp_response = self.send_udp(wire).await?;

        // Check for truncation — retry over TCP if TC bit is set
        let response = if is_truncated(&udp_response) {
            tracing::debug!(
                server = %self.server,
                "UDP response truncated, retrying over TCP"
            );
            self.send_tcp(wire).await?
        } else {
            udp_response
        };

        let result = parse_dns_response(&response)?;

        // Verify response TSIG if the request was signed
        if let (Some(key), Some(request_mac)) = (tsig_key, update.request_mac()) {
            if let Some(tsig_offset) = find_tsig_in_response(&response)? {
                // Parse the TSIG record from the response
                let response_tsig = TsigRecord::parse_from_wire(&response[tsig_offset..])
                    .map_err(|e| NetError::Protocol(format!("failed to parse response TSIG: {e}")))?;

                // The message bytes for verification = response without TSIG, ARCOUNT decremented
                let mut msg_sans_tsig = response[..tsig_offset].to_vec();
                if msg_sans_tsig.len() >= DNS_HEADER_SIZE {
                    let arcount = u16::from_be_bytes([msg_sans_tsig[10], msg_sans_tsig[11]]);
                    if arcount > 0 {
                        msg_sans_tsig[10..12]
                            .copy_from_slice(&(arcount - 1).to_be_bytes());
                    }
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                TsigRecord::verify_response(key, &msg_sans_tsig, &response_tsig, request_mac, now)
                    .map_err(|e| {
                        NetError::Protocol(format!("response TSIG verification failed: {e}"))
                    })?;

                tracing::debug!(
                    server = %self.server,
                    "response TSIG verified successfully"
                );
            } else {
                tracing::warn!(
                    server = %self.server,
                    "signed request but response contains no TSIG record"
                );
            }
        }

        Ok(result)
    }

    /// Send update message bytes over UDP and return the raw response.
    async fn send_udp(&self, wire: &[u8]) -> Result<Vec<u8>, NetError> {
        // Bind to the matching address family (IPv4 vs IPv6)
        let bind_addr: SocketAddr = if self.server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetError::Connection(format!("failed to bind UDP socket: {e}")))?;

        socket
            .connect(self.server)
            .await
            .map_err(|e| NetError::Connection(format!("UDP connect failed: {e}")))?;

        socket
            .send(wire)
            .await
            .map_err(|e| NetError::Connection(format!("UDP send failed: {e}")))?;

        let mut buf = vec![0u8; 4096]; // DNS UDP max is 512 without EDNS, 4096 with
        let recv_future = socket.recv(&mut buf);
        let len = tokio::time::timeout(self.timeout, recv_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("UDP recv failed: {e}")))?;

        buf.truncate(len);
        Ok(buf)
    }

    /// Send update message bytes over TCP with DNS 2-byte length prefix.
    async fn send_tcp(&self, wire: &[u8]) -> Result<Vec<u8>, NetError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let connect_future = tokio::net::TcpStream::connect(self.server);
        let mut stream = tokio::time::timeout(self.timeout, connect_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP connect failed: {e}")))?;

        // DNS over TCP: 2-byte big-endian length prefix
        let len = u16::try_from(wire.len()).map_err(|_| {
            NetError::Protocol(format!(
                "update message too large for TCP: {} bytes",
                wire.len()
            ))
        })?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| NetError::Connection(format!("TCP write length failed: {e}")))?;
        stream
            .write_all(wire)
            .await
            .map_err(|e| NetError::Connection(format!("TCP write message failed: {e}")))?;

        // Read response: 2-byte length prefix + message
        let mut len_buf = [0u8; 2];
        let read_future = stream.read_exact(&mut len_buf);
        tokio::time::timeout(self.timeout, read_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP read length failed: {e}")))?;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < DNS_HEADER_SIZE {
            return Err(NetError::Protocol(format!(
                "TCP response too short: {resp_len} bytes"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        let read_future = stream.read_exact(&mut resp_buf);
        tokio::time::timeout(self.timeout, read_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP read message failed: {e}")))?;

        Ok(resp_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_timeout() {
        let sender = NsUpdateSender::new("127.0.0.1:53".parse().unwrap());
        assert_eq!(sender.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn with_timeout_uses_custom_timeout() {
        let timeout = Duration::from_secs(30);
        let sender = NsUpdateSender::with_timeout("127.0.0.1:53".parse().unwrap(), timeout);
        assert_eq!(sender.timeout, timeout);
    }

    #[test]
    fn server_address_stored() {
        let addr: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let sender = NsUpdateSender::new(addr);
        assert_eq!(sender.server, addr);
    }

    // -- DNS response header parsing tests --

    #[test]
    fn parse_response_extracts_noerror_rcode() {
        let response = [
            0x12, 0x34, // ID
            0x85, 0x00, // Flags: QR=1, AA=1, TC=0, RD=0, RA=0, RCODE=0 (NOERROR)
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x1234);
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn parse_response_extracts_refused_rcode() {
        let response = [
            0x00, 0x01, // ID
            0x80, 0x05, // Flags: QR=1, RCODE=5 (REFUSED)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0001);
        assert_eq!(result.rcode, Rcode::Refused);
    }

    #[test]
    fn parse_response_extracts_nxdomain() {
        let response = [
            0xAB, 0xCD, // ID
            0x80, 0x03, // Flags: QR=1, RCODE=3 (NXDOMAIN)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0xABCD);
        assert_eq!(result.rcode, Rcode::NxDomain);
    }

    #[test]
    fn parse_response_too_short_fails() {
        let response = [0x00, 0x01, 0x80]; // Only 3 bytes, need at least 12
        assert!(parse_dns_response(&response).is_err());
    }

    #[test]
    fn detect_tc_bit_set() {
        let response = [
            0x00, 0x01, // ID
            0x82, 0x00, // Flags: QR=1, TC=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_truncated(&response));
    }

    #[test]
    fn detect_tc_bit_not_set() {
        let response = [
            0x00, 0x01, // ID
            0x80, 0x00, // Flags: QR=1, TC=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_truncated(&response));
    }

    // -- Edge case tests --

    #[test]
    fn parse_response_notauth_rcode() {
        let response = [
            0x00, 0x42, // ID
            0x80, 0x09, // Flags: QR=1, RCODE=9 (NOTAUTH)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0042);
        assert_eq!(result.rcode, Rcode::NotAuth);
    }

    #[test]
    fn parse_response_yxdomain_rcode() {
        let response = [
            0xFF, 0xFF, // ID
            0x80, 0x06, // Flags: QR=1, RCODE=6 (YXDOMAIN)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0xFFFF);
        assert_eq!(result.rcode, Rcode::YxDomain);
    }

    #[test]
    fn parse_response_preserves_all_rcode_bits() {
        let response = [
            0x00, 0x01, // ID
            0x80, 0xF5, // Flags: QR=1, Z bits set, RCODE=5 (REFUSED)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.rcode, Rcode::Refused);
    }

    #[test]
    fn parse_response_with_extra_data_succeeds() {
        let mut response = vec![
            0x00, 0x01, // ID
            0x85, 0x00, // Flags: QR=1, AA=1, RCODE=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra data
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0001);
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn parse_response_exactly_12_bytes() {
        let response = [
            0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_response(&response).is_ok());
    }

    #[test]
    fn parse_response_11_bytes_fails() {
        let response = [
            0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_response(&response).is_err());
    }

    #[test]
    fn tc_bit_combined_with_other_flags() {
        // TC=1 along with AA=1, RD=1
        let response = [
            0x00, 0x01, // ID
            0x87, 0x00, // Flags: QR=1, AA=1, TC=1, RD=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_truncated(&response));
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn is_truncated_empty_buffer() {
        assert!(!is_truncated(&[]));
    }

    #[test]
    fn new_with_ipv6_server() {
        let addr: SocketAddr = "[::1]:53".parse().unwrap();
        let sender = NsUpdateSender::new(addr);
        assert_eq!(sender.server, addr);
        assert!(sender.server.is_ipv6());
    }

    // -- TSIG response extraction tests --

    /// Build a minimal DNS response with the given section counts and an optional
    /// TSIG record in additional section.
    fn build_test_response(qdcount: u16, arcount: u16, include_tsig: bool) -> Vec<u8> {
        let mut wire = vec![
            0x00, 0x01, // ID
            0x85, 0x00, // Flags: QR=1, AA=1, RCODE=0
            0x00, 0x00, // QDCOUNT (placeholder)
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT (placeholder)
        ];
        wire[4..6].copy_from_slice(&qdcount.to_be_bytes());
        wire[10..12].copy_from_slice(&arcount.to_be_bytes());

        // Add question section entries (zone section for UPDATE)
        for _ in 0..qdcount {
            // Zone name: example.com. in wire format
            wire.extend_from_slice(&[7]); // label length
            wire.extend_from_slice(b"example");
            wire.extend_from_slice(&[3]); // label length
            wire.extend_from_slice(b"com");
            wire.push(0); // root label
            wire.extend_from_slice(&6u16.to_be_bytes()); // QTYPE = SOA
            wire.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        }

        if include_tsig {
            // Minimal TSIG record: key name + TYPE=250 + CLASS=255 + TTL=0 + RDATA
            // Key name: "test-key." in wire format
            wire.extend_from_slice(&[8]); // label length
            wire.extend_from_slice(b"test-key");
            wire.push(0); // root label
            wire.extend_from_slice(&250u16.to_be_bytes()); // TYPE = TSIG
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS = ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
            // RDATA: algorithm name + time + fudge + mac_size + mac + orig_id + error + other_len
            let mut rdata = Vec::new();
            // Algorithm: hmac-sha256. in wire format
            rdata.extend_from_slice(&[11]); // label length
            rdata.extend_from_slice(b"hmac-sha256");
            rdata.push(0); // root label
            // Time signed: 48-bit (6 bytes)
            rdata.extend_from_slice(&[0x00, 0x00, 0x65, 0xD0, 0xA0, 0x00]);
            // Fudge: 300
            rdata.extend_from_slice(&300u16.to_be_bytes());
            // MAC size: 32
            rdata.extend_from_slice(&32u16.to_be_bytes());
            // MAC: 32 bytes of 0xAA
            rdata.extend_from_slice(&[0xAA; 32]);
            // Original ID
            rdata.extend_from_slice(&0x0001u16.to_be_bytes());
            // Error: 0
            rdata.extend_from_slice(&0u16.to_be_bytes());
            // Other length: 0
            rdata.extend_from_slice(&0u16.to_be_bytes());

            wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            wire.extend_from_slice(&rdata);
        }

        wire
    }

    #[test]
    fn find_tsig_no_additional_section() {
        let response = build_test_response(1, 0, false);
        assert!(find_tsig_in_response(&response).unwrap().is_none());
    }

    #[test]
    fn find_tsig_with_tsig_record() {
        let response = build_test_response(1, 1, true);
        let offset = find_tsig_in_response(&response).unwrap();
        assert!(offset.is_some(), "should find TSIG in additional section");
        // Verify the offset points to the TSIG owner name
        let off = offset.unwrap();
        // First byte at offset should be the key name label length (8 for "test-key")
        assert_eq!(response[off], 8);
    }

    #[test]
    fn find_tsig_header_only() {
        // Minimal 12-byte header with ARCOUNT=0
        let response = [
            0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(find_tsig_in_response(&response).unwrap().is_none());
    }

    #[test]
    fn find_tsig_too_short() {
        assert!(find_tsig_in_response(&[0x00, 0x01]).unwrap().is_none());
    }

    #[test]
    fn skip_wire_name_uncompressed() {
        // "example.com." = \x07example\x03com\x00
        let wire = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let mut pos = 0;
        skip_wire_name(&wire, &mut pos).unwrap();
        assert_eq!(pos, 13);
    }

    #[test]
    fn skip_wire_name_compressed() {
        // Compression pointer: 0xC0 0x00
        let wire = [0xC0, 0x00];
        let mut pos = 0;
        skip_wire_name(&wire, &mut pos).unwrap();
        assert_eq!(pos, 2);
    }

    #[test]
    fn skip_wire_name_root() {
        let wire = [0]; // root label
        let mut pos = 0;
        skip_wire_name(&wire, &mut pos).unwrap();
        assert_eq!(pos, 1);
    }

    #[test]
    fn signed_update_message_has_request_mac() {
        use bind9_sdk_core::domain::DomainName;
        use bind9_sdk_core::record::RecordClass;
        use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
        use bind9_sdk_core::update::UpdateBuilder;

        let zone = DomainName::new("example.com.").unwrap();
        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xBB; 32],
        )
        .unwrap();

        let msg = UpdateBuilder::new(zone, RecordClass::IN)
            .sign(&key, 1710000000)
            .build();

        assert!(msg.is_signed());
        assert!(msg.request_mac().is_some());
        assert_eq!(msg.request_mac().unwrap().len(), 32); // SHA256 MAC
    }

    #[test]
    fn unsigned_update_message_has_no_request_mac() {
        use bind9_sdk_core::domain::DomainName;
        use bind9_sdk_core::record::RecordClass;
        use bind9_sdk_core::update::UpdateBuilder;

        let zone = DomainName::new("example.com.").unwrap();
        let msg = UpdateBuilder::new(zone, RecordClass::IN).build_unsigned();

        assert!(!msg.is_signed());
        assert!(msg.request_mac().is_none());
    }

    // -- Integration test stubs --

    #[tokio::test]
    #[ignore = "requires live BIND9 accepting dynamic updates on localhost:53"]
    async fn integration_send_update_to_live_bind9() {
        // Requires: running BIND9 + zone accepting dynamic updates + UpdateBuilder from WT-2
        todo!("implement after WT-2 delivers UpdateBuilder")
    }

    #[tokio::test]
    #[ignore = "requires live BIND9 — tests TCP fallback with large update"]
    async fn integration_tcp_fallback_with_large_update() {
        todo!("implement after WT-2 delivers UpdateBuilder")
    }
}
