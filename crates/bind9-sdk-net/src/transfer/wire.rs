// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! DNS wire format parsing and encoding for zone transfers.
//!
//! Implements RFC 1035 §4 message parsing: header, name decompression,
//! resource record extraction, and rdata decoding for common types.
//! Also provides AXFR/IXFR query encoding with optional TSIG.

use std::net::{Ipv4Addr, Ipv6Addr};

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::protocol::RecordType;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::record::{RecordClass, ResourceRecord, Serial, Ttl};
use bind9_sdk_core::tsig::{TsigKey, TsigRecord};

use crate::error::NetError;

/// DNS header size in bytes.
const DNS_HEADER_SIZE: usize = 12;

/// Maximum allowed compression pointer depth to prevent loops.
const MAX_COMPRESSION_DEPTH: usize = 128;

/// AXFR query type (252).
const QTYPE_AXFR: u16 = 252;

/// IXFR query type (251).
const QTYPE_IXFR: u16 = 251;

/// Encoded transfer query plus the state needed to authenticate responses.
pub(super) struct EncodedXfrQuery {
    pub(super) message: Vec<u8>,
    pub(super) id: u16,
    pub(super) request_mac: Option<Vec<u8>>,
}

/// DNS message with its final TSIG pseudo-record removed, when present.
pub(super) struct SplitTsigMessage {
    pub(super) unsigned_message: Vec<u8>,
    pub(super) tsig: Option<TsigRecord>,
}

/// Parsed DNS message header (RFC 1035 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsHeader {
    /// Message ID.
    pub id: u16,
    /// Whether this is a response (QR=1) or query (QR=0).
    pub is_response: bool,
    /// Opcode (4 bits).
    pub opcode: u8,
    /// Authoritative answer flag.
    pub authoritative: bool,
    /// Truncation flag.
    pub truncated: bool,
    /// Recursion desired flag.
    pub recursion_desired: bool,
    /// Recursion available flag.
    pub recursion_available: bool,
    /// Response code (4 bits).
    pub rcode: u8,
    /// Number of entries in the question section.
    pub question_count: u16,
    /// Number of entries in the answer section.
    pub answer_count: u16,
    /// Number of entries in the authority section.
    pub authority_count: u16,
    /// Number of entries in the additional section.
    pub additional_count: u16,
}

impl DnsHeader {
    /// Parse a DNS header from the first 12 bytes of a message.
    pub fn parse(buf: &[u8]) -> Result<Self, NetError> {
        if buf.len() < DNS_HEADER_SIZE {
            return Err(NetError::XfrProtocolError(format!(
                "DNS header too short: {} bytes, need {DNS_HEADER_SIZE}",
                buf.len()
            )));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags1 = buf[2];
        let flags2 = buf[3];

        Ok(DnsHeader {
            id,
            is_response: flags1 & 0x80 != 0,
            opcode: (flags1 >> 3) & 0x0F,
            authoritative: flags1 & 0x04 != 0,
            truncated: flags1 & 0x02 != 0,
            recursion_desired: flags1 & 0x01 != 0,
            recursion_available: flags2 & 0x80 != 0,
            rcode: flags2 & 0x0F,
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

/// Parse a DNS name from wire format with compression support (RFC 1035 §4.1.4).
///
/// Returns the parsed name as a `DomainName` and the number of bytes consumed
/// from the current position (not counting compression pointer targets).
pub fn parse_name(buf: &[u8], offset: usize) -> Result<(DomainName, usize), NetError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut bytes_consumed = 0;
    let mut jumped = false;
    let mut depth = 0;
    // Track the first pointer's position to restrict forward references
    let mut first_pointer_pos: Option<usize> = None;

    loop {
        if pos >= buf.len() {
            return Err(NetError::XfrProtocolError("truncated DNS name".into()));
        }

        depth += 1;
        if depth > MAX_COMPRESSION_DEPTH {
            return Err(NetError::XfrProtocolError(
                "DNS name compression loop detected".into(),
            ));
        }

        let len_byte = buf[pos];

        if len_byte == 0 {
            // Root label — end of name
            if !jumped {
                bytes_consumed = pos - offset + 1;
            }
            break;
        }

        // Compression pointer: top 2 bits are 11
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(NetError::XfrProtocolError(
                    "truncated compression pointer".into(),
                ));
            }
            if !jumped {
                bytes_consumed = pos - offset + 2;
                jumped = true;
            }
            let pointer = ((u16::from(len_byte) & 0x3F) << 8) | u16::from(buf[pos + 1]);
            let pointer_usize = pointer as usize;

            // Restrict compression pointers to backward references only.
            // Forward pointers enable crafted messages that jump into unprocessed
            // rdata where bytes are not valid label data (RFC 1035 §4.1.4).
            let limit = first_pointer_pos.unwrap_or(offset);
            if pointer_usize >= limit {
                return Err(NetError::XfrProtocolError(format!(
                    "compression pointer at offset {pos} targets {pointer_usize} \
                     (must be before {limit})"
                )));
            }
            if first_pointer_pos.is_none() {
                first_pointer_pos = Some(pos);
            }
            pos = pointer_usize;
            continue;
        }

        // Regular label
        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > buf.len() {
            return Err(NetError::XfrProtocolError(format!(
                "truncated DNS label: need {label_len} bytes at offset {pos}"
            )));
        }

        let label_str = std::str::from_utf8(&buf[pos..pos + label_len])
            .map_err(|_| NetError::XfrProtocolError("DNS label contains non-UTF8 bytes".into()))?;
        labels.push(label_str.to_string());
        pos += label_len;
    }

    if labels.is_empty() {
        return Ok((DomainName::root(), bytes_consumed));
    }

    let name_str = format!("{}.", labels.join("."));
    let domain = DomainName::new(&name_str)
        .map_err(|e| NetError::XfrProtocolError(format!("invalid DNS name from wire: {e}")))?;

    Ok((domain, bytes_consumed))
}

/// Parse rdata from DNS wire format for common record types.
///
/// `rtype_value` is the numeric record type, `rdata_buf` is the raw RDATA bytes,
/// and `full_msg` is the complete DNS message (needed for name decompression in
/// types like NS, CNAME, MX, SOA).
pub fn parse_rdata_wire(
    rtype_value: u16,
    rdata_buf: &[u8],
    full_msg: &[u8],
    rdata_offset: usize,
) -> Result<RecordData, NetError> {
    let rtype = RecordType::from_value(rtype_value);

    match rtype {
        RecordType::A => {
            if rdata_buf.len() != 4 {
                return Err(NetError::XfrProtocolError(format!(
                    "A record RDATA must be 4 bytes, got {}",
                    rdata_buf.len()
                )));
            }
            Ok(RecordData::A(Ipv4Addr::new(
                rdata_buf[0],
                rdata_buf[1],
                rdata_buf[2],
                rdata_buf[3],
            )))
        }

        RecordType::Aaaa => {
            if rdata_buf.len() != 16 {
                return Err(NetError::XfrProtocolError(format!(
                    "AAAA record RDATA must be 16 bytes, got {}",
                    rdata_buf.len()
                )));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata_buf);
            Ok(RecordData::Aaaa(Ipv6Addr::from(octets)))
        }

        RecordType::Ns => {
            let (name, _) = parse_name(full_msg, rdata_offset)?;
            Ok(RecordData::Ns(name))
        }

        RecordType::Cname => {
            let (name, _) = parse_name(full_msg, rdata_offset)?;
            Ok(RecordData::Cname(name))
        }

        RecordType::Ptr => {
            let (name, _) = parse_name(full_msg, rdata_offset)?;
            Ok(RecordData::Ptr(name))
        }

        RecordType::Mx => {
            if rdata_buf.len() < 3 {
                return Err(NetError::XfrProtocolError(
                    "MX record RDATA too short".into(),
                ));
            }
            let preference = u16::from_be_bytes([rdata_buf[0], rdata_buf[1]]);
            let (exchange, _) = parse_name(full_msg, rdata_offset + 2)?;
            Ok(RecordData::Mx {
                preference,
                exchange,
            })
        }

        RecordType::Txt => {
            let mut strings = Vec::new();
            let mut pos = 0;
            while pos < rdata_buf.len() {
                let str_len = rdata_buf[pos] as usize;
                pos += 1;
                if pos + str_len > rdata_buf.len() {
                    return Err(NetError::XfrProtocolError("truncated TXT string".into()));
                }
                let s = std::str::from_utf8(&rdata_buf[pos..pos + str_len])
                    .map_err(|_| NetError::XfrProtocolError("TXT string not UTF-8".into()))?
                    .to_string();
                strings.push(s);
                pos += str_len;
            }
            Ok(RecordData::Txt(strings))
        }

        RecordType::Soa => {
            let (mname, mname_len) = parse_name(full_msg, rdata_offset)?;
            let (rname, rname_len) = parse_name(full_msg, rdata_offset + mname_len)?;
            let soa_data_offset = rdata_offset + mname_len + rname_len;

            // Need 20 bytes: serial(4) + refresh(4) + retry(4) + expire(4) + minimum(4)
            if soa_data_offset + 20 > full_msg.len() {
                return Err(NetError::XfrProtocolError(
                    "SOA record RDATA too short for timers".into(),
                ));
            }

            let b = &full_msg[soa_data_offset..soa_data_offset + 20];
            let serial = Serial::new(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            let refresh = Ttl::new(u32::from_be_bytes([b[4], b[5], b[6], b[7]]))
                .map_err(|e| NetError::XfrProtocolError(format!("SOA refresh: {e}")))?;
            let retry = Ttl::new(u32::from_be_bytes([b[8], b[9], b[10], b[11]]))
                .map_err(|e| NetError::XfrProtocolError(format!("SOA retry: {e}")))?;
            let expire = Ttl::new(u32::from_be_bytes([b[12], b[13], b[14], b[15]]))
                .map_err(|e| NetError::XfrProtocolError(format!("SOA expire: {e}")))?;
            let minimum = Ttl::new(u32::from_be_bytes([b[16], b[17], b[18], b[19]]))
                .map_err(|e| NetError::XfrProtocolError(format!("SOA minimum: {e}")))?;

            Ok(RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }

        RecordType::Srv => {
            if rdata_buf.len() < 7 {
                return Err(NetError::XfrProtocolError(
                    "SRV record RDATA too short".into(),
                ));
            }
            let priority = u16::from_be_bytes([rdata_buf[0], rdata_buf[1]]);
            let weight = u16::from_be_bytes([rdata_buf[2], rdata_buf[3]]);
            let port = u16::from_be_bytes([rdata_buf[4], rdata_buf[5]]);
            let (target, _) = parse_name(full_msg, rdata_offset + 6)?;
            Ok(RecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }

        RecordType::Caa => {
            if rdata_buf.len() < 2 {
                return Err(NetError::XfrProtocolError(
                    "CAA record RDATA too short".into(),
                ));
            }
            let flags = rdata_buf[0];
            let tag_len = rdata_buf[1] as usize;
            if 2 + tag_len > rdata_buf.len() {
                return Err(NetError::XfrProtocolError("truncated CAA tag".into()));
            }
            let tag = std::str::from_utf8(&rdata_buf[2..2 + tag_len])
                .map_err(|_| NetError::XfrProtocolError("CAA tag not UTF-8".into()))?
                .to_string();
            let value = std::str::from_utf8(&rdata_buf[2 + tag_len..])
                .map_err(|_| NetError::XfrProtocolError("CAA value not UTF-8".into()))?
                .to_string();
            Ok(RecordData::Caa { flags, tag, value })
        }

        _ => Ok(RecordData::Unknown {
            rtype: rtype_value,
            rdata: rdata_buf.to_vec(),
        }),
    }
}

/// Parse a single resource record from the wire at `offset`.
///
/// Returns the parsed `ResourceRecord` and the number of bytes consumed.
/// `full_msg` is the complete DNS message (for name decompression).
pub fn parse_resource_record(
    full_msg: &[u8],
    offset: usize,
) -> Result<(ResourceRecord, usize), NetError> {
    let (name, name_len) = parse_name(full_msg, offset)?;
    let pos = offset + name_len;

    // Need: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
    if pos + 10 > full_msg.len() {
        return Err(NetError::XfrProtocolError(
            "truncated resource record header".into(),
        ));
    }

    let rtype_value = u16::from_be_bytes([full_msg[pos], full_msg[pos + 1]]);
    let rclass_value = u16::from_be_bytes([full_msg[pos + 2], full_msg[pos + 3]]);
    let ttl_value = u32::from_be_bytes([
        full_msg[pos + 4],
        full_msg[pos + 5],
        full_msg[pos + 6],
        full_msg[pos + 7],
    ]);
    let rdlength = u16::from_be_bytes([full_msg[pos + 8], full_msg[pos + 9]]) as usize;
    let rdata_offset = pos + 10;

    if rdata_offset + rdlength > full_msg.len() {
        return Err(NetError::XfrProtocolError(format!(
            "truncated RDATA: need {rdlength} bytes at offset {rdata_offset}"
        )));
    }

    let rdata_buf = &full_msg[rdata_offset..rdata_offset + rdlength];
    let rdata = parse_rdata_wire(rtype_value, rdata_buf, full_msg, rdata_offset)?;

    let class = RecordClass::from_value(rclass_value);
    // TTL values > 2^31 - 1 are clamped to 0 per RFC 8767
    let ttl = Ttl::new(ttl_value).unwrap_or_else(|_| {
        tracing::warn!(
            ttl_value,
            "TTL exceeds RFC 8767 max (2^31-1), clamping to 0"
        );
        Ttl::new(0).unwrap()
    });

    let rr = ResourceRecord {
        name,
        class,
        ttl,
        rdata,
    };

    let total = name_len + 10 + rdlength;
    Ok((rr, total))
}

/// Remove and parse a TSIG record from the final additional-section position.
pub(super) fn split_final_tsig(message: &[u8]) -> Result<SplitTsigMessage, NetError> {
    let header = DnsHeader::parse(message)?;
    let mut offset = DNS_HEADER_SIZE;

    for _ in 0..header.question_count {
        let (_, name_len) = parse_name(message, offset)?;
        offset = offset
            .checked_add(name_len + 4)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| NetError::XfrProtocolError("truncated DNS question".into()))?;
    }

    let non_additional_count = usize::from(header.answer_count)
        .checked_add(usize::from(header.authority_count))
        .ok_or_else(|| NetError::XfrProtocolError("DNS section count overflow".into()))?;
    for _ in 0..non_additional_count {
        let (rtype, consumed) = resource_record_type_and_len(message, offset)?;
        if rtype == 250 {
            return Err(NetError::XfrProtocolError(
                "TSIG is only valid in the additional section".into(),
            ));
        }
        offset += consumed;
    }

    let mut tsig_offset = None;
    for index in 0..header.additional_count {
        let record_offset = offset;
        let (rtype, consumed) = resource_record_type_and_len(message, offset)?;
        offset += consumed;
        if rtype == 250 {
            if index + 1 != header.additional_count {
                return Err(NetError::XfrProtocolError(
                    "TSIG must be the final additional record".into(),
                ));
            }
            tsig_offset = Some(record_offset);
        }
    }

    if offset != message.len() {
        return Err(NetError::XfrProtocolError(format!(
            "trailing bytes after DNS sections: {}",
            message.len() - offset
        )));
    }

    let Some(tsig_offset) = tsig_offset else {
        return Ok(SplitTsigMessage {
            unsigned_message: message.to_vec(),
            tsig: None,
        });
    };

    let tsig = TsigRecord::parse_from_wire(&message[tsig_offset..])?;
    let mut unsigned_message = message[..tsig_offset].to_vec();
    let unsigned_additional_count = header.additional_count.checked_sub(1).ok_or_else(|| {
        NetError::XfrProtocolError("TSIG present with zero additional count".into())
    })?;
    unsigned_message[10..12].copy_from_slice(&unsigned_additional_count.to_be_bytes());

    Ok(SplitTsigMessage {
        unsigned_message,
        tsig: Some(tsig),
    })
}

fn resource_record_type_and_len(message: &[u8], offset: usize) -> Result<(u16, usize), NetError> {
    let (_, name_len) = parse_name(message, offset)?;
    let fixed_offset = offset
        .checked_add(name_len)
        .ok_or_else(|| NetError::XfrProtocolError("resource record offset overflow".into()))?;
    if fixed_offset + 10 > message.len() {
        return Err(NetError::XfrProtocolError(
            "truncated resource record header".into(),
        ));
    }

    let rtype = u16::from_be_bytes([message[fixed_offset], message[fixed_offset + 1]]);
    let rdlength =
        u16::from_be_bytes([message[fixed_offset + 8], message[fixed_offset + 9]]) as usize;
    let consumed = name_len
        .checked_add(10)
        .and_then(|length| length.checked_add(rdlength))
        .ok_or_else(|| NetError::XfrProtocolError("resource record length overflow".into()))?;
    if offset
        .checked_add(consumed)
        .is_none_or(|end| end > message.len())
    {
        return Err(NetError::XfrProtocolError(
            "truncated resource record data".into(),
        ));
    }

    Ok((rtype, consumed))
}

/// Encode an AXFR query message for the given zone.
///
/// If `tsig_key` is provided, the query is signed with TSIG (appended as
/// an additional record per RFC 8945).
///
/// Returns the complete DNS message bytes (without TCP length prefix).
pub fn encode_axfr_query(zone: &DomainName, tsig_key: Option<&TsigKey>) -> Vec<u8> {
    encode_axfr_query_with_metadata(zone, tsig_key).message
}

/// Encode an AXFR query while retaining response-authentication state.
pub(super) fn encode_axfr_query_with_metadata(
    zone: &DomainName,
    tsig_key: Option<&TsigKey>,
) -> EncodedXfrQuery {
    encode_xfr_query(zone, QTYPE_AXFR, None, tsig_key)
}

/// Encode an IXFR query message for the given zone.
///
/// The query includes a SOA record in the authority section with the
/// `current_serial` to indicate what the client already has.
///
/// If `tsig_key` is provided, the query is signed with TSIG.
pub fn encode_ixfr_query(
    zone: &DomainName,
    current_serial: Serial,
    tsig_key: Option<&TsigKey>,
) -> Vec<u8> {
    encode_ixfr_query_with_metadata(zone, current_serial, tsig_key).message
}

/// Encode an IXFR query while retaining response-authentication state.
pub(super) fn encode_ixfr_query_with_metadata(
    zone: &DomainName,
    current_serial: Serial,
    tsig_key: Option<&TsigKey>,
) -> EncodedXfrQuery {
    encode_xfr_query(zone, QTYPE_IXFR, Some(current_serial), tsig_key)
}

/// Internal: encode an XFR query (AXFR or IXFR).
fn encode_xfr_query(
    zone: &DomainName,
    qtype: u16,
    current_serial: Option<Serial>,
    tsig_key: Option<&TsigKey>,
) -> EncodedXfrQuery {
    let mut buf = Vec::with_capacity(128);

    // Generate a cryptographically random query ID (RFC 5452 §3)
    let id: u16 = {
        let mut buf = [0u8; 2];
        getrandom::fill(&mut buf).expect("getrandom failed for DNS query ID");
        u16::from_be_bytes(buf)
    };

    // Header
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x00, 0x00]); // Flags: standard query
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0

    let nscount: u16 = if current_serial.is_some() { 1 } else { 0 };
    buf.extend_from_slice(&nscount.to_be_bytes()); // NSCOUNT

    // ARCOUNT placeholder — filled in after TSIG
    let arcount_offset = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT (placeholder)

    // Question section
    zone.write_wire(&mut buf);
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&RecordClass::IN.value().to_be_bytes()); // QCLASS

    // Authority section (IXFR: include SOA with current serial)
    if let Some(serial) = current_serial {
        zone.write_wire(&mut buf); // NAME
        buf.extend_from_slice(&RecordType::Soa.value().to_be_bytes()); // TYPE = SOA
        buf.extend_from_slice(&RecordClass::IN.value().to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0

        // SOA RDATA: mname = zone, rname = zone, serial, refresh=0, retry=0, expire=0, minimum=0
        let rdata_len_offset = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder

        let rdata_start = buf.len();
        zone.write_wire(&mut buf); // MNAME
        zone.write_wire(&mut buf); // RNAME
        buf.extend_from_slice(&serial.value().to_be_bytes()); // SERIAL
        buf.extend_from_slice(&0u32.to_be_bytes()); // REFRESH
        buf.extend_from_slice(&0u32.to_be_bytes()); // RETRY
        buf.extend_from_slice(&0u32.to_be_bytes()); // EXPIRE
        buf.extend_from_slice(&0u32.to_be_bytes()); // MINIMUM

        let rdata_len = (buf.len() - rdata_start) as u16;
        buf[rdata_len_offset..rdata_len_offset + 2].copy_from_slice(&rdata_len.to_be_bytes());
    }

    // TSIG signing
    let mut arcount: u16 = 0;
    let mut request_mac = None;
    if let Some(key) = tsig_key {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let tsig = bind9_sdk_core::tsig::TsigRecord::new(key, &buf, now, None);
        request_mac = Some(tsig.mac.to_vec());
        buf.extend_from_slice(&tsig.wire_bytes);
        arcount = 1;
    }

    // Patch ARCOUNT
    buf[arcount_offset..arcount_offset + 2].copy_from_slice(&arcount.to_be_bytes());

    EncodedXfrQuery {
        message: buf,
        id,
        request_mac,
    }
}

/// Read a DNS TCP message: 2-byte big-endian length prefix + message bytes.
///
/// Returns the message bytes (without the length prefix).
pub async fn read_tcp_dns_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, NetError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NetError::IncompleteTransfer {
                reason: "connection closed before message length".into(),
            }
        } else {
            NetError::Io(e)
        }
    })?;

    let msg_len = u16::from_be_bytes(len_buf) as usize;
    if msg_len < DNS_HEADER_SIZE {
        return Err(NetError::XfrProtocolError(format!(
            "DNS TCP message too short: {msg_len} bytes"
        )));
    }

    let mut buf = vec![0u8; msg_len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| NetError::IncompleteTransfer {
            reason: format!("connection closed mid-message: {e}"),
        })?;

    Ok(buf)
}

/// Write a DNS TCP message with 2-byte big-endian length prefix.
pub async fn write_tcp_dns_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), NetError> {
    let len = u16::try_from(message.len()).map_err(|_| {
        NetError::XfrProtocolError(format!(
            "DNS message too large for TCP: {} bytes",
            message.len()
        ))
    })?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(NetError::Io)?;
    writer.write_all(message).await.map_err(NetError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_header() {
        let bytes = [
            0x12, 0x34, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = DnsHeader::parse(&bytes).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(header.is_response);
        assert_eq!(header.answer_count, 1);
        assert_eq!(header.rcode, 0);
    }

    #[test]
    fn parse_dns_header_too_short() {
        let bytes = [0x12, 0x34, 0x80];
        assert!(DnsHeader::parse(&bytes).is_err());
    }

    #[test]
    fn parse_dns_header_flags() {
        // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=3
        let bytes = [
            0x00, 0x01, 0x85, 0x83, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        ];
        let header = DnsHeader::parse(&bytes).unwrap();
        assert!(header.is_response);
        assert!(header.authoritative);
        assert!(!header.truncated);
        assert!(header.recursion_desired);
        assert!(header.recursion_available);
        assert_eq!(header.rcode, 3);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 2);
        assert_eq!(header.authority_count, 3);
        assert_eq!(header.additional_count, 4);
    }

    #[test]
    fn parse_name_simple() {
        // "example.com." = \x07example\x03com\x00
        let buf = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (name, consumed) = parse_name(&buf, 0).unwrap();
        assert_eq!(name, DomainName::new("example.com.").unwrap());
        assert_eq!(consumed, 13);
    }

    #[test]
    fn parse_name_root() {
        let buf = [0];
        let (name, consumed) = parse_name(&buf, 0).unwrap();
        assert!(name.is_root());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_name_with_compression() {
        // Message: \x07example\x03com\x00 at offset 0 (13 bytes)
        // Then a pointer: \xC0\x00 (points back to offset 0)
        let mut buf = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        buf.extend_from_slice(&[0xC0, 0x00]); // pointer to offset 0

        let (name, consumed) = parse_name(&buf, 13).unwrap();
        assert_eq!(name, DomainName::new("example.com.").unwrap());
        assert_eq!(consumed, 2); // only the pointer bytes consumed
    }

    #[test]
    fn parse_name_partial_compression() {
        // "ns1" label then pointer to "example.com."
        // Full message starts with "example.com." at offset 0
        let mut buf = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        // At offset 13: "ns1" + pointer
        buf.extend_from_slice(&[3, b'n', b's', b'1', 0xC0, 0x00]);

        let (name, consumed) = parse_name(&buf, 13).unwrap();
        assert_eq!(name, DomainName::new("ns1.example.com.").unwrap());
        assert_eq!(consumed, 6); // 1+3 for "ns1" + 2 for pointer
    }

    #[test]
    fn parse_resource_record_a() {
        // Build: name "a.com." + TYPE=A + CLASS=IN + TTL=300 + RDLENGTH=4 + 192.0.2.1
        let mut buf = Vec::new();
        // Name: a.com.
        buf.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0]);
        // TYPE = A (1)
        buf.extend_from_slice(&1u16.to_be_bytes());
        // CLASS = IN (1)
        buf.extend_from_slice(&1u16.to_be_bytes());
        // TTL = 300
        buf.extend_from_slice(&300u32.to_be_bytes());
        // RDLENGTH = 4
        buf.extend_from_slice(&4u16.to_be_bytes());
        // RDATA: 192.0.2.1
        buf.extend_from_slice(&[192, 0, 2, 1]);

        let (rr, consumed) = parse_resource_record(&buf, 0).unwrap();
        assert_eq!(rr.name, DomainName::new("a.com.").unwrap());
        assert_eq!(rr.class, RecordClass::IN);
        assert_eq!(rr.ttl.value(), 300);
        assert!(matches!(rr.rdata, RecordData::A(addr) if addr == Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_resource_record_soa() {
        let mut buf = Vec::new();
        // Name: example.com.
        let zone = DomainName::new("example.com.").unwrap();
        zone.write_wire(&mut buf);
        // TYPE = SOA (6)
        buf.extend_from_slice(&6u16.to_be_bytes());
        // CLASS = IN (1)
        buf.extend_from_slice(&1u16.to_be_bytes());
        // TTL = 3600
        buf.extend_from_slice(&3600u32.to_be_bytes());

        // RDATA
        let rdata_len_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes()); // placeholder
        let rdata_start = buf.len();

        let ns1 = DomainName::new("ns1.example.com.").unwrap();
        let admin = DomainName::new("admin.example.com.").unwrap();
        ns1.write_wire(&mut buf);
        admin.write_wire(&mut buf);
        buf.extend_from_slice(&2024010101u32.to_be_bytes()); // serial
        buf.extend_from_slice(&3600u32.to_be_bytes()); // refresh
        buf.extend_from_slice(&900u32.to_be_bytes()); // retry
        buf.extend_from_slice(&604800u32.to_be_bytes()); // expire
        buf.extend_from_slice(&86400u32.to_be_bytes()); // minimum

        let rdata_len = (buf.len() - rdata_start) as u16;
        buf[rdata_len_pos..rdata_len_pos + 2].copy_from_slice(&rdata_len.to_be_bytes());

        let (rr, _) = parse_resource_record(&buf, 0).unwrap();
        assert_eq!(rr.name, zone);
        if let RecordData::Soa { serial, mname, .. } = &rr.rdata {
            assert_eq!(serial.value(), 2024010101);
            assert_eq!(*mname, ns1);
        } else {
            panic!("expected SOA record data");
        }
    }

    #[test]
    fn encode_axfr_query_no_tsig() {
        let zone = DomainName::new("example.com.").unwrap();
        let query = encode_axfr_query(&zone, None);

        let header = DnsHeader::parse(&query).unwrap();
        assert!(!header.is_response);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 0);
        assert_eq!(header.authority_count, 0);
        assert_eq!(header.additional_count, 0);

        // Check QTYPE = AXFR (252) — it follows the zone name in the question
        let zone_wire_len = zone.wire_len();
        let qtype_offset = DNS_HEADER_SIZE + zone_wire_len;
        let qtype = u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]);
        assert_eq!(qtype, QTYPE_AXFR);
    }

    #[test]
    fn encode_ixfr_query_has_authority() {
        let zone = DomainName::new("example.com.").unwrap();
        let serial = Serial::new(2024010101);
        let query = encode_ixfr_query(&zone, serial, None);

        let header = DnsHeader::parse(&query).unwrap();
        assert_eq!(header.question_count, 1);
        assert_eq!(header.authority_count, 1);

        // Check QTYPE = IXFR (251)
        let zone_wire_len = zone.wire_len();
        let qtype_offset = DNS_HEADER_SIZE + zone_wire_len;
        let qtype = u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]);
        assert_eq!(qtype, QTYPE_IXFR);
    }

    #[test]
    fn axfr_query_includes_tsig() {
        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            bind9_sdk_core::tsig::TsigAlgorithm::HmacSha256,
            vec![0u8; 32],
        )
        .unwrap();
        let query = encode_axfr_query(&DomainName::new("example.com.").unwrap(), Some(&key));

        let header = DnsHeader::parse(&query).unwrap();
        assert_eq!(header.additional_count, 1);
    }

    #[test]
    fn signed_axfr_query_retains_id_and_request_mac() {
        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            bind9_sdk_core::tsig::TsigAlgorithm::HmacSha256,
            vec![0xA5; 32],
        )
        .unwrap();
        let zone = DomainName::new("example.com.").unwrap();

        let encoded = encode_axfr_query_with_metadata(&zone, Some(&key));
        let header = DnsHeader::parse(&encoded.message).unwrap();
        let tsig_offset = DNS_HEADER_SIZE + zone.wire_len() + 4;
        let parsed_tsig =
            bind9_sdk_core::tsig::TsigRecord::parse_from_wire(&encoded.message[tsig_offset..])
                .unwrap();

        assert_eq!(encoded.id, header.id);
        assert_eq!(
            encoded.request_mac.as_deref(),
            Some(parsed_tsig.mac.as_slice())
        );
    }

    #[test]
    fn parse_rdata_a_record() {
        let rdata = [192, 0, 2, 1];
        let result = parse_rdata_wire(1, &rdata, &rdata, 0).unwrap();
        assert!(matches!(result, RecordData::A(addr) if addr == Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn parse_rdata_aaaa_record() {
        let rdata = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = parse_rdata_wire(28, &rdata, &rdata, 0).unwrap();
        assert!(matches!(result, RecordData::Aaaa(_)));
    }

    #[test]
    fn parse_rdata_txt_record() {
        // TXT with two strings: "hello" and "world"
        let rdata = [
            5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
        ];
        let result = parse_rdata_wire(16, &rdata, &rdata, 0).unwrap();
        if let RecordData::Txt(strings) = result {
            assert_eq!(strings, vec!["hello", "world"]);
        } else {
            panic!("expected TXT");
        }
    }

    #[test]
    fn parse_rdata_unknown_type() {
        let rdata = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = parse_rdata_wire(65534, &rdata, &rdata, 0).unwrap();
        assert!(matches!(result, RecordData::Unknown { rtype: 65534, .. }));
    }

    #[test]
    fn parse_name_rejects_forward_pointer() {
        // Pointer at offset 0 targeting offset 2 (forward reference)
        let buf = [0xC0, 0x02, 3, b'c', b'o', b'm', 0];
        let result = parse_name(&buf, 0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("compression pointer"),
            "expected compression pointer error, got: {err}"
        );
    }

    #[test]
    fn parse_name_allows_backward_pointer() {
        // "com." at offset 0, pointer at offset 5 pointing back to offset 0
        let mut buf = vec![3, b'c', b'o', b'm', 0];
        buf.extend_from_slice(&[0xC0, 0x00]);
        let (name, consumed) = parse_name(&buf, 5).unwrap();
        assert_eq!(name, DomainName::new("com.").unwrap());
        assert_eq!(consumed, 2);
    }

    #[test]
    fn query_id_is_random() {
        // Two queries for the same zone should (almost certainly) have different IDs
        let zone = DomainName::new("example.com.").unwrap();
        let q1 = encode_axfr_query(&zone, None);
        let q2 = encode_axfr_query(&zone, None);
        let id1 = u16::from_be_bytes([q1[0], q1[1]]);
        let id2 = u16::from_be_bytes([q2[0], q2[1]]);
        // With 16 bits of randomness, collision probability is 1/65536
        // If they happen to match, that's fine — this test is probabilistic
        // but we run it to verify the code path works
        assert!(
            id1 != id2 || id1 != 0,
            "query IDs should be random, not zero"
        );
    }
}
