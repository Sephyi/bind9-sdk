// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! ISC binary message encoding for the rndc wire protocol (isccc).
//!
//! The rndc protocol uses a custom binary key-value format, NOT DNS wire format.
//! Messages are collections of key-value pairs where keys are strings and values
//! are either binary data or nested maps. Each key is length-prefixed (1-byte
//! length). Each value has a 1-byte type tag and 4-byte big-endian length prefix.
//!
//! # Wire format (per key-value pair)
//!
//! ```text
//! [1-byte key length] [key bytes]
//! [1-byte type tag]   -- 0x01 = binary, 0x02 = table
//! [4-byte BE value length] [value bytes]
//! ```
//!
//! Type tags verified against BIND9 source (`lib/isccc/cc.c`) and live wire
//! captures from BIND 9.20.18.

use std::collections::BTreeMap;

use crate::error::NetError;

/// Maximum nesting depth for ISC message maps.
///
/// Prevents stack overflow from deeply nested (potentially malicious) messages.
const MAX_DECODE_DEPTH: usize = 32;

/// ISC message version constant (always 1).
const ISC_MSG_VERSION: u32 = 1;

/// Type tag for binary/string data (isccc SEXPRTYPE_VALUE).
const ISCCC_TYPE_BINARY: u8 = 0x01;

/// Type tag for table/map (isccc SEXPRTYPE_ALIST).
const ISCCC_TYPE_TABLE: u8 = 0x02;

/// A value in an ISC binary message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IscValue {
    /// A UTF-8 string value (wire type: BINARY 0x01).
    String(String),
    /// Raw binary data (wire type: BINARY 0x01, same as String on the wire).
    Binary(Vec<u8>),
    /// A nested key-value map (wire type: TABLE 0x02).
    Map(BTreeMap<String, IscValue>),
}

/// An ISC binary message -- a collection of key-value pairs.
///
/// This is the top-level message structure exchanged over the rndc TCP channel.
/// Each message is framed with a 4-byte big-endian length prefix on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IscMessage {
    /// The key-value pairs in the message.
    ///
    /// Uses `BTreeMap` for deterministic serialization order.
    pub(crate) data: BTreeMap<String, IscValue>,
}

impl IscMessage {
    /// Create a new empty ISC message.
    pub(crate) fn new() -> Self {
        IscMessage {
            data: BTreeMap::new(),
        }
    }

    /// Insert a string value.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn insert_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), IscValue::String(value.into()));
    }

    /// Insert a raw binary value.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn insert_binary(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.data.insert(key.into(), IscValue::Binary(value));
    }

    /// Insert a nested map value.
    pub(crate) fn insert_map(&mut self, key: impl Into<String>, value: BTreeMap<String, IscValue>) {
        self.data.insert(key.into(), IscValue::Map(value));
    }

    /// Get a string value by key.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn get_string(&self, key: &str) -> Option<&str> {
        match self.data.get(key) {
            Some(IscValue::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get a raw binary value by key.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn get_binary(&self, key: &str) -> Option<&[u8]> {
        match self.data.get(key) {
            Some(IscValue::Binary(b)) => Some(b),
            _ => None,
        }
    }

    /// Get a nested map by key.
    pub(crate) fn get_map(&self, key: &str) -> Option<&BTreeMap<String, IscValue>> {
        match self.data.get(key) {
            Some(IscValue::Map(m)) => Some(m),
            _ => None,
        }
    }

    /// Encode this message to ISC binary format with version header.
    ///
    /// The output does NOT include the 4-byte framing length prefix -- that is
    /// added by [`frame_message`].
    ///
    /// Returns: `[4-byte version][encoded table entries]`
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NetError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ISC_MSG_VERSION.to_be_bytes());
        Self::encode_map(&self.data, &mut buf)?;
        Ok(buf)
    }

    /// Encode just the table entries without the version header.
    ///
    /// Used for computing HMAC signatures: the HMAC covers the serialized
    /// table entries (excluding `_auth`) but NOT the version header.
    pub(crate) fn encode_body(&self) -> Result<Vec<u8>, NetError> {
        let mut buf = Vec::new();
        Self::encode_map(&self.data, &mut buf)?;
        Ok(buf)
    }

    /// Decode an ISC message from binary format.
    ///
    /// The input must NOT include the 4-byte framing length prefix.
    pub(crate) fn decode(data: &[u8]) -> Result<Self, NetError> {
        if data.len() < 4 {
            return Err(NetError::Protocol("ISC message too short".into()));
        }
        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if version != ISC_MSG_VERSION {
            return Err(NetError::Protocol(format!(
                "unsupported ISC message version: {version}"
            )));
        }
        let mut pos = 4;
        let map = Self::decode_map(data, &mut pos, 0)?;
        Ok(IscMessage { data: map })
    }

    fn encode_map(map: &BTreeMap<String, IscValue>, buf: &mut Vec<u8>) -> Result<(), NetError> {
        for (key, value) in map {
            // Key: 1-byte length + key bytes
            let key_bytes = key.as_bytes();
            let key_len = u8::try_from(key_bytes.len()).map_err(|_| {
                NetError::Protocol(format!(
                    "ISC message key exceeds 255 bytes: {} bytes",
                    key_bytes.len()
                ))
            })?;
            buf.push(key_len);
            buf.extend_from_slice(key_bytes);

            // Type tag + 4-byte BE value length + value bytes
            match value {
                IscValue::String(s) => {
                    buf.push(ISCCC_TYPE_BINARY);
                    let val_bytes = s.as_bytes();
                    let val_len = u32::try_from(val_bytes.len()).map_err(|_| {
                        NetError::Protocol(format!(
                            "ISC string value exceeds 4GB: {} bytes",
                            val_bytes.len()
                        ))
                    })?;
                    buf.extend_from_slice(&val_len.to_be_bytes());
                    buf.extend_from_slice(val_bytes);
                }
                IscValue::Binary(b) => {
                    buf.push(ISCCC_TYPE_BINARY);
                    let val_len = u32::try_from(b.len()).map_err(|_| {
                        NetError::Protocol(format!(
                            "ISC binary value exceeds 4GB: {} bytes",
                            b.len()
                        ))
                    })?;
                    buf.extend_from_slice(&val_len.to_be_bytes());
                    buf.extend_from_slice(b);
                }
                IscValue::Map(m) => {
                    buf.push(ISCCC_TYPE_TABLE);
                    // Encode the nested map into a temporary buffer to get its length
                    let mut nested = Vec::new();
                    Self::encode_map(m, &mut nested)?;
                    let nested_len = u32::try_from(nested.len()).map_err(|_| {
                        NetError::Protocol(format!(
                            "ISC nested map exceeds 4GB: {} bytes",
                            nested.len()
                        ))
                    })?;
                    buf.extend_from_slice(&nested_len.to_be_bytes());
                    buf.extend_from_slice(&nested);
                }
            }
        }
        Ok(())
    }

    fn decode_map(
        data: &[u8],
        pos: &mut usize,
        depth: usize,
    ) -> Result<BTreeMap<String, IscValue>, NetError> {
        if depth > MAX_DECODE_DEPTH {
            return Err(NetError::Protocol(format!(
                "ISC message exceeds maximum nesting depth ({MAX_DECODE_DEPTH})"
            )));
        }
        let mut map = BTreeMap::new();
        while *pos < data.len() {
            // Key length (1 byte)
            if *pos >= data.len() {
                break;
            }
            let key_len = data[*pos] as usize;
            *pos += 1;

            // Key bytes
            if *pos + key_len > data.len() {
                return Err(NetError::Protocol(format!(
                    "ISC message truncated: expected {key_len} key bytes at offset {}",
                    *pos
                )));
            }
            let key = String::from_utf8(data[*pos..*pos + key_len].to_vec()).map_err(|e| {
                NetError::Protocol(format!("ISC message key is not valid UTF-8: {e}"))
            })?;
            *pos += key_len;

            // Type tag (1 byte)
            if *pos >= data.len() {
                return Err(NetError::Protocol(
                    "ISC message truncated: missing type tag".into(),
                ));
            }
            let type_tag = data[*pos];
            *pos += 1;

            // Value length (4 bytes BE)
            if *pos + 4 > data.len() {
                return Err(NetError::Protocol(
                    "ISC message truncated: missing value length".into(),
                ));
            }
            let val_len =
                u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                    as usize;
            *pos += 4;

            if *pos + val_len > data.len() {
                return Err(NetError::Protocol(format!(
                    "ISC message truncated: expected {val_len} value bytes at offset {}",
                    *pos
                )));
            }

            let value = match type_tag {
                ISCCC_TYPE_BINARY => {
                    let raw = data[*pos..*pos + val_len].to_vec();
                    *pos += val_len;
                    // Try UTF-8; if valid, store as String for convenience.
                    // HMAC auth values contain non-UTF-8 bytes and become Binary.
                    match String::from_utf8(raw) {
                        Ok(s) => IscValue::String(s),
                        Err(e) => IscValue::Binary(e.into_bytes()),
                    }
                }
                ISCCC_TYPE_TABLE => {
                    let end = *pos + val_len;
                    let mut nested_pos = *pos;
                    let nested_map = Self::decode_map(&data[..end], &mut nested_pos, depth + 1)?;
                    *pos = end;
                    IscValue::Map(nested_map)
                }
                other => {
                    return Err(NetError::Protocol(format!(
                        "ISC message: unknown type tag 0x{other:02x}"
                    )));
                }
            };

            map.insert(key, value);
        }
        Ok(map)
    }
}

/// Encode an ISC message with the 4-byte big-endian length prefix for TCP framing.
///
/// The rndc protocol uses 4-byte length prefixes, NOT the 2-byte DNS TCP length.
/// This is the most common rndc client implementation bug.
pub(crate) fn frame_message(msg: &IscMessage) -> Result<Vec<u8>, NetError> {
    let payload = msg.encode()?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        NetError::Protocol(format!("ISC message exceeds 4GB: {} bytes", payload.len()))
    })?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Extract the payload length from a 4-byte big-endian length prefix.
///
/// Returns the expected payload size. The caller must then read exactly
/// that many bytes from the TCP stream.
pub(crate) fn read_frame_length(header: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*header)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Accessor tests --

    #[test]
    fn isc_message_new_is_empty() {
        let msg = IscMessage::new();
        assert!(msg.data.is_empty());
    }

    #[test]
    fn isc_message_insert_and_get_string() {
        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        assert_eq!(msg.get_string("_ctrl"), Some("command"));
        assert_eq!(msg.get_string("missing"), None);
    }

    #[test]
    fn isc_message_insert_and_get_binary() {
        let mut msg = IscMessage::new();
        msg.insert_binary("hmac", vec![0xA3, 0x01, 0x02]);
        assert_eq!(msg.get_binary("hmac"), Some([0xA3, 0x01, 0x02].as_slice()));
        assert_eq!(msg.get_binary("missing"), None);
    }

    #[test]
    fn isc_message_insert_and_get_map() {
        let mut msg = IscMessage::new();
        let mut nested = BTreeMap::new();
        nested.insert("key".to_string(), IscValue::String("value".to_string()));
        msg.insert_map("_data", nested.clone());
        assert_eq!(msg.get_map("_data"), Some(&nested));
        assert_eq!(msg.get_map("missing"), None);
    }

    #[test]
    fn isc_message_get_string_returns_none_for_map_value() {
        let mut msg = IscMessage::new();
        msg.insert_map("nested", BTreeMap::new());
        assert_eq!(msg.get_string("nested"), None);
    }

    #[test]
    fn isc_message_get_map_returns_none_for_string_value() {
        let mut msg = IscMessage::new();
        msg.insert_string("text", "hello");
        assert_eq!(msg.get_map("text"), None);
    }

    // -- Roundtrip tests --

    #[test]
    fn isc_message_encode_decode_roundtrip_empty() {
        let msg = IscMessage::new();
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_single_string() {
        let mut msg = IscMessage::new();
        msg.insert_string("type", "command");
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_multiple_strings() {
        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        msg.insert_string("_data", "status");
        msg.insert_string("_nonce", "abc123");
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_nested_map() {
        let mut msg = IscMessage::new();
        let mut nested = BTreeMap::new();
        nested.insert(
            "command".to_string(),
            IscValue::String("status".to_string()),
        );
        nested.insert("args".to_string(), IscValue::String(String::new()));
        msg.insert_map("_data", nested);
        msg.insert_string("_ctrl", "command");
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_deeply_nested() {
        let mut msg = IscMessage::new();
        let mut inner = BTreeMap::new();
        inner.insert(
            "zone".to_string(),
            IscValue::String("example.com.".to_string()),
        );
        let mut outer = BTreeMap::new();
        outer.insert("reload".to_string(), IscValue::Map(inner));
        msg.insert_map("_data", outer);
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_starts_with_version() {
        let msg = IscMessage::new();
        let encoded = msg.encode().unwrap();
        assert_eq!(&encoded[..4], &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn encode_body_omits_version_header() {
        let mut msg = IscMessage::new();
        msg.insert_string("key", "value");
        let full = msg.encode().unwrap();
        let body = msg.encode_body().unwrap();
        // Full = version(4) + body
        assert_eq!(full.len(), 4 + body.len());
        assert_eq!(&full[4..], &body);
    }

    #[test]
    fn isc_message_encode_empty_string_value() {
        let mut msg = IscMessage::new();
        msg.insert_string("key", "");
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.get_string("key"), Some(""));
    }

    #[test]
    fn binary_value_roundtrip_non_utf8() {
        let mut msg = IscMessage::new();
        let raw = vec![0xA3, 0x01, 0xFF, 0x00];
        msg.insert_binary("hmac", raw.clone());
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        // Non-UTF-8 binary data decodes as Binary variant
        assert_eq!(decoded.get_binary("hmac"), Some(raw.as_slice()));
    }

    #[test]
    fn string_type_tag_is_0x01() {
        let mut msg = IscMessage::new();
        msg.insert_string("k", "v");
        let body = msg.encode_body().unwrap();
        // body: [1-byte key_len=1] [key='k'] [type_tag] [4-byte val_len] [val='v']
        assert_eq!(body[0], 1); // key length
        assert_eq!(body[1], b'k'); // key
        assert_eq!(body[2], 0x01); // type tag = BINARY
    }

    #[test]
    fn map_type_tag_is_0x02() {
        let mut msg = IscMessage::new();
        msg.insert_map("m", BTreeMap::new());
        let body = msg.encode_body().unwrap();
        assert_eq!(body[0], 1); // key length
        assert_eq!(body[1], b'm'); // key
        assert_eq!(body[2], 0x02); // type tag = TABLE
    }

    // -- Error case tests --

    #[test]
    fn isc_message_decode_too_short() {
        let result = IscMessage::decode(&[0x00, 0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too short"),
            "expected 'too short', got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_wrong_version() {
        let data = [0x00, 0x00, 0x00, 0x99];
        let result = IscMessage::decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("version"),
            "expected 'version' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_truncated_key() {
        let mut data = vec![0x00, 0x00, 0x00, 0x01];
        data.push(10);
        data.extend_from_slice(b"ab");
        let result = IscMessage::decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("truncated"),
            "expected 'truncated' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_truncated_value() {
        let mut data = vec![0x00, 0x00, 0x00, 0x01];
        data.push(2);
        data.extend_from_slice(b"ab");
        data.push(ISCCC_TYPE_BINARY);
        data.extend_from_slice(&100u32.to_be_bytes());
        let result = IscMessage::decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("truncated"),
            "expected 'truncated' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_unknown_type_tag() {
        let mut data = vec![0x00, 0x00, 0x00, 0x01];
        data.push(1);
        data.push(b'k');
        data.push(0xFF);
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(b"test");
        let result = IscMessage::decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown type tag"),
            "expected 'unknown type tag' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_encode_key_too_long() {
        let mut msg = IscMessage::new();
        let long_key = "k".repeat(256);
        msg.insert_string(&long_key, "value");
        let result = msg.encode();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds 255 bytes"),
            "expected 'exceeds 255 bytes' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_depth_limit() {
        fn build_nested(depth: usize) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(1);
            buf.push(b'k');
            if depth == 0 {
                buf.push(ISCCC_TYPE_BINARY);
                let val = b"leaf";
                buf.extend_from_slice(&(val.len() as u32).to_be_bytes());
                buf.extend_from_slice(val);
            } else {
                buf.push(ISCCC_TYPE_TABLE);
                let nested = build_nested(depth - 1);
                buf.extend_from_slice(&(nested.len() as u32).to_be_bytes());
                buf.extend_from_slice(&nested);
            }
            buf
        }

        let mut msg_data = vec![0x00, 0x00, 0x00, 0x01]; // version
        msg_data.extend_from_slice(&build_nested(MAX_DECODE_DEPTH + 5));

        let result = IscMessage::decode(&msg_data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nesting depth"),
            "expected 'nesting depth' in error, got: {err}"
        );
    }

    #[test]
    fn isc_message_decode_valid_nesting_within_limit() {
        fn build_nested(depth: usize) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(1);
            buf.push(b'k');
            if depth == 0 {
                buf.push(ISCCC_TYPE_BINARY);
                let val = b"ok";
                buf.extend_from_slice(&(val.len() as u32).to_be_bytes());
                buf.extend_from_slice(val);
            } else {
                buf.push(ISCCC_TYPE_TABLE);
                let nested = build_nested(depth - 1);
                buf.extend_from_slice(&(nested.len() as u32).to_be_bytes());
                buf.extend_from_slice(&nested);
            }
            buf
        }

        let mut msg_data = vec![0x00, 0x00, 0x00, 0x01];
        msg_data.extend_from_slice(&build_nested(3));

        let result = IscMessage::decode(&msg_data);
        assert!(result.is_ok(), "3-level nesting should succeed");
    }

    // -- Framing tests --

    #[test]
    fn frame_message_prepends_length() {
        let mut msg = IscMessage::new();
        msg.insert_string("cmd", "status");
        let frame = frame_message(&msg).unwrap();
        let payload_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(payload_len as usize, frame.len() - 4);
        let decoded = IscMessage::decode(&frame[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn frame_message_empty_message() {
        let msg = IscMessage::new();
        let frame = frame_message(&msg).unwrap();
        let payload_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(payload_len, 4);
    }

    #[test]
    fn read_frame_length_extracts_correctly() {
        let header: [u8; 4] = [0x00, 0x00, 0x01, 0x00];
        assert_eq!(read_frame_length(&header), 256);
    }

    #[test]
    fn read_frame_length_zero() {
        let header: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_frame_length(&header), 0);
    }

    #[test]
    fn read_frame_length_max() {
        let header: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_frame_length(&header), u32::MAX);
    }

    #[test]
    fn frame_roundtrip_with_nested_message() {
        let mut msg = IscMessage::new();
        let mut data = BTreeMap::new();
        data.insert(
            "zone".to_string(),
            IscValue::String("example.com.".to_string()),
        );
        msg.insert_map("_data", data);
        msg.insert_string("_ctrl", "command");

        let frame = frame_message(&msg).unwrap();
        let payload_len = read_frame_length(&<[u8; 4]>::try_from(&frame[..4]).unwrap());
        let decoded = IscMessage::decode(&frame[4..4 + payload_len as usize]).unwrap();
        assert_eq!(decoded, msg);
    }
}
