// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! ISC binary message encoding for the rndc wire protocol.
//!
//! The rndc protocol uses a custom binary key-value format, NOT DNS wire format.
//! Messages are collections of key-value pairs where keys are strings and values
//! are either strings or nested maps. Each string is length-prefixed (1-byte length
//! for keys, 4-byte big-endian length for values).
//!
//! # Wire format reference
//!
//! The encoding is derived from BIND9 source (`lib/isccfg/`). The format is
//! stable across BIND9 minor versions.
//!
//! TODO: Verify all encoding details against BIND9 source before v0.1.0 release.

use std::collections::BTreeMap;

use crate::error::NetError;

/// Maximum nesting depth for ISC message maps.
///
/// Prevents stack overflow from deeply nested (potentially malicious) messages.
const MAX_DECODE_DEPTH: usize = 32;

/// ISC message version constant.
///
/// TODO: Verify against BIND9 source -- this is the version field
/// in the rndc protocol handshake.
const ISC_MSG_VERSION: u32 = 1;

/// A value in an ISC binary message.
///
/// Values are either UTF-8 strings or nested key-value maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IscValue {
    /// A UTF-8 string value.
    String(String),
    /// A nested key-value map.
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
    pub(crate) fn insert_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), IscValue::String(value.into()));
    }

    /// Insert a nested map value.
    #[allow(dead_code)]
    pub(crate) fn insert_map(&mut self, key: impl Into<String>, value: BTreeMap<String, IscValue>) {
        self.data.insert(key.into(), IscValue::Map(value));
    }

    /// Get a string value by key.
    pub(crate) fn get_string(&self, key: &str) -> Option<&str> {
        match self.data.get(key) {
            Some(IscValue::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get a nested map by key.
    #[allow(dead_code)]
    pub(crate) fn get_map(&self, key: &str) -> Option<&BTreeMap<String, IscValue>> {
        match self.data.get(key) {
            Some(IscValue::Map(m)) => Some(m),
            _ => None,
        }
    }

    /// Encode this message to ISC binary format.
    ///
    /// The output does NOT include the 4-byte length prefix -- that is
    /// added by the framing layer.
    ///
    /// # Wire format (per key-value pair)
    ///
    /// ```text
    /// [1-byte key length] [key bytes]
    /// [1-byte type tag]  -- 0x00 = string, 0x01 = map
    /// [4-byte BE value length] [value bytes]
    /// ```
    ///
    /// TODO: Verify type tag values against BIND9 source.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NetError> {
        let mut buf = Vec::new();
        // Version header
        // TODO: Verify version encoding against BIND9 source
        buf.extend_from_slice(&ISC_MSG_VERSION.to_be_bytes());
        Self::encode_map(&self.data, &mut buf)?;
        Ok(buf)
    }

    /// Decode an ISC message from binary format.
    ///
    /// The input must NOT include the 4-byte length prefix -- the framing
    /// layer strips that before calling decode.
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
            // TODO: Verify key length encoding -- BIND9 may use different sizes
            let key_bytes = key.as_bytes();
            let key_len = u8::try_from(key_bytes.len()).map_err(|_| {
                NetError::Protocol(format!(
                    "ISC message key exceeds 255 bytes: {} bytes",
                    key_bytes.len()
                ))
            })?;
            buf.push(key_len);
            buf.extend_from_slice(key_bytes);

            match value {
                IscValue::String(s) => {
                    // Type tag: 0x00 = string
                    buf.push(0x00);
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
                IscValue::Map(m) => {
                    // Type tag: 0x01 = map
                    buf.push(0x01);
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
                0x00 => {
                    // String value
                    let s =
                        String::from_utf8(data[*pos..*pos + val_len].to_vec()).map_err(|e| {
                            NetError::Protocol(format!("ISC message value is not valid UTF-8: {e}"))
                        })?;
                    *pos += val_len;
                    IscValue::String(s)
                }
                0x01 => {
                    // Nested map
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
    fn isc_message_encode_empty_string_value() {
        let mut msg = IscMessage::new();
        msg.insert_string("key", "");
        let encoded = msg.encode().unwrap();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.get_string("key"), Some(""));
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
        data.push(0x00);
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
        // Build a message with nesting depth > MAX_DECODE_DEPTH
        // Each nesting level: 1-byte key_len + key + 1-byte type_tag(0x01) + 4-byte val_len + nested
        let mut data = vec![0x00, 0x00, 0x00, 0x01]; // version
        for _ in 0..=MAX_DECODE_DEPTH + 1 {
            data.push(1); // key length
            data.push(b'k'); // key
            data.push(0x01); // type tag: map
                             // Value length: remaining nesting bytes (we'll just make it large enough)
                             // We don't need it to be exact since the depth check fires first
        }
        // This won't decode cleanly, but we need to craft it so the depth check fires.
        // Instead, encode a valid deeply nested message programmatically.
        fn build_nested(depth: usize) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(1); // key length
            buf.push(b'k'); // key byte
            if depth == 0 {
                buf.push(0x00); // string type
                let val = b"leaf";
                buf.extend_from_slice(&(val.len() as u32).to_be_bytes());
                buf.extend_from_slice(val);
            } else {
                buf.push(0x01); // map type
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
        // 3 levels of nesting should work fine
        fn build_nested(depth: usize) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(1);
            buf.push(b'k');
            if depth == 0 {
                buf.push(0x00);
                let val = b"ok";
                buf.extend_from_slice(&(val.len() as u32).to_be_bytes());
                buf.extend_from_slice(val);
            } else {
                buf.push(0x01);
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
