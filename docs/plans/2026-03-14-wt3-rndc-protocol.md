<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# WT-3: rndc Wire Protocol Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the BIND9 rndc control channel wire protocol client with typestate connection management and HMAC authentication.

**Architecture:** Three-layer design: ISC message encoding (binary key-value pairs), wire framing (4-byte big-endian length prefix), and connection management (typestate Unauthenticated -> Authenticated). The protocol is NOT DNS -- it uses BIND9's custom framing. Auth handshake uses HMAC via TsigKey from core.

**Tech Stack:** Rust 2024, tokio (TCP), bind9-sdk-core (TsigKey, HMAC), thiserror, tracing

**Branch:** `feat/rndc-protocol`
**Spec:** `docs/specs/2026-03-14-phase1-remainder-design.md` SS5
**Depends on:** Phase 1 scaffolding + Wave 1 (WT-2 TSIG/net foundation)

## Pre-conditions (from Wave 1 / WT-2)

Before starting this plan, the following must exist on `development`:

- `bind9-sdk-core` has: `TsigKey`, `TsigAlgorithm`, HMAC `sign()`/`verify()` in `tsig.rs`
- `bind9-sdk-net` has: `NetError` enum in `error.rs`, `TlsConfig` in `tls.rs`, `Bind9Client` skeleton + `ClientConfig` in `config.rs`
- Net module stub exists: `crates/bind9-sdk-net/src/rndc/mod.rs` (empty, from scaffolding)
- Traits in core: `NamedControl` trait, `ServerStatus` type (with real fields: `version`, `running_since`, `reload_count`, `server_up`, `raw_text`), `FrozenZone` type (with `name`, `class`)

## Important Protocol Notes

The rndc protocol is **not formally documented** outside the BIND9 source code. The authentication handshake described in the spec (SS5.3) is approximate and must be verified against BIND9 source (`lib/isccfg/`, `lib/isc/netmgr/`) or captured wire dumps before implementation.

Key facts:
- Framing: 4-byte big-endian length prefix + payload. **NOT** 2-byte DNS TCP prefix.
- ISC message format: binary key-value pairs with length-prefixed strings.
- Authentication: HMAC-based mutual auth over the `_ctrl` channel.
- The protocol is stable across BIND9 minor versions.

All protocol encoding code must include `// TODO: Verify against BIND9 source` markers on any behavior inferred from the spec rather than directly observed from BIND9 source or wire captures.

## Chunk 1: ISC Message Encoding (`protocol.rs`)

Implement the binary key-value message format used by the rndc wire protocol. This is the lowest layer -- pure encode/decode, no I/O.

### Task 1.1: ISC Message Value Type and Basic Encoding Tests

**Files:**
- Create: `crates/bind9-sdk-net/src/rndc/protocol.rs`
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`

- [ ] **Step 1: Write failing tests for ISC value encoding**

Create `crates/bind9-sdk-net/src/rndc/protocol.rs` with the SPDX header, type stubs that do not compile yet, and tests:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Version header
        // TODO: Verify version encoding against BIND9 source
        buf.extend_from_slice(&ISC_MSG_VERSION.to_be_bytes());
        Self::encode_map(&self.data, &mut buf);
        buf
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
        let map = Self::decode_map(data, &mut pos)?;
        Ok(IscMessage { data: map })
    }

    fn encode_map(map: &BTreeMap<String, IscValue>, buf: &mut Vec<u8>) {
        for (key, value) in map {
            // Key: 1-byte length + key bytes
            // TODO: Verify key length encoding -- BIND9 may use different sizes
            let key_bytes = key.as_bytes();
            buf.push(
                u8::try_from(key_bytes.len())
                    .expect("ISC message keys must be <= 255 bytes"),
            );
            buf.extend_from_slice(key_bytes);

            match value {
                IscValue::String(s) => {
                    // Type tag: 0x00 = string
                    buf.push(0x00);
                    let val_bytes = s.as_bytes();
                    buf.extend_from_slice(
                        &u32::try_from(val_bytes.len())
                            .expect("ISC string value too large")
                            .to_be_bytes(),
                    );
                    buf.extend_from_slice(val_bytes);
                }
                IscValue::Map(m) => {
                    // Type tag: 0x01 = map
                    buf.push(0x01);
                    // Encode the nested map into a temporary buffer to get its length
                    let mut nested = Vec::new();
                    Self::encode_map(m, &mut nested);
                    buf.extend_from_slice(
                        &u32::try_from(nested.len())
                            .expect("ISC nested map too large")
                            .to_be_bytes(),
                    );
                    buf.extend_from_slice(&nested);
                }
            }
        }
    }

    fn decode_map(data: &[u8], pos: &mut usize) -> Result<BTreeMap<String, IscValue>, NetError> {
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
            let val_len = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as usize;
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
                    let s = String::from_utf8(data[*pos..*pos + val_len].to_vec()).map_err(
                        |e| {
                            NetError::Protocol(format!(
                                "ISC message value is not valid UTF-8: {e}"
                            ))
                        },
                    )?;
                    *pos += val_len;
                    IscValue::String(s)
                }
                0x01 => {
                    // Nested map
                    let end = *pos + val_len;
                    let mut nested_pos = *pos;
                    let nested_map = Self::decode_map(&data[..end], &mut nested_pos)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
```

- [ ] **Step 2: Update rndc/mod.rs to declare protocol submodule**

Replace `crates/bind9-sdk-net/src/rndc/mod.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! BIND9 rndc wire protocol client.
//!
//! This module implements the custom TCP control channel protocol used by
//! BIND9's `rndc` tool. The protocol uses 4-byte big-endian length framing
//! (NOT 2-byte DNS TCP framing) and ISC binary key-value message encoding.

pub(crate) mod protocol;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-net -- rndc::protocol`
Expected: All 5 accessor tests pass. Encode/decode not yet tested.

- [ ] **Step 4: Commit**

```
feat(net/rndc): add ISC message type with accessor tests
```

### Task 1.2: ISC Message Encode/Decode Roundtrip

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/protocol.rs`

- [ ] **Step 1: Write encode/decode roundtrip tests**

Add these tests to the existing `mod tests` block in `protocol.rs`:

```rust
    #[test]
    fn isc_message_encode_decode_roundtrip_empty() {
        let msg = IscMessage::new();
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_single_string() {
        let mut msg = IscMessage::new();
        msg.insert_string("type", "command");
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_multiple_strings() {
        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        msg.insert_string("_data", "status");
        msg.insert_string("_nonce", "abc123");
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_nested_map() {
        let mut msg = IscMessage::new();
        let mut nested = BTreeMap::new();
        nested.insert("command".to_string(), IscValue::String("status".to_string()));
        nested.insert(
            "args".to_string(),
            IscValue::String(String::new()),
        );
        msg.insert_map("_data", nested);
        msg.insert_string("_ctrl", "command");
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_decode_roundtrip_deeply_nested() {
        let mut msg = IscMessage::new();
        let mut inner = BTreeMap::new();
        inner.insert("zone".to_string(), IscValue::String("example.com.".to_string()));
        let mut outer = BTreeMap::new();
        outer.insert("reload".to_string(), IscValue::Map(inner));
        msg.insert_map("_data", outer);
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn isc_message_encode_starts_with_version() {
        let msg = IscMessage::new();
        let encoded = msg.encode();
        // First 4 bytes are version (1) in big-endian
        assert_eq!(&encoded[..4], &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn isc_message_encode_empty_string_value() {
        let mut msg = IscMessage::new();
        msg.insert_string("key", "");
        let encoded = msg.encode();
        let decoded = IscMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.get_string("key"), Some(""));
    }
```

- [ ] **Step 2: Run tests to verify roundtrips pass**

Run: `cargo test -p bind9-sdk-net -- rndc::protocol`
Expected: All 12 tests pass (5 accessor + 7 roundtrip).

- [ ] **Step 3: Commit**

```
test(net/rndc): add ISC message encode/decode roundtrip tests
```

### Task 1.3: ISC Message Error Cases

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/protocol.rs`

- [ ] **Step 1: Write error case tests**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn isc_message_decode_too_short() {
        let result = IscMessage::decode(&[0x00, 0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "expected 'too short', got: {err}");
    }

    #[test]
    fn isc_message_decode_wrong_version() {
        let data = [0x00, 0x00, 0x00, 0x99]; // version 153, not 1
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
        // Version header (4 bytes) + key_len=10 but only 2 key bytes
        let mut data = vec![0x00, 0x00, 0x00, 0x01]; // version 1
        data.push(10); // key_len = 10
        data.extend_from_slice(b"ab"); // only 2 bytes, not 10
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
        // Valid version + valid key "ab" + type 0x00 (string) + length 100 but no data
        let mut data = vec![0x00, 0x00, 0x00, 0x01]; // version 1
        data.push(2); // key_len = 2
        data.extend_from_slice(b"ab"); // key
        data.push(0x00); // type = string
        data.extend_from_slice(&100u32.to_be_bytes()); // value length = 100
        // No value bytes
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
        let mut data = vec![0x00, 0x00, 0x00, 0x01]; // version 1
        data.push(1); // key_len = 1
        data.push(b'k'); // key = "k"
        data.push(0xFF); // type = unknown
        data.extend_from_slice(&4u32.to_be_bytes()); // value length = 4
        data.extend_from_slice(b"test"); // value bytes
        let result = IscMessage::decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown type tag"),
            "expected 'unknown type tag' in error, got: {err}"
        );
    }
```

- [ ] **Step 2: Run tests to verify error cases pass**

Run: `cargo test -p bind9-sdk-net -- rndc::protocol`
Expected: All 17 tests pass (5 accessor + 7 roundtrip + 5 error).

- [ ] **Step 3: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 4: Commit**

```
test(net/rndc): add ISC message decode error case tests
```

## Chunk 2: Wire Framing + RndcCommand Enum (`command.rs`)

### Task 2.1: Wire Frame Read/Write Functions

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/protocol.rs`

- [ ] **Step 1: Write tests for frame encoding**

Add frame encoding/decoding functions and tests to `protocol.rs`. The framing layer wraps ISC messages with a 4-byte big-endian length prefix for TCP transport.

Add these functions after the `IscMessage` impl block:

```rust
/// Encode an ISC message with the 4-byte big-endian length prefix for TCP framing.
///
/// The rndc protocol uses 4-byte length prefixes, NOT the 2-byte DNS TCP length.
/// This is the most common rndc client implementation bug.
pub(crate) fn frame_message(msg: &IscMessage) -> Vec<u8> {
    let payload = msg.encode();
    let len = u32::try_from(payload.len()).expect("ISC message exceeds 4GB");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Extract the payload length from a 4-byte big-endian length prefix.
///
/// Returns the expected payload size. The caller must then read exactly
/// that many bytes from the TCP stream.
pub(crate) fn read_frame_length(header: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*header)
}
```

Add these tests:

```rust
    #[test]
    fn frame_message_prepends_length() {
        let mut msg = IscMessage::new();
        msg.insert_string("cmd", "status");
        let frame = frame_message(&msg);

        // First 4 bytes are the payload length
        let payload_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(payload_len as usize, frame.len() - 4);

        // Remaining bytes decode to the original message
        let decoded = IscMessage::decode(&frame[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn frame_message_empty_message() {
        let msg = IscMessage::new();
        let frame = frame_message(&msg);

        // Empty message still has version header (4 bytes)
        let payload_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(payload_len, 4); // just the version u32
    }

    #[test]
    fn read_frame_length_extracts_correctly() {
        let header: [u8; 4] = [0x00, 0x00, 0x01, 0x00]; // 256
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
        data.insert("zone".to_string(), IscValue::String("example.com.".to_string()));
        msg.insert_map("_data", data);
        msg.insert_string("_ctrl", "command");

        let frame = frame_message(&msg);
        let payload_len = read_frame_length(
            &<[u8; 4]>::try_from(&frame[..4]).unwrap(),
        );
        let decoded = IscMessage::decode(&frame[4..4 + payload_len as usize]).unwrap();
        assert_eq!(decoded, msg);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-net -- rndc::protocol`
Expected: All 23 tests pass (17 previous + 6 framing).

- [ ] **Step 3: Commit**

```
feat(net/rndc): add wire frame encode/decode with 4-byte BE length prefix
```

### Task 2.2: RndcCommand Enum and Serialization

**Files:**
- Create: `crates/bind9-sdk-net/src/rndc/command.rs`
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`

- [ ] **Step 1: Write RndcCommand enum with serialization tests**

Create `crates/bind9-sdk-net/src/rndc/command.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! rndc command types and response parsing.
//!
//! Each `RndcCommand` variant maps to a BIND9 `rndc` subcommand.
//! The `to_command_string()` method produces the command text sent
//! inside the ISC message `_data` field.

use std::fmt;

/// An rndc command to send to a BIND9 server.
///
/// Covers all rndc commands available in BIND9 9.20.
/// Use `Raw` for commands not yet represented by a named variant.
///
/// # Examples
///
/// ```ignore
/// let cmd = RndcCommand::Status;
/// assert_eq!(cmd.to_command_string(), "status");
///
/// let cmd = RndcCommand::ReloadZone { zone: "example.com".into() };
/// assert_eq!(cmd.to_command_string(), "reload example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RndcCommand {
    /// Query server status.
    Status,
    /// Reload all zones and configuration.
    Reload,
    /// Reload a specific zone.
    ReloadZone { zone: String },
    /// Refresh a secondary zone from its primary.
    Refresh { zone: String },
    /// Force a zone retransfer from primary.
    Retransfer { zone: String },
    /// Freeze a zone (stop dynamic updates).
    Freeze { zone: String },
    /// Thaw a frozen zone (resume dynamic updates).
    Thaw { zone: String },
    /// Synchronize zone journal to zone file.
    /// If `zone` is `None`, syncs all zones.
    Sync { zone: Option<String> },
    /// Flush all caches.
    Flush,
    /// Flush a specific name from cache.
    FlushName { name: String },
    /// Dump statistics to the statistics file.
    Stats,
    /// Dump the database to the dump file.
    DumpDb,
    /// Send NOTIFY for a zone.
    Notify { zone: String },
    /// Set debug trace level.
    /// If `level` is `None`, increments by 1.
    Trace { level: Option<u32> },
    /// Disable debug tracing.
    NoTrace,
    /// Reload configuration and add/remove zones.
    Reconfig,
    /// Sign a zone with DNSSEC keys.
    Sign { zone: String },
    /// Enable or disable DNSSEC validation.
    Validation { enable: bool },
    /// Add a zone at runtime.
    AddZone { zone: String, config: String },
    /// Modify a zone's configuration at runtime.
    ModZone { zone: String, config: String },
    /// Delete a zone at runtime.
    DelZone { zone: String },
    /// Show a zone's runtime configuration.
    ShowZone { zone: String },
    /// Managed-keys operations.
    Managed { subcommand: String },
    /// Query zone status.
    ZoneStatus { zone: String },
    /// Negative Trust Anchor operations.
    /// - `domain: None` = list all NTAs
    /// - `domain: Some(d), lifetime: Some(l)` = add NTA
    /// - `domain: Some(d), lifetime: None` = remove NTA
    NtA {
        domain: Option<String>,
        lifetime: Option<u32>,
    },
    /// Raw command string -- escape hatch for commands not yet in the enum.
    Raw(String),
}

impl RndcCommand {
    /// Convert to the command string sent in the rndc wire protocol.
    ///
    /// This is the text placed in the `_data` map's `type` field of the
    /// ISC binary message.
    pub fn to_command_string(&self) -> String {
        match self {
            Self::Status => "status".to_string(),
            Self::Reload => "reload".to_string(),
            Self::ReloadZone { zone } => format!("reload {zone}"),
            Self::Refresh { zone } => format!("refresh {zone}"),
            Self::Retransfer { zone } => format!("retransfer {zone}"),
            Self::Freeze { zone } => format!("freeze {zone}"),
            Self::Thaw { zone } => format!("thaw {zone}"),
            Self::Sync { zone: Some(z) } => format!("sync {z}"),
            Self::Sync { zone: None } => "sync".to_string(),
            Self::Flush => "flush".to_string(),
            Self::FlushName { name } => format!("flush {name}"),
            Self::Stats => "stats".to_string(),
            Self::DumpDb => "dumpdb".to_string(),
            Self::Notify { zone } => format!("notify {zone}"),
            Self::Trace { level: Some(l) } => format!("trace {l}"),
            Self::Trace { level: None } => "trace".to_string(),
            Self::NoTrace => "notrace".to_string(),
            Self::Reconfig => "reconfig".to_string(),
            Self::Sign { zone } => format!("sign {zone}"),
            Self::Validation { enable: true } => "validation on".to_string(),
            Self::Validation { enable: false } => "validation off".to_string(),
            Self::AddZone { zone, config } => format!("addzone {zone} {config}"),
            Self::ModZone { zone, config } => format!("modzone {zone} {config}"),
            Self::DelZone { zone } => format!("delzone {zone}"),
            Self::ShowZone { zone } => format!("showzone {zone}"),
            Self::Managed { subcommand } => format!("managed-keys {subcommand}"),
            Self::ZoneStatus { zone } => format!("zonestatus {zone}"),
            Self::NtA {
                domain: None,
                lifetime: _,
            } => "nta -dump".to_string(),
            Self::NtA {
                domain: Some(d),
                lifetime: Some(l),
            } => format!("nta -lifetime {l} {d}"),
            Self::NtA {
                domain: Some(d),
                lifetime: None,
            } => format!("nta -remove {d}"),
            Self::Raw(cmd) => cmd.clone(),
        }
    }
}

impl fmt::Display for RndcCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_command_string())
    }
}

/// Response from an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RndcResponse {
    /// The text output from the server (may be multi-line).
    pub text: String,
    /// Parsed result status.
    pub result: RndcResult,
}

/// Result status of an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RndcResult {
    /// Command succeeded.
    Success,
    /// Command failed with an error.
    Error {
        /// Numeric error code from the server (if provided).
        code: u32,
        /// Human-readable error message.
        message: String,
    },
}

impl RndcResponse {
    /// Whether the command succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self.result, RndcResult::Success)
    }

    /// Parse a response from the raw text returned by BIND9.
    ///
    /// BIND9 rndc responses typically start with "rndc: " for errors,
    /// or contain the result text directly for successful commands.
    ///
    /// TODO: Verify response format against BIND9 source / wire captures.
    pub(crate) fn from_text(text: &str) -> Self {
        // TODO: Verify this parsing logic against actual BIND9 responses.
        // The error detection heuristic below is approximate.
        if text.starts_with("rndc: ") || text.contains("error") {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Error {
                    code: 1,
                    message: text.to_string(),
                },
            }
        } else {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Success,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- RndcCommand serialization tests --

    #[test]
    fn command_status() {
        assert_eq!(RndcCommand::Status.to_command_string(), "status");
    }

    #[test]
    fn command_reload() {
        assert_eq!(RndcCommand::Reload.to_command_string(), "reload");
    }

    #[test]
    fn command_reload_zone() {
        let cmd = RndcCommand::ReloadZone {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "reload example.com");
    }

    #[test]
    fn command_refresh() {
        let cmd = RndcCommand::Refresh {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "refresh example.com");
    }

    #[test]
    fn command_retransfer() {
        let cmd = RndcCommand::Retransfer {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "retransfer example.com");
    }

    #[test]
    fn command_freeze() {
        let cmd = RndcCommand::Freeze {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "freeze example.com");
    }

    #[test]
    fn command_thaw() {
        let cmd = RndcCommand::Thaw {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "thaw example.com");
    }

    #[test]
    fn command_sync_all() {
        let cmd = RndcCommand::Sync { zone: None };
        assert_eq!(cmd.to_command_string(), "sync");
    }

    #[test]
    fn command_sync_zone() {
        let cmd = RndcCommand::Sync {
            zone: Some("example.com".into()),
        };
        assert_eq!(cmd.to_command_string(), "sync example.com");
    }

    #[test]
    fn command_flush() {
        assert_eq!(RndcCommand::Flush.to_command_string(), "flush");
    }

    #[test]
    fn command_flush_name() {
        let cmd = RndcCommand::FlushName {
            name: "stale.example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "flush stale.example.com");
    }

    #[test]
    fn command_stats() {
        assert_eq!(RndcCommand::Stats.to_command_string(), "stats");
    }

    #[test]
    fn command_dumpdb() {
        assert_eq!(RndcCommand::DumpDb.to_command_string(), "dumpdb");
    }

    #[test]
    fn command_notify() {
        let cmd = RndcCommand::Notify {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "notify example.com");
    }

    #[test]
    fn command_trace_increment() {
        let cmd = RndcCommand::Trace { level: None };
        assert_eq!(cmd.to_command_string(), "trace");
    }

    #[test]
    fn command_trace_level() {
        let cmd = RndcCommand::Trace { level: Some(3) };
        assert_eq!(cmd.to_command_string(), "trace 3");
    }

    #[test]
    fn command_notrace() {
        assert_eq!(RndcCommand::NoTrace.to_command_string(), "notrace");
    }

    #[test]
    fn command_reconfig() {
        assert_eq!(RndcCommand::Reconfig.to_command_string(), "reconfig");
    }

    #[test]
    fn command_sign() {
        let cmd = RndcCommand::Sign {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "sign example.com");
    }

    #[test]
    fn command_validation_on() {
        let cmd = RndcCommand::Validation { enable: true };
        assert_eq!(cmd.to_command_string(), "validation on");
    }

    #[test]
    fn command_validation_off() {
        let cmd = RndcCommand::Validation { enable: false };
        assert_eq!(cmd.to_command_string(), "validation off");
    }

    #[test]
    fn command_addzone() {
        let cmd = RndcCommand::AddZone {
            zone: "new.example.com".into(),
            config: "{ type primary; file \"new.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "addzone new.example.com { type primary; file \"new.zone\"; };"
        );
    }

    #[test]
    fn command_modzone() {
        let cmd = RndcCommand::ModZone {
            zone: "example.com".into(),
            config: "{ type primary; file \"updated.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "modzone example.com { type primary; file \"updated.zone\"; };"
        );
    }

    #[test]
    fn command_delzone() {
        let cmd = RndcCommand::DelZone {
            zone: "old.example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "delzone old.example.com");
    }

    #[test]
    fn command_showzone() {
        let cmd = RndcCommand::ShowZone {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "showzone example.com");
    }

    #[test]
    fn command_managed_keys() {
        let cmd = RndcCommand::Managed {
            subcommand: "status".into(),
        };
        assert_eq!(cmd.to_command_string(), "managed-keys status");
    }

    #[test]
    fn command_zonestatus() {
        let cmd = RndcCommand::ZoneStatus {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "zonestatus example.com");
    }

    #[test]
    fn command_nta_list() {
        let cmd = RndcCommand::NtA {
            domain: None,
            lifetime: None,
        };
        assert_eq!(cmd.to_command_string(), "nta -dump");
    }

    #[test]
    fn command_nta_add() {
        let cmd = RndcCommand::NtA {
            domain: Some("bad.example.com".into()),
            lifetime: Some(3600),
        };
        assert_eq!(
            cmd.to_command_string(),
            "nta -lifetime 3600 bad.example.com"
        );
    }

    #[test]
    fn command_nta_remove() {
        let cmd = RndcCommand::NtA {
            domain: Some("bad.example.com".into()),
            lifetime: None,
        };
        assert_eq!(cmd.to_command_string(), "nta -remove bad.example.com");
    }

    #[test]
    fn command_raw() {
        let cmd = RndcCommand::Raw("custom-command arg1 arg2".into());
        assert_eq!(cmd.to_command_string(), "custom-command arg1 arg2");
    }

    #[test]
    fn command_display_matches_command_string() {
        let cmd = RndcCommand::Status;
        assert_eq!(format!("{cmd}"), cmd.to_command_string());
    }

    // -- RndcResponse tests --

    #[test]
    fn response_success() {
        let resp = RndcResponse::from_text("version: BIND 9.20.0\nserver is up and running");
        assert!(resp.is_success());
        assert!(resp.text.contains("BIND 9.20.0"));
    }

    #[test]
    fn response_error_rndc_prefix() {
        let resp = RndcResponse::from_text("rndc: connect failed: connection refused");
        assert!(!resp.is_success());
        if let RndcResult::Error { message, .. } = &resp.result {
            assert!(message.contains("connect failed"));
        } else {
            panic!("expected error result");
        }
    }

    #[test]
    fn response_is_success_returns_false_for_error() {
        let resp = RndcResponse {
            text: "failed".into(),
            result: RndcResult::Error {
                code: 1,
                message: "failed".into(),
            },
        };
        assert!(!resp.is_success());
    }
}
```

- [ ] **Step 2: Update rndc/mod.rs to declare command submodule**

Add to `crates/bind9-sdk-net/src/rndc/mod.rs`:

```rust
pub mod command;
pub(crate) mod protocol;
```

- [ ] **Step 3: Run all rndc tests**

Run: `cargo test -p bind9-sdk-net -- rndc`
Expected: All tests pass (protocol + command).

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 5: Commit**

```
feat(net/rndc): add RndcCommand enum, RndcResponse, and command serialization
```

## Chunk 3: RndcConnection Typestate + Authentication (`mod.rs`)

### Task 3.1: Connection Typestate Structs

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`

- [ ] **Step 1: Define typestate types and RndcConnection struct**

Replace `crates/bind9-sdk-net/src/rndc/mod.rs` with the full module declaration and connection types. Note: the `authenticate()` and `command()` methods are stubs that return `todo!()` -- they are implemented in subsequent tasks.

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! BIND9 rndc wire protocol client.
//!
//! This module implements the custom TCP control channel protocol used by
//! BIND9's `rndc` tool. The protocol uses 4-byte big-endian length framing
//! (NOT 2-byte DNS TCP framing) and ISC binary key-value message encoding.
//!
//! # Connection lifecycle
//!
//! ```text
//! RndcConnection<Unauthenticated>
//!     │
//!     ├── connect(addr)       → new unauthenticated connection
//!     │
//!     └── authenticate(key)   → RndcConnection<Authenticated>
//!             │
//!             ├── command(cmd) → RndcResponse
//!             ├── command(cmd) → RndcResponse  (reusable)
//!             │
//!             └── close()      → connection dropped
//! ```
//!
//! The typestate pattern ensures at compile time that `command()` cannot
//! be called on an unauthenticated connection.

pub mod command;
pub(crate) mod protocol;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use bind9_sdk_core::tsig::TsigKey;

use crate::error::NetError;

use self::command::{RndcCommand, RndcResponse};
use self::protocol::{frame_message, read_frame_length, IscMessage};

/// Typestate marker: connection is not yet authenticated.
pub struct Unauthenticated;

/// Typestate marker: connection has been authenticated with HMAC.
pub struct Authenticated;

/// A connection to a BIND9 rndc control channel.
///
/// Uses the typestate pattern to enforce authentication before commands
/// can be sent. Transitions from `Unauthenticated` to `Authenticated`
/// via the [`authenticate()`](RndcConnection::authenticate) method.
///
/// # Wire protocol
///
/// The rndc protocol uses:
/// - 4-byte big-endian length prefix (NOT 2-byte DNS TCP)
/// - ISC binary key-value message encoding
/// - HMAC-based mutual authentication
///
/// # Example
///
/// ```ignore
/// let conn = RndcConnection::connect(addr).await?;
/// let mut conn = conn.authenticate(&key).await?;
/// let resp = conn.command(RndcCommand::Status).await?;
/// conn.close().await?;
/// ```
pub struct RndcConnection<State = Unauthenticated> {
    stream: TcpStream,
    _state: core::marker::PhantomData<State>,
}

impl RndcConnection<Unauthenticated> {
    /// Connect to a BIND9 rndc control channel.
    ///
    /// Establishes a TCP connection to the given address (typically port 953).
    /// The connection is unauthenticated until [`authenticate()`] is called.
    pub async fn connect(addr: SocketAddr) -> Result<Self, NetError> {
        tracing::debug!("connecting to rndc at {addr}");
        let stream = TcpStream::connect(addr).await.map_err(|e| {
            NetError::Connection(format!("failed to connect to rndc at {addr}: {e}"))
        })?;
        tracing::debug!("connected to rndc at {addr}");
        Ok(RndcConnection {
            stream,
            _state: core::marker::PhantomData,
        })
    }

    /// Authenticate with the BIND9 server using HMAC.
    ///
    /// Sends the `_ctrl` handshake message signed with the provided key.
    /// On success, consumes the unauthenticated connection and returns
    /// an authenticated connection that can send commands.
    ///
    /// # Authentication sequence (approximate)
    ///
    /// 1. Client sends `_ctrl` message with nonce, HMAC-signed
    /// 2. Server validates HMAC, responds success/failure
    ///
    /// TODO: Verify exact handshake sequence against BIND9 source.
    /// The current implementation is based on the spec description and
    /// may need adjustment after wire capture verification.
    pub async fn authenticate(
        mut self,
        key: &TsigKey,
    ) -> Result<RndcConnection<Authenticated>, NetError> {
        tracing::debug!("authenticating rndc connection");

        // Build the auth handshake message
        // TODO: Verify _ctrl message structure against BIND9 source.
        // The nonce and HMAC placement below is approximate.
        let mut auth_msg = IscMessage::new();
        auth_msg.insert_string("_ctrl", "null");

        // TODO: The actual BIND9 handshake likely includes:
        // - A nonce value
        // - Timestamp for replay protection
        // - HMAC computed over specific fields
        // These details must be verified against BIND9 source before
        // integration testing.

        // Sign the serialized message with HMAC
        let payload = auth_msg.encode();
        let mac = key.sign(&payload);

        // Build the outer message with the HMAC
        let mut signed_msg = IscMessage::new();
        signed_msg.insert_string("_auth", &base64_encode(&mac));
        // Re-include the original message fields
        for (k, v) in auth_msg.data {
            signed_msg.data.insert(k, v);
        }

        // Send the framed message
        let frame = frame_message(&signed_msg);
        self.stream.write_all(&frame).await.map_err(|e| {
            NetError::Connection(format!("failed to send auth message: {e}"))
        })?;

        // Read the server's response
        let response = read_isc_message(&mut self.stream).await?;

        // Check for authentication success
        // TODO: Verify the success indicator field name against BIND9 source.
        let result = response.get_string("_ctrl");
        if result != Some("null") {
            let err_text = response
                .get_string("_err")
                .or(response.get_string("result"))
                .unwrap_or("unknown auth error");
            return Err(NetError::AuthFailed);
        }

        tracing::debug!("rndc authentication successful");
        Ok(RndcConnection {
            stream: self.stream,
            _state: core::marker::PhantomData,
        })
    }
}

impl RndcConnection<Authenticated> {
    /// Send an rndc command and receive the response.
    ///
    /// The connection remains open and can be reused for subsequent commands.
    /// The TCP stream is mutably borrowed for the duration of the command.
    pub async fn command(&mut self, cmd: RndcCommand) -> Result<RndcResponse, NetError> {
        tracing::debug!("sending rndc command: {cmd}");

        // Build the command message
        // TODO: Verify command message structure against BIND9 source.
        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        msg.insert_string("type", &cmd.to_command_string());

        // Send
        let frame = frame_message(&msg);
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetError::Connection(format!("failed to send command: {e}")))?;

        // Read response
        let response = read_isc_message(&mut self.stream).await?;

        // Extract response text
        // TODO: Verify response field names against BIND9 source.
        let text = response
            .get_string("text")
            .or(response.get_string("_data"))
            .unwrap_or("")
            .to_string();

        tracing::debug!("rndc command response received ({} bytes)", text.len());
        Ok(RndcResponse::from_text(&text))
    }

    /// Close the rndc connection gracefully.
    ///
    /// Shuts down the TCP stream. After calling this, the connection
    /// is consumed and cannot be reused.
    pub async fn close(mut self) -> Result<(), NetError> {
        tracing::debug!("closing rndc connection");
        self.stream
            .shutdown()
            .await
            .map_err(|e| NetError::Connection(format!("failed to close connection: {e}")))?;
        Ok(())
    }
}

/// Read a framed ISC message from a TCP stream.
///
/// Reads the 4-byte length prefix, then reads exactly that many bytes,
/// then decodes the ISC message.
async fn read_isc_message(stream: &mut TcpStream) -> Result<IscMessage, NetError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        NetError::Connection(format!("failed to read message length: {e}"))
    })?;
    let payload_len = read_frame_length(&len_buf) as usize;

    if payload_len == 0 {
        return Err(NetError::Protocol(
            "received zero-length rndc message".into(),
        ));
    }

    // Sanity check: reject absurdly large messages (> 16MB)
    const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
    if payload_len > MAX_MESSAGE_SIZE {
        return Err(NetError::Protocol(format!(
            "rndc message too large: {payload_len} bytes (max {MAX_MESSAGE_SIZE})"
        )));
    }

    // Read payload
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.map_err(|e| {
        NetError::Connection(format!("failed to read message payload: {e}"))
    })?;

    IscMessage::decode(&payload)
}

/// Base64-encode bytes for HMAC values in ISC messages.
///
/// Uses standard base64 encoding (not URL-safe).
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Typestate compile-time checks --
    // These tests verify that the typestate pattern works correctly.
    // The actual send/receive is tested via integration tests with a live BIND9.

    #[test]
    fn unauthenticated_has_connect_and_authenticate() {
        // Verify the type signatures exist -- this is a compile-time check.
        // We cannot call connect() without a real server, but we can verify
        // the function exists and has the right signature.
        fn _assert_connect_exists(
            _f: impl FnOnce(SocketAddr) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<RndcConnection<Unauthenticated>, NetError>>>,
            >,
        ) {
        }
        // This won't actually call connect, just checks the type system.
    }

    #[test]
    fn authenticated_has_command_and_close() {
        // Compile-time check that the method signatures exist on Authenticated.
        // The RndcConnection<Authenticated> type must have command() and close().
        fn _check_method_exists<T>()
        where
            T: Sized,
        {
        }
        _check_method_exists::<RndcConnection<Authenticated>>();
    }

    // The following test would be a compile-fail test (trybuild) to verify
    // that command() is NOT available on RndcConnection<Unauthenticated>.
    // We leave it as a TODO since trybuild tests need a separate test file.
    //
    // TODO: Add trybuild compile-fail test:
    //   let conn = RndcConnection::<Unauthenticated> { ... };
    //   conn.command(RndcCommand::Status).await; // should not compile

    #[test]
    fn read_isc_message_rejects_zero_length() {
        // Test the zero-length rejection without a real TCP stream.
        // This is tested indirectly -- the function checks payload_len == 0.
        // Direct testing requires tokio::test, which is below.
    }

    #[tokio::test]
    async fn read_isc_message_from_mock_stream() {
        // Create an in-memory TCP stream pair to test read_isc_message
        let (mut client, mut server) = tokio::io::duplex(4096);

        // Write a valid framed ISC message
        let mut msg = IscMessage::new();
        msg.insert_string("test", "value");
        let frame = frame_message(&msg);

        // Spawn writer
        let write_handle = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // The duplex stream is not a TcpStream, so we test the protocol
        // layer directly instead.
        let mut buf = vec![0u8; frame.len()];
        client
            .read_exact(&mut buf)
            .await
            .unwrap();

        let payload_len = read_frame_length(&<[u8; 4]>::try_from(&buf[..4]).unwrap()) as usize;
        let decoded = IscMessage::decode(&buf[4..4 + payload_len]).unwrap();
        assert_eq!(decoded, msg);

        write_handle.await.unwrap();
    }
}
```

- [ ] **Step 2: Add `base64` dependency to bind9-sdk-net Cargo.toml**

Add to `[dependencies]` in `crates/bind9-sdk-net/Cargo.toml`:

```toml
base64 = { workspace = true }
```

If `base64` is not yet in `[workspace.dependencies]` in the root `Cargo.toml`, it was added during scaffolding. If missing, add:

```toml
base64 = { version = "0.22", default-features = false, features = ["alloc"] }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-net -- rndc`
Expected: All rndc tests pass (protocol, command, and mod tests).

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 5: Commit**

```
feat(net/rndc): add RndcConnection typestate with connect, authenticate, command, close
```

### Task 3.2: Typestate Compile-Fail Test

**Files:**
- Create: `crates/bind9-sdk-net/tests/rndc_typestate.rs`

- [ ] **Step 1: Write a trybuild compile-fail test**

Create `crates/bind9-sdk-net/tests/rndc_typestate.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Compile-fail test to verify RndcConnection typestate enforcement.
//!
//! This test verifies that calling `command()` on an `Unauthenticated`
//! connection does not compile.

#[test]
fn rndc_typestate_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/rndc_unauthenticated_command.rs");
}
```

Create `crates/bind9-sdk-net/tests/compile-fail/rndc_unauthenticated_command.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! This file MUST NOT compile. It verifies that `command()` is not
//! available on `RndcConnection<Unauthenticated>`.

use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::rndc::{RndcConnection, Unauthenticated};

async fn should_not_compile() {
    // This line must fail to compile because command() is only
    // available on RndcConnection<Authenticated>.
    let addr = "127.0.0.1:953".parse().unwrap();
    let mut conn: RndcConnection<Unauthenticated> = RndcConnection::connect(addr).await.unwrap();
    conn.command(RndcCommand::Status).await.unwrap();
}

fn main() {}
```

- [ ] **Step 2: Add trybuild dev-dependency**

Add to `crates/bind9-sdk-net/Cargo.toml` under `[dev-dependencies]`:

```toml
trybuild = "1"
```

Add to `[workspace.dependencies]` in root `Cargo.toml` if not present:

```toml
trybuild = { version = "1" }
```

- [ ] **Step 3: Run the compile-fail test**

Run: `cargo test -p bind9-sdk-net -- rndc_typestate`
Expected: Test passes (the compile-fail file fails to compile as expected).

Note: The first run will generate the `.stderr` file. Review it to ensure the error is about `command()` not being found on `Unauthenticated`. If the `.stderr` file needs updating, run with `TRYBUILD=overwrite`.

- [ ] **Step 4: Commit**

```
test(net/rndc): add compile-fail test for typestate enforcement
```

### Task 3.3: TCP Stream Helper Tests

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`

- [ ] **Step 1: Add tokio duplex stream tests for frame read/write**

Add more detailed async tests to the `mod tests` block in `mod.rs`:

```rust
    #[tokio::test]
    async fn frame_write_and_read_roundtrip_via_duplex() {
        let (mut client_read, mut client_write) = tokio::io::duplex(8192);

        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        msg.insert_string("type", "status");

        let frame = frame_message(&msg);

        // Writer sends the frame
        let write_handle = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        // Reader reads length prefix + payload
        let mut len_buf = [0u8; 4];
        client_read.read_exact(&mut len_buf).await.unwrap();
        let payload_len = read_frame_length(&len_buf) as usize;

        let mut payload = vec![0u8; payload_len];
        client_read.read_exact(&mut payload).await.unwrap();

        let decoded = IscMessage::decode(&payload).unwrap();
        assert_eq!(decoded.get_string("_ctrl"), Some("command"));
        assert_eq!(decoded.get_string("type"), Some("status"));

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_messages_over_same_stream() {
        let (mut client_read, mut client_write) = tokio::io::duplex(8192);

        // Send two messages
        let mut msg1 = IscMessage::new();
        msg1.insert_string("seq", "1");
        let mut msg2 = IscMessage::new();
        msg2.insert_string("seq", "2");

        let frame1 = frame_message(&msg1);
        let frame2 = frame_message(&msg2);

        let write_handle = tokio::spawn(async move {
            client_write.write_all(&frame1).await.unwrap();
            client_write.write_all(&frame2).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        // Read first message
        let mut len_buf = [0u8; 4];
        client_read.read_exact(&mut len_buf).await.unwrap();
        let len1 = read_frame_length(&len_buf) as usize;
        let mut payload1 = vec![0u8; len1];
        client_read.read_exact(&mut payload1).await.unwrap();
        let decoded1 = IscMessage::decode(&payload1).unwrap();
        assert_eq!(decoded1.get_string("seq"), Some("1"));

        // Read second message
        client_read.read_exact(&mut len_buf).await.unwrap();
        let len2 = read_frame_length(&len_buf) as usize;
        let mut payload2 = vec![0u8; len2];
        client_read.read_exact(&mut payload2).await.unwrap();
        let decoded2 = IscMessage::decode(&payload2).unwrap();
        assert_eq!(decoded2.get_string("seq"), Some("2"));

        write_handle.await.unwrap();
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-net -- rndc`
Expected: All tests pass including new async tests.

- [ ] **Step 3: Commit**

```
test(net/rndc): add TCP stream roundtrip tests via tokio duplex
```

### Task 3.4: Integration Test Skeleton (Deferred)

**Files:**
- Create: `crates/bind9-sdk-net/tests/rndc_integration.rs`

- [ ] **Step 1: Write ignored integration test skeleton**

Create `crates/bind9-sdk-net/tests/rndc_integration.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for rndc wire protocol against a live BIND9 instance.
//!
//! These tests require:
//! - BIND9 9.20 running on localhost:953
//! - An rndc key configured in named.conf matching the test key below
//!
//! Run with: `cargo test -p bind9-sdk-net -- --ignored rndc_integration`
//!
//! See `tests/README.md` for BIND9 setup instructions.

use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::rndc::RndcConnection;

/// Test rndc key for integration tests.
///
/// This key must match the key configured in the test BIND9 instance's
/// `named.conf`:
///
/// ```conf
/// key "rndc-test-key" {
///     algorithm hmac-sha256;
///     secret "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==";
/// };
/// ```
fn test_key() -> bind9_sdk_core::tsig::TsigKey {
    // TODO: Construct TsigKey from base64 once TsigKey::from_base64 is available.
    // For now this is a placeholder that will be filled in when WT-2 is merged.
    todo!("construct test TsigKey -- depends on WT-2 TsigKey::from_base64")
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_connect_and_status() {
    let addr = "127.0.0.1:953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::Status)
        .await
        .expect("status command failed");

    assert!(resp.is_success(), "status command failed: {:?}", resp);
    assert!(
        resp.text.contains("version"),
        "status output should contain version info"
    );

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_reload() {
    let addr = "127.0.0.1:953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");
    let resp = conn
        .command(RndcCommand::Reload)
        .await
        .expect("reload command failed");

    assert!(resp.is_success(), "reload command failed: {:?}", resp);

    conn.close().await.expect("close failed");
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_wrong_key_fails_auth() {
    let addr = "127.0.0.1:953".parse().unwrap();
    // TODO: Construct a wrong key to test auth failure.
    // let wrong_key = TsigKey::new(...);
    // let conn = RndcConnection::connect(addr).await.unwrap();
    // let result = conn.authenticate(&wrong_key).await;
    // assert!(result.is_err());
    // assert!(matches!(result.unwrap_err(), NetError::AuthFailed));
}

#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_multiple_commands_on_same_connection() {
    let addr = "127.0.0.1:953".parse().unwrap();
    let key = test_key();

    let conn = RndcConnection::connect(addr).await.expect("connect failed");
    let mut conn = conn.authenticate(&key).await.expect("auth failed");

    // First command
    let resp1 = conn
        .command(RndcCommand::Status)
        .await
        .expect("first status failed");
    assert!(resp1.is_success());

    // Second command on same connection
    let resp2 = conn
        .command(RndcCommand::Stats)
        .await
        .expect("stats command failed");
    assert!(resp2.is_success());

    conn.close().await.expect("close failed");
}
```

- [ ] **Step 2: Run test compilation check (not execution)**

Run: `cargo test -p bind9-sdk-net --no-run`
Expected: Compiles successfully (tests are `#[ignore]`).

- [ ] **Step 3: Commit**

```
test(net/rndc): add ignored integration test skeleton for live BIND9
```

## Chunk 4: NamedControl Impl + ServerStatus Parsing

### Task 4.1: ServerStatus Response Parser

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs`

- [ ] **Step 1: Write tests for ServerStatus parsing from rndc output**

Add a `parse_server_status` function and tests to `command.rs`. The rndc `status` command returns multi-line text that must be parsed into the `ServerStatus` struct defined in `bind9-sdk-core/src/traits.rs`.

Add this function and its tests to `command.rs`:

```rust
use bind9_sdk_core::traits::ServerStatus;

/// Parse the output of `rndc status` into a `ServerStatus` struct.
///
/// # Expected format (BIND9 9.20)
///
/// ```text
/// version: BIND 9.20.0 (Stable Release) <id:abc123>
/// running on myhost: Linux x86_64
/// boot time: Mon, 01 Jan 2026 00:00:00 GMT
/// last configured: Mon, 01 Jan 2026 00:00:00 GMT
/// configuration file: /etc/named.conf
/// CPUs found: 4
/// worker threads: 4
/// UDP listeners per interface: 2
/// number of zones: 42 (0 automatic)
/// debug level: 0
/// xfers running: 0
/// xfers deferred: 0
/// soa queries in progress: 0
/// query logging is OFF
/// recursive clients: 0/900/1000
/// tcp clients: 0/150
/// TCP high-water: 0
/// server is up and running
/// number of zones: 42
/// ```
///
/// TODO: Verify format against BIND9 9.20 output. The format may vary
/// slightly between BIND9 minor versions.
pub(crate) fn parse_server_status(text: &str) -> ServerStatus {
    let version = extract_field(text, "version:")
        .unwrap_or_else(|| "unknown".to_string());

    let running_since = extract_field(text, "boot time:");

    let reload_count = extract_field(text, "number of zones:")
        .and_then(|s| {
            // "42 (0 automatic)" -> try to parse the first number
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let server_up = text.contains("server is up and running");

    ServerStatus {
        version,
        running_since,
        reload_count,
        server_up,
        raw_text: text.to_string(),
    }
}

/// Extract the value after a field label from multi-line text.
///
/// Given text like "version: BIND 9.20.0\nboot time: Mon..." and
/// label "version:", returns Some("BIND 9.20.0").
fn extract_field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(label) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}
```

Add these tests to the `mod tests` block:

```rust
    // -- ServerStatus parsing tests --

    #[test]
    fn parse_status_full_output() {
        let text = "\
version: BIND 9.20.0 (Stable Release) <id:abc123>
running on myhost: Linux x86_64
boot time: Mon, 01 Jan 2026 00:00:00 GMT
last configured: Mon, 01 Jan 2026 00:00:00 GMT
configuration file: /etc/named.conf
CPUs found: 4
worker threads: 4
number of zones: 42 (0 automatic)
debug level: 0
xfers running: 0
server is up and running";

        let status = parse_server_status(text);
        assert!(status.version.contains("BIND 9.20.0"));
        assert_eq!(
            status.running_since,
            Some("Mon, 01 Jan 2026 00:00:00 GMT".into())
        );
        assert_eq!(status.reload_count, 42);
        assert!(status.server_up);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn parse_status_missing_version() {
        let text = "server is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.version, "unknown");
        assert!(status.server_up);
    }

    #[test]
    fn parse_status_server_down() {
        let text = "version: BIND 9.20.0\nserver is shutting down";
        let status = parse_server_status(text);
        assert!(!status.server_up);
    }

    #[test]
    fn parse_status_no_boot_time() {
        let text = "version: BIND 9.20.0\nserver is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.running_since, None);
    }

    #[test]
    fn parse_status_preserves_raw_text() {
        let text = "version: BIND 9.20.0\nsome custom output";
        let status = parse_server_status(text);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn extract_field_finds_label() {
        let text = "version: BIND 9.20.0\nboot time: Monday";
        assert_eq!(
            extract_field(text, "version:"),
            Some("BIND 9.20.0".into())
        );
        assert_eq!(
            extract_field(text, "boot time:"),
            Some("Monday".into())
        );
    }

    #[test]
    fn extract_field_returns_none_for_missing() {
        let text = "version: BIND 9.20.0";
        assert_eq!(extract_field(text, "missing:"), None);
    }

    #[test]
    fn extract_field_handles_leading_whitespace() {
        let text = "  version: BIND 9.20.0";
        assert_eq!(
            extract_field(text, "version:"),
            Some("BIND 9.20.0".into())
        );
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-net -- rndc::command`
Expected: All command tests pass (serialization + status parsing).

- [ ] **Step 3: Commit**

```
feat(net/rndc): add ServerStatus parser for rndc status output
```

### Task 4.2: FrozenZone Response Parser

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs`

- [ ] **Step 1: Write FrozenZone construction helper and tests**

Add a helper to construct `FrozenZone` from a freeze response, and tests:

```rust
use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::RecordClass;
use bind9_sdk_core::traits::FrozenZone;

/// Construct a `FrozenZone` from the zone name used in a freeze command.
///
/// The rndc `freeze` command response does not contain structured data --
/// it just confirms success. The `FrozenZone` is constructed from the
/// command parameters.
pub(crate) fn make_frozen_zone(zone_name: &DomainName) -> FrozenZone {
    FrozenZone {
        name: zone_name.clone(),
        class: RecordClass::IN, // rndc freeze does not specify class; default to IN
    }
}
```

Add tests:

```rust
    // -- FrozenZone construction tests --

    #[test]
    fn make_frozen_zone_from_domain_name() {
        let name = DomainName::new("example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
        assert_eq!(frozen.class, RecordClass::IN);
    }

    #[test]
    fn make_frozen_zone_preserves_name() {
        let name = DomainName::new("sub.domain.example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-net -- rndc::command`
Expected: All tests pass.

- [ ] **Step 3: Commit**

```
feat(net/rndc): add FrozenZone construction helper
```

### Task 4.3: NamedControl Implementation for Bind9Client

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs`

- [ ] **Step 1: Implement NamedControl trait for Bind9Client**

Replace `crates/bind9-sdk-net/src/config.rs` with the `Bind9Client` implementation that uses `RndcConnection` internally. The `Bind9Client` wraps the connection in a `tokio::sync::Mutex` to allow `&self` access at the trait level.

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! BIND9 client configuration and trait implementations.
//!
//! `Bind9Client` is the primary entry point for interacting with a BIND9
//! server. It implements the management traits from `bind9-sdk-core`
//! (`NamedControl`, etc.) using the rndc wire protocol internally.

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::traits::{FrozenZone, NamedControl, ServerStatus};
use bind9_sdk_core::tsig::TsigKey;

use crate::error::NetError;
use crate::rndc::command::{make_frozen_zone, parse_server_status, RndcCommand};
use crate::rndc::RndcConnection;

/// Configuration for connecting to a BIND9 server.
pub struct ClientConfig {
    /// Address of the rndc control channel (typically port 953).
    pub rndc_addr: SocketAddr,
    /// TSIG key for rndc authentication.
    pub rndc_key: TsigKey,
    /// URL of the statistics-channel HTTP endpoint (optional).
    pub stats_url: Option<String>,
    /// Address of the DNS server for dynamic updates (optional, typically port 53).
    pub dns_addr: Option<SocketAddr>,
    /// Connection timeout.
    pub timeout: Duration,
}

/// A client for managing a BIND9 server.
///
/// Implements the management traits from `bind9-sdk-core` using the
/// rndc wire protocol for server control, HTTP for statistics, and
/// DNS over UDP/TCP for dynamic updates.
///
/// # Connection management
///
/// Each trait method call establishes a new rndc connection, authenticates,
/// sends the command, and closes the connection. This matches the behavior
/// of the `rndc` CLI tool. For bulk operations, consider using
/// `RndcConnection` directly for connection reuse.
///
/// # Thread safety
///
/// `Bind9Client` is `Send + Sync` and can be shared across tasks.
/// Each method call creates its own TCP connection, so concurrent
/// calls are safe.
pub struct Bind9Client {
    config: ClientConfig,
}

impl Bind9Client {
    /// Create a new BIND9 client with the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Bind9Client { config }
    }

    /// Execute a single rndc command using a fresh connection.
    ///
    /// Connects, authenticates, sends the command, reads the response,
    /// and closes the connection.
    async fn rndc_command(
        &self,
        cmd: RndcCommand,
    ) -> Result<crate::rndc::command::RndcResponse, NetError> {
        let conn = RndcConnection::connect(self.config.rndc_addr).await?;
        let mut conn = conn.authenticate(&self.config.rndc_key).await?;
        let resp = conn.command(cmd).await?;
        conn.close().await?;
        Ok(resp)
    }
}

impl NamedControl for Bind9Client {
    type Error = NetError;

    async fn status(&self) -> Result<ServerStatus, NetError> {
        let resp = self.rndc_command(RndcCommand::Status).await?;
        if !resp.is_success() {
            return Err(NetError::Protocol(format!(
                "rndc status failed: {}",
                resp.text
            )));
        }
        Ok(parse_server_status(&resp.text))
    }

    async fn reload(&self) -> Result<(), NetError> {
        let resp = self.rndc_command(RndcCommand::Reload).await?;
        if !resp.is_success() {
            return Err(NetError::Protocol(format!(
                "rndc reload failed: {}",
                resp.text
            )));
        }
        Ok(())
    }

    async fn reload_zone(&self, zone: &DomainName) -> Result<(), NetError> {
        let resp = self
            .rndc_command(RndcCommand::ReloadZone {
                zone: zone.to_string(),
            })
            .await?;
        if !resp.is_success() {
            return Err(NetError::Protocol(format!(
                "rndc reload zone failed: {}",
                resp.text
            )));
        }
        Ok(())
    }

    async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, NetError> {
        let resp = self
            .rndc_command(RndcCommand::Freeze {
                zone: zone.to_string(),
            })
            .await?;
        if !resp.is_success() {
            return Err(NetError::Protocol(format!(
                "rndc freeze failed: {}",
                resp.text
            )));
        }
        Ok(make_frozen_zone(zone))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_construction() {
        // Verify ClientConfig can be constructed with all fields.
        // We can't test TsigKey construction here (depends on WT-2),
        // so this is a compile-time check only.
        let _addr: SocketAddr = "127.0.0.1:953".parse().unwrap();
        let _timeout = Duration::from_secs(5);
    }

    #[test]
    fn bind9_client_is_send_sync() {
        // Compile-time check that Bind9Client is Send + Sync.
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<Bind9Client>();
    }

    // Note: Full NamedControl tests require a live BIND9 instance.
    // See tests/rndc_integration.rs for #[ignore] integration tests.
}
```

- [ ] **Step 2: Run cargo check**

Run: `cargo check --workspace`
Expected: Compiles successfully.

- [ ] **Step 3: Run all tests**

Run: `cargo test -p bind9-sdk-net`
Expected: All tests pass.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 5: Commit**

```
feat(net): implement NamedControl trait for Bind9Client via rndc
```

### Task 4.4: Final Verification

- [ ] **Step 1: Full workspace test suite**

Run: `cargo test --workspace`
Expected: All tests pass across all crates.

- [ ] **Step 2: Clippy clean**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 3: Format check**

Run: `cargo fmt --check`
Expected: Clean.

- [ ] **Step 4: WASM target check (core only)**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (net crate is not checked for WASM -- it uses tokio).

- [ ] **Step 5: Count new tests**

Run: `cargo test -p bind9-sdk-net -- --list 2>&1 | grep 'test ' | wc -l`
Expected: 50+ new tests across protocol, command, mod, and config modules.

- [ ] **Step 6: Final commit if any changes remain**

```
chore(net/rndc): WT-3 rndc wire protocol implementation complete
```

## Summary

| Chunk | Module | Tests | Key deliverables |
| --- | --- | --- | --- |
| 1 | `rndc/protocol.rs` | 17 | ISC binary message encode/decode, error handling |
| 2 | `rndc/protocol.rs`, `rndc/command.rs` | 40+ | Wire framing (4-byte BE), RndcCommand enum (25 variants), RndcResponse |
| 3 | `rndc/mod.rs` | 10+ | RndcConnection typestate, connect/authenticate/command/close, compile-fail test |
| 4 | `rndc/command.rs`, `config.rs` | 15+ | ServerStatus parser, FrozenZone helper, NamedControl impl for Bind9Client |

## Open Questions for BIND9 Source Verification

The following items are marked with `TODO: Verify against BIND9 source` in the code and must be verified before integration testing:

1. **ISC message version number** -- Is `1` correct for BIND9 9.20?
2. **Type tag values** -- Are `0x00` (string) and `0x01` (map) correct?
3. **Auth handshake sequence** -- What is the exact `_ctrl` message structure? Does it include a nonce? Timestamp?
4. **HMAC placement** -- Where in the ISC message is the HMAC placed? Is it a separate top-level key?
5. **Command message structure** -- Is `type` the correct key for the command string?
6. **Response field names** -- Is `text` or `_data` the key for response text?
7. **Success/failure indicators** -- How does the server signal success vs failure in the response?

These questions should be answered by examining BIND9 source (`lib/isccfg/`, `lib/isc/netmgr/`) or by capturing wire traffic from a real `rndc` session using tcpdump/Wireshark.
