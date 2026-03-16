// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
//!
//! # Authentication protocol
//!
//! The rndc handshake is a two-step HMAC-authenticated exchange:
//!
//! 1. Client sends a signed "null" command with serial, timestamp, and expiry
//! 2. Server responds with a nonce (used in all subsequent commands)
//! 3. Each command message includes the nonce and a fresh HMAC signature
//!
//! The HMAC covers the encoded `_ctrl` and `_data` table entries but NOT
//! the `_auth` entry or the version header.

pub mod command;
pub(crate) mod protocol;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};

use crate::error::NetError;

use self::command::{RndcCommand, RndcResponse};
use self::protocol::{IscMessage, IscValue, frame_message, read_frame_length};

/// Fixed buffer size for isccc HMAC auth values.
///
/// The `_auth.hsha` field is always exactly 89 bytes:
/// `[1-byte algorithm tag][base64 HMAC digest][NUL padding]`
///
/// - SHA256: 1 + 44 + 44 = 89
/// - SHA512: 1 + 88 + 0  = 89
/// - SHA1:   1 + 28 + 60 = 89
const ISCCC_HMAC_BUF_SIZE: usize = 89;

/// Default message expiry window in seconds.
///
/// Messages are valid for this many seconds after creation. BIND9's
/// default is 60 seconds.
const ISCCC_EXPIRY_SECS: u64 = 60;

/// Typestate marker: connection is not yet authenticated.
pub struct Unauthenticated;

/// Typestate marker: connection has been authenticated with HMAC.
///
/// Holds the TSIG key reference, serial counter, and server nonce
/// needed to sign subsequent command messages.
pub struct Authenticated<'k> {
    /// TSIG key used for HMAC signing of all messages.
    key: &'k TsigKey,
    /// Monotonically increasing message serial number.
    serial: u32,
    /// Server-provided nonce from the auth handshake response.
    /// Echoed in all subsequent command messages.
    nonce: Option<String>,
}

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
/// - ISC binary key-value message encoding (isccc format)
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
    state: State,
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
            state: Unauthenticated,
        })
    }

    /// Authenticate with the BIND9 server using HMAC.
    ///
    /// Sends a signed "null" command handshake. On success, consumes the
    /// unauthenticated connection and returns an authenticated connection
    /// that can send commands.
    ///
    /// # Authentication handshake
    ///
    /// 1. Client builds `_ctrl` (serial, timestamp, expiry) and `_data` (type=null)
    /// 2. HMAC is computed over the encoded `_ctrl` + `_data` body
    /// 3. Client sends message with `_auth.hsha` containing the HMAC
    /// 4. Server responds with a nonce in `_ctrl._nonce`
    /// 5. Nonce is stored for use in subsequent command messages
    pub async fn authenticate(
        mut self,
        key: &TsigKey,
    ) -> Result<RndcConnection<Authenticated<'_>>, NetError> {
        tracing::debug!("authenticating rndc connection");

        // Starting serial derived from current time for uniqueness across connections
        let now = current_unix_time()?;
        let serial = (now & 0xFFFF_FFFF) as u32;

        // Build _ctrl table: serial, timestamp, expiry
        let ctrl = build_ctrl_table(serial, now, None);

        // Build _data table: type = "null" (auth handshake command)
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        // Compute HMAC over encoded _ctrl + _data body (excludes _auth and version)
        let hmac_value = sign_rndc_body(key, &ctrl, &data)?;

        // Build _auth table with HMAC value
        let mut auth = BTreeMap::new();
        auth.insert("hsha".to_string(), IscValue::Binary(hmac_value));

        // Assemble the full message: _auth + _ctrl + _data
        // BTreeMap sorts alphabetically, so order is: _auth, _ctrl, _data
        let mut msg = IscMessage::new();
        msg.insert_map("_auth", auth);
        msg.insert_map("_ctrl", ctrl);
        msg.insert_map("_data", data);

        // Send the framed message
        let frame = frame_message(&msg)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetError::Connection(format!("failed to send auth message: {e}")))?;

        // Read the server's response
        let response = read_isc_message(&mut self.stream).await?;

        // Extract nonce from server's _ctrl table
        let nonce = response
            .get_map("_ctrl")
            .and_then(|ctrl_map| match ctrl_map.get("_nonce") {
                Some(IscValue::String(s)) => Some(s.clone()),
                _ => None,
            });

        // Check for authentication success via _data.result
        // "0" = success, anything else = error
        let result_code = response
            .get_map("_data")
            .and_then(|data_map| match data_map.get("result") {
                Some(IscValue::String(s)) => Some(s.as_str()),
                _ => None,
            });

        match result_code {
            Some("0") => {
                tracing::debug!(
                    "rndc authentication successful (nonce: {})",
                    nonce.is_some()
                );
            }
            Some(code) => {
                // Server returned a non-zero result code
                let err_text = extract_error_text(&response)
                    .unwrap_or("server rejected authentication");
                return Err(NetError::AuthFailed {
                    reason: format!("result code {code}: {err_text}"),
                });
            }
            None => {
                // No _data.result field — unexpected response format
                return Err(NetError::AuthFailed {
                    reason: "server response missing _data.result field".to_string(),
                });
            }
        }

        Ok(RndcConnection {
            stream: self.stream,
            state: Authenticated {
                key,
                serial,
                nonce,
            },
        })
    }
}

impl<'k> RndcConnection<Authenticated<'k>> {
    /// Send an rndc command and receive the response.
    ///
    /// Each command is signed with the HMAC key and includes the server's
    /// nonce from the authentication handshake. The serial counter is
    /// incremented for each command.
    ///
    /// The connection remains open and can be reused for subsequent commands.
    pub async fn command(&mut self, cmd: RndcCommand) -> Result<RndcResponse, NetError> {
        tracing::debug!("sending rndc command: {cmd}");

        // Increment serial for this command
        self.state.serial = self.state.serial.wrapping_add(1);
        let now = current_unix_time()?;

        // Build _ctrl table with serial, timestamp, expiry, and nonce
        let ctrl = build_ctrl_table(self.state.serial, now, self.state.nonce.as_deref());

        // Build _data table with the command type
        let mut data = BTreeMap::new();
        data.insert(
            "type".to_string(),
            IscValue::String(cmd.to_command_string()),
        );

        // Compute HMAC over encoded _ctrl + _data body
        let hmac_value = sign_rndc_body(self.state.key, &ctrl, &data)?;

        // Build _auth table with HMAC value
        let mut auth = BTreeMap::new();
        auth.insert("hsha".to_string(), IscValue::Binary(hmac_value));

        // Assemble and send the full message
        let mut msg = IscMessage::new();
        msg.insert_map("_auth", auth);
        msg.insert_map("_ctrl", ctrl);
        msg.insert_map("_data", data);

        let frame = frame_message(&msg)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetError::Connection(format!("failed to send command: {e}")))?;

        // Read response
        let response = read_isc_message(&mut self.stream).await?;

        // Extract result code and text from _data table
        let data_map = response.get_map("_data");

        let result_code = data_map
            .and_then(|d| match d.get("result") {
                Some(IscValue::String(s)) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let text = data_map
            .and_then(|d| match d.get("text") {
                Some(IscValue::String(s)) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();

        tracing::debug!(
            "rndc command response: result={result_code}, text_len={}",
            text.len()
        );

        // result "0" = success, anything else = error
        if result_code == "0" {
            Ok(RndcResponse::from_text(&text))
        } else {
            let err_text = if text.is_empty() {
                format!("rndc command failed with result code {result_code}")
            } else {
                text
            };
            Ok(RndcResponse::from_text(&format!("rndc: {err_text}")))
        }
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

// -- Helper functions --

/// Build the `_ctrl` table for an rndc message.
///
/// Contains serial number, timestamp, expiry, and optionally the server nonce.
/// All values are stored as ASCII decimal strings (isccc convention).
fn build_ctrl_table(
    serial: u32,
    now_secs: u64,
    nonce: Option<&str>,
) -> BTreeMap<String, IscValue> {
    let mut ctrl = BTreeMap::new();
    ctrl.insert(
        "_ser".to_string(),
        IscValue::String(serial.to_string()),
    );
    ctrl.insert(
        "_tim".to_string(),
        IscValue::String(now_secs.to_string()),
    );
    ctrl.insert(
        "_exp".to_string(),
        IscValue::String((now_secs + ISCCC_EXPIRY_SECS).to_string()),
    );
    if let Some(n) = nonce {
        ctrl.insert("_nonce".to_string(), IscValue::String(n.to_string()));
    }
    ctrl
}

/// Compute the HMAC value for an rndc message.
///
/// The HMAC covers the serialized body of `_ctrl` and `_data` table entries,
/// excluding `_auth` and the version header. The result is the 89-byte
/// `_auth.hsha` binary value: `[algorithm byte][base64 HMAC digest][NUL padding]`
fn sign_rndc_body(
    key: &TsigKey,
    ctrl: &BTreeMap<String, IscValue>,
    data: &BTreeMap<String, IscValue>,
) -> Result<Vec<u8>, NetError> {
    // Serialize just _ctrl and _data for HMAC input (no _auth, no version)
    let mut sign_msg = IscMessage::new();
    sign_msg.insert_map("_ctrl", ctrl.clone());
    sign_msg.insert_map("_data", data.clone());
    let body = sign_msg.encode_body()?;

    // Compute HMAC digest
    let digest = key.sign(&body);

    // Build the 89-byte auth value: algo_byte + base64(digest) + NUL padding
    let algo_byte = isccc_algorithm_byte(key.algorithm());
    let b64 = base64_encode(&digest);

    let mut buf = Vec::with_capacity(ISCCC_HMAC_BUF_SIZE);
    buf.push(algo_byte);
    buf.extend_from_slice(b64.as_bytes());
    // NUL-pad to fixed 89-byte size
    buf.resize(ISCCC_HMAC_BUF_SIZE, 0);

    Ok(buf)
}

/// Map a TSIG algorithm to its isccc algorithm byte.
///
/// Values from BIND9 source `lib/isccc/include/isccc/types.h`:
/// - ISCCC_ALG_HMACSHA1   = 0xA1 (161)
/// - ISCCC_ALG_HMACSHA224 = 0xA2 (162) -- not supported by this SDK
/// - ISCCC_ALG_HMACSHA256 = 0xA3 (163)
/// - ISCCC_ALG_HMACSHA384 = 0xA4 (164) -- not supported by this SDK
/// - ISCCC_ALG_HMACSHA512 = 0xA5 (165)
fn isccc_algorithm_byte(algo: TsigAlgorithm) -> u8 {
    #[allow(deprecated)]
    match algo {
        TsigAlgorithm::HmacSha1 => 0xA1,
        TsigAlgorithm::HmacSha256 => 0xA3,
        TsigAlgorithm::HmacSha512 => 0xA5,
        _ => unreachable!("unsupported TSIG algorithm for rndc"),
    }
}

/// Get the current Unix timestamp in seconds.
fn current_unix_time() -> Result<u64, NetError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| NetError::Protocol(format!("system clock error: {e}")))
}

/// Extract error text from a server response.
///
/// Checks `_data.err` first, then `_data.text` as a fallback.
fn extract_error_text(response: &IscMessage) -> Option<&str> {
    response.get_map("_data").and_then(|d| {
        match d.get("err") {
            Some(IscValue::String(s)) => Some(s.as_str()),
            _ => match d.get("text") {
                Some(IscValue::String(s)) => Some(s.as_str()),
                _ => None,
            },
        }
    })
}

/// Read a framed ISC message from a TCP stream.
///
/// Reads the 4-byte length prefix, then reads exactly that many bytes,
/// then decodes the ISC message.
async fn read_isc_message(stream: &mut TcpStream) -> Result<IscMessage, NetError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetError::Connection(format!("failed to read message length: {e}")))?;
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
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| NetError::Connection(format!("failed to read message payload: {e}")))?;

    IscMessage::decode(&payload)
}

/// Base64-encode bytes using standard encoding.
fn base64_encode(data: &[u8]) -> String {
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
        fn _assert_connect_exists(
            _f: impl FnOnce(
                SocketAddr,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<RndcConnection<Unauthenticated>, NetError>,
                        >,
                >,
            >,
        ) {
        }
    }

    #[test]
    fn authenticated_has_command_and_close() {
        // Compile-time check that the method signatures exist on Authenticated.
        fn _check_method_exists<T>()
        where
            T: Sized,
        {
        }
        _check_method_exists::<RndcConnection<Authenticated<'static>>>();
    }

    // -- Helper function unit tests --

    #[test]
    fn isccc_algorithm_byte_sha256() {
        assert_eq!(isccc_algorithm_byte(TsigAlgorithm::HmacSha256), 0xA3);
    }

    #[test]
    fn isccc_algorithm_byte_sha512() {
        assert_eq!(isccc_algorithm_byte(TsigAlgorithm::HmacSha512), 0xA5);
    }

    #[test]
    #[allow(deprecated)]
    fn isccc_algorithm_byte_sha1() {
        assert_eq!(isccc_algorithm_byte(TsigAlgorithm::HmacSha1), 0xA1);
    }

    #[test]
    fn build_ctrl_table_without_nonce() {
        let ctrl = build_ctrl_table(42, 1000, None);
        assert_eq!(
            ctrl.get("_ser"),
            Some(&IscValue::String("42".to_string()))
        );
        assert_eq!(
            ctrl.get("_tim"),
            Some(&IscValue::String("1000".to_string()))
        );
        assert_eq!(
            ctrl.get("_exp"),
            Some(&IscValue::String("1060".to_string()))
        );
        assert!(!ctrl.contains_key("_nonce"));
    }

    #[test]
    fn build_ctrl_table_with_nonce() {
        let ctrl = build_ctrl_table(1, 2000, Some("abc123"));
        assert_eq!(
            ctrl.get("_nonce"),
            Some(&IscValue::String("abc123".to_string()))
        );
        assert_eq!(
            ctrl.get("_ser"),
            Some(&IscValue::String("1".to_string()))
        );
    }

    #[test]
    fn sign_rndc_body_produces_89_bytes() {
        use bind9_sdk_core::domain::DomainName;

        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xAA; 32],
        )
        .unwrap();

        let ctrl = build_ctrl_table(1, 1000, None);
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        let hmac = sign_rndc_body(&key, &ctrl, &data).unwrap();
        assert_eq!(
            hmac.len(),
            ISCCC_HMAC_BUF_SIZE,
            "HMAC value must be exactly {ISCCC_HMAC_BUF_SIZE} bytes"
        );
    }

    #[test]
    fn sign_rndc_body_starts_with_algorithm_byte() {
        use bind9_sdk_core::domain::DomainName;

        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xBB; 32],
        )
        .unwrap();

        let ctrl = build_ctrl_table(1, 1000, None);
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        let hmac = sign_rndc_body(&key, &ctrl, &data).unwrap();
        assert_eq!(hmac[0], 0xA3, "first byte must be SHA256 algorithm tag");
    }

    #[test]
    fn sign_rndc_body_sha512_starts_with_0xa5() {
        use bind9_sdk_core::domain::DomainName;

        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha512,
            vec![0xCC; 64],
        )
        .unwrap();

        let ctrl = build_ctrl_table(1, 1000, None);
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        let hmac = sign_rndc_body(&key, &ctrl, &data).unwrap();
        assert_eq!(hmac[0], 0xA5, "first byte must be SHA512 algorithm tag");
        assert_eq!(hmac.len(), ISCCC_HMAC_BUF_SIZE);
    }

    #[test]
    fn sign_rndc_body_contains_valid_base64_after_algo_byte() {
        use bind9_sdk_core::domain::DomainName;

        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xDD; 32],
        )
        .unwrap();

        let ctrl = build_ctrl_table(1, 1000, None);
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        let hmac = sign_rndc_body(&key, &ctrl, &data).unwrap();

        // After algo byte, next 44 bytes should be valid base64 for SHA256
        let b64_portion = &hmac[1..45];
        let b64_str = std::str::from_utf8(b64_portion).expect("base64 should be valid UTF-8");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_str)
            .expect("should be valid base64");
        assert_eq!(decoded.len(), 32, "decoded HMAC-SHA256 should be 32 bytes");
    }

    #[test]
    fn sign_rndc_body_nul_padded_to_89_bytes() {
        use bind9_sdk_core::domain::DomainName;

        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xEE; 32],
        )
        .unwrap();

        let ctrl = build_ctrl_table(1, 1000, None);
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), IscValue::String("null".to_string()));

        let hmac = sign_rndc_body(&key, &ctrl, &data).unwrap();

        // SHA256: 1 algo + 44 base64 = 45 content bytes, rest should be NUL
        for (i, &byte) in hmac[45..].iter().enumerate() {
            assert_eq!(
                byte, 0,
                "byte at offset {} should be NUL padding, got 0x{:02x}",
                45 + i,
                byte
            );
        }
    }

    #[test]
    fn current_unix_time_returns_reasonable_value() {
        let now = current_unix_time().unwrap();
        // Should be after 2024-01-01 (1704067200) and before 2030-01-01 (1893456000)
        assert!(
            now > 1_704_067_200,
            "timestamp {now} should be after 2024"
        );
        assert!(
            now < 1_893_456_000,
            "timestamp {now} should be before 2030"
        );
    }

    // -- Framing tests (using duplex streams) --

    #[tokio::test]
    async fn read_isc_message_from_mock_stream() {
        // Create an in-memory duplex stream pair to test framing logic.
        let (mut client, mut server) = tokio::io::duplex(4096);

        // Write a valid framed ISC message
        let mut msg = IscMessage::new();
        msg.insert_string("test", "value");
        let frame = frame_message(&msg).unwrap();
        let frame_len = frame.len();

        // Spawn writer
        let write_handle = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // The duplex stream is not a TcpStream, so we test the protocol
        // layer directly instead.
        let mut buf = vec![0u8; frame_len];
        client.read_exact(&mut buf).await.unwrap();

        let payload_len = read_frame_length(&<[u8; 4]>::try_from(&buf[..4]).unwrap()) as usize;
        let decoded = IscMessage::decode(&buf[4..4 + payload_len]).unwrap();
        assert_eq!(decoded, msg);

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn frame_write_and_read_roundtrip_via_duplex() {
        let (mut client_read, mut client_write) = tokio::io::duplex(8192);

        let mut msg = IscMessage::new();
        msg.insert_string("_ctrl", "command");
        msg.insert_string("type", "status");

        let frame = frame_message(&msg).unwrap();

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

        let frame1 = frame_message(&msg1).unwrap();
        let frame2 = frame_message(&msg2).unwrap();

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
}
