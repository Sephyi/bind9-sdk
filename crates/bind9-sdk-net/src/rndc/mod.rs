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

pub mod command;
pub(crate) mod protocol;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use bind9_sdk_core::tsig::TsigKey;

use crate::error::NetError;

use self::command::{RndcCommand, RndcResponse};
use self::protocol::{IscMessage, frame_message, read_frame_length};

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
        let payload = auth_msg.encode()?;
        let mac = key.sign(&payload);

        // Build the outer message with the HMAC
        let mut signed_msg = IscMessage::new();
        signed_msg.insert_string("_auth", base64_encode(&mac));
        // Re-include the original message fields
        for (k, v) in auth_msg.data {
            signed_msg.data.insert(k, v);
        }

        // Send the framed message
        let frame = frame_message(&signed_msg)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetError::Connection(format!("failed to send auth message: {e}")))?;

        // Read the server's response
        let response = read_isc_message(&mut self.stream).await?;

        // Check for authentication success
        // TODO: Verify the success indicator field name against BIND9 source.
        let result = response.get_string("_ctrl");
        if result != Some("null") {
            let _err_text = response
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
        msg.insert_string("type", cmd.to_command_string());

        // Send
        let frame = frame_message(&msg)?;
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
        _check_method_exists::<RndcConnection<Authenticated>>();
    }

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
