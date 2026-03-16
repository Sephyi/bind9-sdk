// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::time::Duration;

/// Errors from the `bind9-sdk-net` crate.
///
/// Covers network failures, protocol errors, authentication failures,
/// and upstream core errors. The enum is `#[non_exhaustive]` so new
/// variants can be added without a semver bump.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// TCP/UDP connection failed.
    #[error("connection failed: {0}")]
    Connection(String),

    /// A request timed out.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// rndc HMAC authentication was rejected by the server.
    #[error("rndc authentication failed")]
    AuthFailed,

    /// rndc wire protocol error (framing, encoding, unexpected response).
    #[error("rndc protocol error: {0}")]
    Protocol(String),

    /// TLS handshake or configuration error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// HTTP error from the statistics-channel.
    #[error("HTTP error: {status}")]
    Http { status: u16, body: String },

    /// DNS server rejected an RFC 2136 update.
    #[error("DNS update rejected: {rcode}")]
    UpdateRejected { rcode: String },

    /// An error propagated from `bind9-sdk-core`.
    #[error(transparent)]
    Core(#[from] bind9_sdk_core::CoreError),

    /// An I/O error from the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_error_display() {
        let err = NetError::Connection("refused".into());
        assert_eq!(err.to_string(), "connection failed: refused");
    }

    #[test]
    fn timeout_error_display() {
        let err = NetError::Timeout(Duration::from_secs(5));
        assert_eq!(err.to_string(), "request timed out after 5s");
    }

    #[test]
    fn auth_failed_display() {
        let err = NetError::AuthFailed;
        assert_eq!(err.to_string(), "rndc authentication failed");
    }

    #[test]
    fn protocol_error_display() {
        let err = NetError::Protocol("bad framing".into());
        assert_eq!(err.to_string(), "rndc protocol error: bad framing");
    }

    #[test]
    fn tls_error_display() {
        let err = NetError::Tls("certificate expired".into());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn http_error_display() {
        let err = NetError::Http {
            status: 503,
            body: "unavailable".into(),
        };
        assert_eq!(err.to_string(), "HTTP error: 503");
    }

    #[test]
    fn update_rejected_display() {
        let err = NetError::UpdateRejected {
            rcode: "REFUSED".into(),
        };
        assert_eq!(err.to_string(), "DNS update rejected: REFUSED");
    }

    #[test]
    fn from_core_error() {
        let core_err = bind9_sdk_core::CoreError::Tsig("bad key".into());
        let net_err: NetError = core_err.into();
        assert!(matches!(net_err, NetError::Core(_)));
        assert!(net_err.to_string().contains("TSIG error: bad key"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let net_err: NetError = io_err.into();
        assert!(matches!(net_err, NetError::Io(_)));
    }

    #[test]
    fn net_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetError>();
    }

    #[test]
    fn net_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<NetError>();
    }
}
