// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use crate::error::NetError;

/// TLS 1.3 configuration for secure connections to BIND9.
///
/// Wraps a `rustls::ClientConfig` configured for TLS 1.3 only, with
/// AES-256-GCM and ChaCha20-Poly1305 cipher suites. Certificate
/// validation uses Mozilla's CA root certificates via `webpki-roots`.
///
/// Used by the rndc and statistics-channel clients when TLS is enabled.
/// Phase 1 rndc uses plaintext TCP on localhost; TLS is prepared here
/// for Phase 2 XoT (DNS-over-TLS for zone transfers).
pub struct TlsConfig {
    inner: Arc<rustls::ClientConfig>,
}

impl TlsConfig {
    /// Create a TLS 1.3 configuration with Mozilla CA root certificates.
    ///
    /// Configures:
    /// - TLS 1.3 only (no TLS 1.2 fallback)
    /// - AES-256-GCM and ChaCha20-Poly1305 cipher suites
    /// - Certificate validation via webpki-roots
    pub fn new() -> Result<Self, NetError> {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| NetError::Tls(format!("protocol version error: {e}")))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Access the underlying `rustls::ClientConfig`.
    ///
    /// Used internally by transport layers that need the rustls config
    /// for `tokio-rustls` connectors.
    pub fn client_config(&self) -> &rustls::ClientConfig {
        &self.inner
    }

    /// Get an `Arc` reference to the underlying config.
    ///
    /// Useful for sharing across multiple connections.
    pub fn client_config_arc(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_new_succeeds() {
        let config = TlsConfig::new();
        assert!(config.is_ok());
    }

    #[test]
    fn tls_config_inner_is_accessible() {
        let config = TlsConfig::new().unwrap();
        let inner = config.client_config();
        // TLS 1.3 should be enabled
        assert!(
            inner.alpn_protocols.is_empty(),
            "Default config should have no ALPN protocols"
        );
    }

    #[test]
    fn tls_config_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TlsConfig>();
    }
}
