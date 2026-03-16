// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::tsig::TsigKey;

use crate::tls::TlsConfig;

/// Configuration for connecting to a BIND9 server.
///
/// Combines rndc control channel, DNS update, and statistics-channel
/// connection parameters into a single config struct.
pub struct ClientConfig {
    /// rndc control channel address (default: 127.0.0.1:953).
    pub rndc_addr: SocketAddr,

    /// TSIG key for rndc authentication and DNS update signing.
    pub rndc_key: TsigKey,

    /// Statistics-channel HTTP URL (e.g., "http://127.0.0.1:8053").
    pub stats_url: Option<String>,

    /// DNS server address for sending updates (default: same host, port 53).
    pub dns_addr: Option<SocketAddr>,

    /// Optional TLS configuration for encrypted connections.
    pub tls: Option<TlsConfig>,

    /// Timeout for individual operations (default: 10 seconds).
    pub timeout: Duration,
}

/// Client for managing a BIND9 DNS server.
///
/// This is the primary entry point for the `bind9-sdk-net` crate.
/// In Phase 1, this is a skeleton that holds configuration. Wave 2
/// implementation plans will add trait implementations for
/// `NamedControl`, `DynamicUpdater`, and `StatsClient`.
pub struct Bind9Client {
    config: ClientConfig,
}

impl Bind9Client {
    /// Create a new BIND9 client with the given configuration.
    ///
    /// This does not establish any connections — connections are created
    /// on demand by trait method implementations (added in Wave 2).
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Access the client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};

    fn test_key() -> TsigKey {
        TsigKey::new(
            DomainName::new("rndc-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xAA; 32],
        )
        .unwrap()
    }

    #[test]
    fn client_config_construction() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: Some("http://127.0.0.1:8053".into()),
            dns_addr: Some("127.0.0.1:53".parse().unwrap()),
            tls: None,
            timeout: Duration::from_secs(10),
        };
        assert_eq!(config.rndc_addr.port(), 953);
        assert!(config.stats_url.is_some());
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn client_config_minimal() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
        };
        assert!(config.stats_url.is_none());
        assert!(config.dns_addr.is_none());
        assert!(config.tls.is_none());
    }

    #[test]
    fn bind9_client_new() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(10),
        };
        let client = Bind9Client::new(config);
        assert_eq!(client.config().rndc_addr.port(), 953);
    }

    #[test]
    fn bind9_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Bind9Client>();
    }

    #[test]
    fn client_config_with_tls() {
        let tls = TlsConfig::new().unwrap();
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: Some(tls),
            timeout: Duration::from_secs(10),
        };
        assert!(config.tls.is_some());
    }
}
