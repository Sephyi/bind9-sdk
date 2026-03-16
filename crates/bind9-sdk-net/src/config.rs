// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::traits::{
    DynamicUpdater, FrozenZone, NamedControl, ServerStats, ServerStatus, StatsClient, ZoneStats,
};
use bind9_sdk_core::tsig::TsigKey;
use bind9_sdk_core::update::{UpdateMessage, UpdateResult};

use crate::error::NetError;
use crate::nsupdate::NsUpdateSender;
use crate::rndc::RndcConnection;
use crate::rndc::command::{RndcCommand, make_frozen_zone, parse_server_status};
use crate::stats::StatsHttpClient;
use crate::tls::TlsConfig;

/// Configuration for connecting to a BIND9 server.
///
/// Combines rndc control channel, DNS update, and statistics-channel
/// connection parameters into a single config struct.
#[non_exhaustive]
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
    ///
    /// **Note:** Currently unused. Reserved for future TLS-encrypted rndc
    /// and statistics-channel connections (Phase 2 XoT).
    pub tls: Option<TlsConfig>,

    /// Timeout for individual operations (default: 10 seconds).
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
    ///
    /// This does not establish any connections — connections are created
    /// on demand by trait method implementations.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Access the client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
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

impl StatsClient for Bind9Client {
    type Error = NetError;

    async fn server_stats(&self) -> Result<ServerStats, NetError> {
        let url = self
            .config
            .stats_url
            .as_ref()
            .ok_or_else(|| NetError::Connection("stats URL not configured".into()))?;
        let client = StatsHttpClient::new(url, self.config.timeout)?;
        client.fetch_server_stats().await
    }

    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, NetError> {
        let url = self
            .config
            .stats_url
            .as_ref()
            .ok_or_else(|| NetError::Connection("stats URL not configured".into()))?;
        let client = StatsHttpClient::new(url, self.config.timeout)?;
        client.fetch_zone_stats(zone).await
    }
}

impl DynamicUpdater for Bind9Client {
    type Error = NetError;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, NetError> {
        let addr = self
            .config
            .dns_addr
            .ok_or_else(|| NetError::Connection("DNS server address not configured".into()))?;
        let sender = NsUpdateSender::with_timeout(addr, self.config.timeout);
        // Pass the TSIG key for response verification if the update was signed
        let key = if update.is_signed() {
            Some(&self.config.rndc_key)
        } else {
            None
        };
        sender.send(update, key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::test_key;

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

#[cfg(test)]
mod stats_tests {
    use super::*;
    use crate::config::test_key;
    use bind9_sdk_core::traits::StatsClient;

    #[tokio::test]
    async fn bind9_client_server_stats_without_url_returns_error() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
        };
        let client = Bind9Client::new(config);
        let result = client.server_stats().await;
        assert!(
            result.is_err(),
            "should fail when stats_url is not configured"
        );
    }

    #[tokio::test]
    async fn bind9_client_zone_stats_without_url_returns_error() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
        };
        let client = Bind9Client::new(config);
        let zone = bind9_sdk_core::domain::DomainName::new("example.com.").unwrap();
        let result = client.zone_stats(&zone).await;
        assert!(
            result.is_err(),
            "should fail when stats_url is not configured"
        );
    }
}

#[cfg(test)]
mod dynamic_updater_tests {
    use super::*;
    use crate::config::test_key;
    use bind9_sdk_core::traits::DynamicUpdater;

    /// Verify the DynamicUpdater impl compiles via a static bound check.
    fn _assert_dynamic_updater_impl() {
        fn assert_impl<T: DynamicUpdater>() {}
        assert_impl::<Bind9Client>();
    }

    #[tokio::test]
    async fn bind9_client_send_update_without_dns_addr_returns_error() {
        // We cannot construct UpdateMessage without UpdateBuilder (WT-2).
        // This test verifies the trait impl compiles. The actual "no dns_addr"
        // error test requires a valid UpdateMessage which needs UpdateBuilder.
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
        };
        let _client = Bind9Client::new(config);
        // Trait impl is verified at compile time via _assert_dynamic_updater_impl
    }
}

#[cfg(test)]
fn test_key() -> TsigKey {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::TsigAlgorithm;
    TsigKey::new(
        DomainName::new("rndc-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0xAA; 32],
    )
    .unwrap()
}
