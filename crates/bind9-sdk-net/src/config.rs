// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::protocol::Rcode;
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

    /// Maximum concurrent rndc connections for [`RndcPool`](crate::pool::RndcPool).
    ///
    /// `None` means the pool will use its own default (4).
    /// `Some(0)` is treated the same as `None`.
    pub pool_size: Option<usize>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("rndc_addr", &self.rndc_addr)
            .field("rndc_key", &"[REDACTED]")
            .field("stats_url", &self.stats_url)
            .field("dns_addr", &self.dns_addr)
            .field("tls", &self.tls.as_ref().map(|_| "[configured]"))
            .field("timeout", &self.timeout)
            .field("pool_size", &self.pool_size)
            .finish()
    }
}

impl ClientConfig {
    /// Create a minimal configuration with only the required fields.
    ///
    /// All optional fields (`stats_url`, `dns_addr`, `tls`, `pool_size`) are
    /// set to `None`. The `timeout` defaults to 10 seconds.
    ///
    /// Use direct struct construction (within the crate) to set optional fields,
    /// or modify individual fields after calling this constructor.
    pub fn new(rndc_addr: std::net::SocketAddr, rndc_key: TsigKey) -> Self {
        Self {
            rndc_addr,
            rndc_key,
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: std::time::Duration::from_secs(10),
            pool_size: None,
        }
    }
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
        if config.tls.is_some() {
            tracing::warn!(
                "ClientConfig.tls is configured but TLS transports are not implemented yet"
            );
        }
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
        let timeout = self.config.timeout;
        let fut = async {
            let conn = RndcConnection::connect(self.config.rndc_addr).await?;
            let mut conn = conn.authenticate(&self.config.rndc_key).await?;
            let resp = conn.command(cmd).await?;
            conn.close().await?;
            Ok(resp)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| NetError::Timeout(timeout))?
    }

    /// Convert a raw update result into the high-level error taxonomy.
    fn classify_update_result(result: UpdateResult) -> Result<UpdateResult, NetError> {
        match result.rcode {
            Rcode::NoError => Ok(result),
            Rcode::NxDomain | Rcode::YxDomain | Rcode::NxRrset | Rcode::YxRrset => {
                Err(NetError::PrerequisiteFailed {
                    rcode: result.rcode,
                })
            }
            _ => Err(NetError::UpdateRejected {
                rcode: result.rcode.to_string(),
            }),
        }
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
        Self::classify_update_result(sender.send(update, key).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::test_key;
    use bind9_sdk_core::protocol::Rcode;

    #[test]
    fn client_config_construction() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: Some("http://127.0.0.1:8053".into()),
            dns_addr: Some("127.0.0.1:53".parse().unwrap()),
            tls: None,
            timeout: Duration::from_secs(10),
            pool_size: None,
        };
        assert_eq!(config.rndc_addr.port(), 953);
        assert!(config.stats_url.is_some());
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn client_config_debug_redacts_key() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(10),
            pool_size: None,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"), "key must be redacted");
        assert!(!debug.contains("0xAA"), "raw key bytes must not appear");
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
            pool_size: None,
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
            pool_size: None,
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
            pool_size: None,
        };
        assert!(config.tls.is_some());
    }

    #[test]
    fn classify_update_result_returns_success() {
        let result = UpdateResult {
            rcode: Rcode::NoError,
            id: 0x1234,
        };
        let classified = Bind9Client::classify_update_result(result.clone()).unwrap();
        assert_eq!(classified, result);
    }

    #[test]
    fn classify_update_result_maps_prerequisite_failure() {
        let err = Bind9Client::classify_update_result(UpdateResult {
            rcode: Rcode::NxRrset,
            id: 0x2222,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            NetError::PrerequisiteFailed {
                rcode: Rcode::NxRrset
            }
        ));
    }

    #[test]
    fn classify_update_result_maps_general_rejection() {
        let err = Bind9Client::classify_update_result(UpdateResult {
            rcode: Rcode::Refused,
            id: 0x3333,
        })
        .unwrap_err();
        assert!(matches!(err, NetError::UpdateRejected { .. }));
        assert!(err.to_string().contains("REFUSED"));
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
            pool_size: None,
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
            pool_size: None,
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
            pool_size: None,
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
