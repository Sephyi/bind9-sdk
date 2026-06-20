// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! JavaScript bindings for the BIND9 rndc control channel client.

use std::sync::Arc;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_net::rndc::RndcConnection;
use bind9_sdk_net::rndc::command::{DumpDbOptions, RndcCommand, ZoneTarget};
use napi_derive::napi;

use crate::error::BindSdkError;

/// An rndc client for controlling a BIND9 server.
///
/// Each async method creates a fresh TCP connection, authenticates with
/// the TSIG key, sends the command, and closes the connection.
#[napi]
pub struct JsRndcClient {
    host: String,
    port: u16,
    key: Arc<TsigKey>,
}

#[napi]
impl JsRndcClient {
    /// Create a new rndc client.
    ///
    /// `algorithm` must be one of: `"hmac-sha256"`, `"hmac-sha512"`, `"hmac-sha1"` (legacy).
    /// `keySecretBase64` is the base64-encoded HMAC key material from `rndc.conf`.
    #[napi(constructor)]
    pub fn new(
        host: String,
        port: u16,
        key_name: String,
        algorithm: String,
        key_secret_base64: String,
    ) -> napi::Result<Self> {
        let algo = parse_algorithm(&algorithm)?;
        let domain = DomainName::new(&key_name).map_err(BindSdkError::from_core)?;
        let key = TsigKey::from_base64(domain, algo, &key_secret_base64)
            .map_err(BindSdkError::from_core)?;
        Ok(Self {
            host,
            port,
            key: Arc::new(key),
        })
    }

    /// Query server status (`rndc status`).
    #[napi]
    pub async fn status(&self) -> napi::Result<String> {
        self.execute(RndcCommand::Status).await
    }

    /// Reload all zones and configuration (`rndc reload`).
    #[napi]
    pub async fn reload(&self) -> napi::Result<String> {
        self.execute(RndcCommand::Reload { target: None }).await
    }

    /// Reload a specific zone (`rndc reload <zone>`).
    #[napi]
    pub async fn reload_zone(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Reload {
            target: Some(parse_zone_target(&zone)?),
        })
        .await
    }

    /// Reload configuration and add/remove zones (`rndc reconfig`).
    #[napi]
    pub async fn reconfig(&self) -> napi::Result<String> {
        self.execute(RndcCommand::Reconfig).await
    }

    /// Flush all caches (`rndc flush`).
    #[napi]
    pub async fn flush(&self) -> napi::Result<String> {
        self.execute(RndcCommand::Flush { view: None }).await
    }

    /// Flush a specific name from cache (`rndc flush <name>`).
    #[napi]
    pub async fn flush_name(&self, name: String) -> napi::Result<String> {
        let name = DomainName::new(&name).map_err(BindSdkError::from_core)?;
        self.execute(RndcCommand::FlushName { name, view: None })
            .await
    }

    /// Query zone status (`rndc zonestatus <zone>`).
    #[napi]
    pub async fn zone_status(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::ZoneStatus {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Freeze a zone (`rndc freeze <zone>`).
    #[napi]
    pub async fn freeze(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Freeze {
            target: Some(parse_zone_target(&zone)?),
        })
        .await
    }

    /// Thaw a frozen zone (`rndc thaw <zone>`).
    #[napi]
    pub async fn thaw(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Thaw {
            target: Some(parse_zone_target(&zone)?),
        })
        .await
    }

    /// Synchronize zone journal to zone file (`rndc sync`).
    /// If `zone` is provided, syncs only that zone.
    #[napi]
    pub async fn sync(&self, zone: Option<String>) -> napi::Result<String> {
        let target = zone
            .map(|zone| {
                DomainName::new(&zone)
                    .map(ZoneTarget::new)
                    .map_err(BindSdkError::from_core)
            })
            .transpose()?;
        self.execute(RndcCommand::Sync {
            clean: false,
            target,
        })
        .await
    }

    /// Send NOTIFY for a zone (`rndc notify <zone>`).
    #[napi]
    pub async fn notify(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Notify {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Refresh a secondary zone from its primary (`rndc refresh <zone>`).
    #[napi]
    pub async fn refresh(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Refresh {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Force a zone retransfer from primary (`rndc retransfer <zone>`).
    #[napi]
    pub async fn retransfer(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Retransfer {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Dump statistics to the statistics file (`rndc stats`).
    #[napi]
    pub async fn stats(&self) -> napi::Result<String> {
        self.execute(RndcCommand::Stats).await
    }

    /// Dump the database to the dump file (`rndc dumpdb`).
    #[napi]
    pub async fn dumpdb(&self) -> napi::Result<String> {
        self.execute(RndcCommand::DumpDb {
            options: DumpDbOptions::default(),
        })
        .await
    }

    /// Sign a zone with DNSSEC keys (`rndc sign <zone>`).
    #[napi]
    pub async fn sign(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::Sign {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Delete a zone at runtime (`rndc delzone <zone>`).
    #[napi]
    pub async fn delzone(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::DelZone {
            target: parse_zone_target(&zone)?,
            clean: false,
        })
        .await
    }

    /// Show a zone's runtime configuration (`rndc showzone <zone>`).
    #[napi]
    pub async fn showzone(&self, zone: String) -> napi::Result<String> {
        self.execute(RndcCommand::ShowZone {
            target: parse_zone_target(&zone)?,
        })
        .await
    }

    /// Send a raw rndc command string.
    #[napi]
    pub async fn raw(&self, command: String) -> napi::Result<String> {
        self.execute(RndcCommand::Raw(command)).await
    }
}

fn parse_zone_target(zone: &str) -> napi::Result<ZoneTarget> {
    DomainName::new(zone)
        .map(ZoneTarget::new)
        .map_err(BindSdkError::from_core)
}

impl JsRndcClient {
    /// Execute an rndc command over a fresh connection.
    async fn execute(&self, cmd: RndcCommand) -> napi::Result<String> {
        let addr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;

        let conn = RndcConnection::connect(addr)
            .await
            .map_err(BindSdkError::from_net)?;
        let mut conn = conn
            .authenticate(&self.key)
            .await
            .map_err(BindSdkError::from_net)?;
        let resp = conn.command(cmd).await.map_err(BindSdkError::from_net)?;
        conn.close().await.map_err(BindSdkError::from_net)?;

        Ok(resp.text)
    }
}

/// Parse an algorithm string into a `TsigAlgorithm`.
fn parse_algorithm(algorithm: &str) -> napi::Result<TsigAlgorithm> {
    match algorithm {
        "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
        "hmac-sha1" =>
        {
            #[allow(deprecated)]
            Ok(TsigAlgorithm::HmacSha1)
        }
        other => Err(napi::Error::from_reason(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}
