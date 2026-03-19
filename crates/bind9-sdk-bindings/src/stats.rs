// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! JavaScript bindings for the BIND9 statistics-channel HTTP client.

use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_net::StatsHttpClient;
use napi_derive::napi;

use crate::error::BindSdkError;

/// HTTP client for the BIND9 statistics-channel JSON API.
///
/// Fetches server and zone statistics from the statistics-channel endpoint
/// (typically `http://localhost:8053/json/v1`).
#[napi]
pub struct JsStatsClient {
    url: String,
    timeout_secs: u32,
}

#[napi]
impl JsStatsClient {
    /// Create a new statistics client.
    ///
    /// `url` should point to the BIND9 JSON statistics endpoint
    /// (e.g., `"http://127.0.0.1:8053/json/v1"`).
    /// `timeoutSecs` is the HTTP request timeout in seconds (default: 10).
    #[napi(constructor)]
    pub fn new(url: String, timeout_secs: Option<u32>) -> napi::Result<Self> {
        if url.is_empty() {
            return Err(napi::Error::from_reason("stats URL must not be empty"));
        }
        Ok(Self {
            url,
            timeout_secs: timeout_secs.unwrap_or(10),
        })
    }

    /// Fetch server-level statistics.
    ///
    /// Returns the raw JSON response from the `/server` endpoint.
    #[napi]
    pub async fn server_stats(&self) -> napi::Result<serde_json::Value> {
        let client = StatsHttpClient::new(&self.url, Duration::from_secs(u64::from(self.timeout_secs)))
            .map_err(BindSdkError::from_net)?;

        let stats = client
            .fetch_server_stats()
            .await
            .map_err(BindSdkError::from_net)?;

        // Convert the typed ServerStats back to JSON for JS consumption
        Ok(serde_json::json!({
            "bootTime": stats.boot_time,
            "configTime": stats.config_time,
            "currentTime": stats.current_time,
            "version": stats.version,
        }))
    }

    /// Fetch zone-level statistics for a specific zone.
    ///
    /// Returns zone metadata as a JSON object.
    #[napi]
    pub async fn zone_stats(&self, zone: String) -> napi::Result<serde_json::Value> {
        let domain = DomainName::new(&zone).map_err(BindSdkError::from_core)?;
        let client = StatsHttpClient::new(&self.url, Duration::from_secs(u64::from(self.timeout_secs)))
            .map_err(BindSdkError::from_net)?;

        let stats = client
            .fetch_zone_stats(&domain)
            .await
            .map_err(BindSdkError::from_net)?;

        Ok(serde_json::json!({
            "name": stats.name.to_string(),
            "class": stats.class.to_string(),
            "serial": stats.serial.value(),
            "zoneType": stats.zone_type,
        }))
    }
}
