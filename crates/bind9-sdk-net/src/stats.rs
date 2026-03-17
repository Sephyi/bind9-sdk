// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Statistics-channel HTTP client for BIND9.
//!
//! Fetches server and zone statistics from the BIND9 statistics-channel
//! JSON API (typically at `http://localhost:8053/json/v1`).

use serde::Deserialize;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::{RecordClass, Serial};
use bind9_sdk_core::traits::{ServerStats, ZoneStats};

use crate::error::NetError;

/// Raw JSON structure from BIND9 statistics-channel `/json/v1/server`.
///
/// Only the fields we need for v0.1.0 are included. Unknown fields
/// are silently ignored via `#[serde(deny_unknown_fields)]` NOT being set.
#[derive(Debug, Deserialize)]
struct RawServerStats {
    boot_time: Option<String>,
    config_time: Option<String>,
    current_time: Option<String>,
    version: Option<String>,
}

/// Raw JSON structure for a single zone entry in `/json/v1/zones`.
#[derive(Debug, Deserialize)]
struct RawZoneEntry {
    name: String,
    #[serde(rename = "class")]
    dns_class: Option<String>,
    serial: Option<u32>,
    #[serde(rename = "type")]
    zone_type: Option<String>,
    #[serde(rename = "rcodes")]
    #[allow(dead_code)]
    rcodes: Option<serde_json::Value>,
}

impl From<RawServerStats> for ServerStats {
    fn from(raw: RawServerStats) -> Self {
        ServerStats::new(
            raw.boot_time,
            raw.config_time,
            raw.current_time,
            raw.version,
        )
    }
}

/// Convert a raw zone JSON entry to a typed `ZoneStats`.
///
/// Returns `NetError` if the zone name is not a valid DNS name.
fn zone_stats_from_raw(raw: &RawZoneEntry) -> Result<ZoneStats, NetError> {
    // Append trailing dot if not present (BIND9 JSON uses relative names)
    let name_str = if raw.name.ends_with('.') {
        raw.name.clone()
    } else {
        format!("{}.", raw.name)
    };
    let name = DomainName::new(&name_str)
        .map_err(|e| NetError::Protocol(format!("invalid zone name in stats: {e}")))?;

    let class = match raw.dns_class.as_deref() {
        Some("IN") | None => RecordClass::IN,
        Some("CH") => RecordClass::CH,
        Some("HS") => RecordClass::HS,
        Some(other) => other
            .strip_prefix("CLASS")
            .and_then(|n| n.parse::<u16>().ok())
            .map(RecordClass::Unknown)
            .unwrap_or(RecordClass::IN),
    };

    let serial = Serial::new(raw.serial.unwrap_or(0));
    let zone_type = raw.zone_type.clone().unwrap_or_else(|| "unknown".into());

    Ok(ZoneStats::new(name, class, serial, None, zone_type))
}

/// HTTP client for the BIND9 statistics-channel JSON API.
pub struct StatsHttpClient {
    url: String,
    http: reqwest::Client,
}

impl StatsHttpClient {
    /// Create a new stats client targeting the given URL.
    ///
    /// The URL should point to the JSON endpoint, e.g., `http://localhost:8053/json/v1`.
    /// The `timeout` controls how long each HTTP request waits before giving up.
    pub fn new(url: &str, timeout: std::time::Duration) -> Result<Self, NetError> {
        if url.is_empty() {
            return Err(NetError::Connection("stats URL is empty".into()));
        }
        let url = url.strip_suffix('/').unwrap_or(url).to_string();
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { url, http })
    }

    /// Create a stats client with a custom authorization header.
    ///
    /// Use when the statistics-channel is protected by HTTP auth.
    pub fn with_auth(
        url: &str,
        timeout: std::time::Duration,
        auth_header: &str,
    ) -> Result<Self, NetError> {
        if url.is_empty() {
            return Err(NetError::Connection("stats URL is empty".into()));
        }
        let url = url.strip_suffix('/').unwrap_or(url).to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        let header_value = reqwest::header::HeaderValue::from_str(auth_header)
            .map_err(|e| NetError::Connection(format!("invalid auth header: {e}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, header_value);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { url, http })
    }

    /// Fetch server-level statistics from the BIND9 statistics-channel.
    ///
    /// Hits `{url}/server` (or `{url}` if the URL already ends with `/server`).
    pub async fn fetch_server_stats(&self) -> Result<ServerStats, NetError> {
        let endpoint = if self.url.ends_with("/server") {
            self.url.clone()
        } else {
            format!("{}/server", self.url)
        };

        let response = self
            .http
            .get(&endpoint)
            .send()
            .await
            .map_err(|e| NetError::Connection(format!("stats HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(NetError::Http {
                status: status.as_u16(),
                body,
            });
        }

        let raw: RawServerStats = response
            .json()
            .await
            .map_err(|e| NetError::Protocol(format!("failed to parse stats JSON: {e}")))?;

        Ok(ServerStats::from(raw))
    }

    /// Fetch zone-level statistics for a specific zone.
    ///
    /// Queries the zones endpoint and searches for the named zone in the response.
    pub async fn fetch_zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, NetError> {
        let endpoint = if self.url.ends_with("/zones") {
            self.url.clone()
        } else {
            format!("{}/zones", self.url)
        };

        let response = self
            .http
            .get(&endpoint)
            .send()
            .await
            .map_err(|e| NetError::Connection(format!("stats HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(NetError::Http {
                status: status.as_u16(),
                body,
            });
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| NetError::Protocol(format!("failed to parse zones JSON: {e}")))?;

        // BIND9 organizes zones under views. Search all views for the zone.
        let zone_display = zone.to_string();
        // Strip trailing dot for comparison (BIND9 JSON uses names without trailing dot)
        let zone_name_no_dot = zone_display.strip_suffix('.').unwrap_or(&zone_display);

        if let Some(views) = body.get("views").and_then(|v| v.as_object()) {
            for (_view_name, view_data) in views {
                if let Some(zones_arr) = view_data.get("zones").and_then(|z| z.as_array()) {
                    for zone_val in zones_arr {
                        let raw: RawZoneEntry =
                            serde_json::from_value(zone_val.clone()).map_err(|e| {
                                NetError::Protocol(format!("failed to parse zone entry: {e}"))
                            })?;
                        if raw.name == zone_name_no_dot {
                            return zone_stats_from_raw(&raw);
                        }
                    }
                }
            }
        }

        Err(NetError::Protocol(format!(
            "zone '{zone_name_no_dot}' not found in statistics-channel response"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_STATS_JSON: &str = r#"{
        "boot_time": "2026-01-15T08:30:00Z",
        "config_time": "2026-01-15T08:30:05Z",
        "current_time": "2026-03-14T12:00:00Z",
        "version": "BIND 9.20.4 (Stable Release)",
        "opcodes": {},
        "rcodes": {},
        "qtypes": {}
    }"#;

    #[test]
    fn deserialize_server_stats_json() {
        let raw: RawServerStats = serde_json::from_str(SERVER_STATS_JSON).unwrap();
        assert_eq!(raw.boot_time.as_deref(), Some("2026-01-15T08:30:00Z"));
        assert_eq!(raw.version.as_deref(), Some("BIND 9.20.4 (Stable Release)"));
    }

    #[test]
    fn deserialize_server_stats_missing_fields() {
        let json = r#"{"version": "BIND 9.20.0"}"#;
        let raw: RawServerStats = serde_json::from_str(json).unwrap();
        assert!(raw.boot_time.is_none());
        assert!(raw.config_time.is_none());
        assert!(raw.current_time.is_none());
        assert_eq!(raw.version.as_deref(), Some("BIND 9.20.0"));
    }

    const ZONE_ENTRY_JSON: &str = r#"{
        "name": "example.com",
        "class": "IN",
        "serial": 2026031401,
        "type": "primary",
        "rcodes": {}
    }"#;

    #[test]
    fn deserialize_zone_entry_json() {
        let raw: RawZoneEntry = serde_json::from_str(ZONE_ENTRY_JSON).unwrap();
        assert_eq!(raw.name, "example.com");
        assert_eq!(raw.dns_class.as_deref(), Some("IN"));
        assert_eq!(raw.serial, Some(2026031401));
        assert_eq!(raw.zone_type.as_deref(), Some("primary"));
    }

    #[test]
    fn deserialize_zone_entry_minimal() {
        let json = r#"{"name": "test.org"}"#;
        let raw: RawZoneEntry = serde_json::from_str(json).unwrap();
        assert_eq!(raw.name, "test.org");
        assert!(raw.dns_class.is_none());
        assert!(raw.serial.is_none());
    }

    #[test]
    fn raw_server_stats_converts_to_core_type() {
        let raw = RawServerStats {
            boot_time: Some("2026-01-15T08:30:00Z".into()),
            config_time: Some("2026-01-15T08:30:05Z".into()),
            current_time: Some("2026-03-14T12:00:00Z".into()),
            version: Some("BIND 9.20.4".into()),
        };
        let stats = ServerStats::from(raw);
        assert_eq!(stats.boot_time.as_deref(), Some("2026-01-15T08:30:00Z"));
        assert_eq!(stats.version.as_deref(), Some("BIND 9.20.4"));
    }

    #[test]
    fn raw_server_stats_none_for_missing_fields() {
        let raw = RawServerStats {
            boot_time: None,
            config_time: None,
            current_time: None,
            version: None,
        };
        let stats = ServerStats::from(raw);
        assert!(stats.boot_time.is_none());
        assert!(stats.version.is_none());
    }

    #[test]
    fn raw_zone_entry_converts_to_zone_stats() {
        let raw = RawZoneEntry {
            name: "example.com".into(),
            dns_class: Some("IN".into()),
            serial: Some(2026031401),
            zone_type: Some("primary".into()),
            rcodes: None,
        };
        let stats = zone_stats_from_raw(&raw).unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
        assert_eq!(stats.class, RecordClass::IN);
        assert_eq!(stats.serial, Serial::new(2026031401));
        assert_eq!(stats.zone_type, "primary");
    }

    #[test]
    fn raw_zone_entry_invalid_name_fails() {
        // A label exceeding 63 bytes is invalid per RFC 1035
        let long_label = "a".repeat(64);
        let raw = RawZoneEntry {
            name: format!("{long_label}.example.com"),
            dns_class: None,
            serial: None,
            zone_type: None,
            rcodes: None,
        };
        assert!(zone_stats_from_raw(&raw).is_err());
    }

    #[test]
    fn stats_http_client_new() {
        let client = StatsHttpClient::new(
            "http://127.0.0.1:8053/json/v1",
            std::time::Duration::from_secs(10),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn stats_http_client_empty_url_fails() {
        let client = StatsHttpClient::new("", std::time::Duration::from_secs(10));
        assert!(client.is_err());
    }

    #[test]
    fn stats_http_client_with_auth() {
        let client = StatsHttpClient::with_auth(
            "http://127.0.0.1:8053/json/v1",
            std::time::Duration::from_secs(10),
            "Bearer test-token-123",
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn fetch_server_stats_returns_http_error_on_failure() {
        // Use a port that nothing listens on
        let client = StatsHttpClient::new(
            "http://127.0.0.1:19999/json/v1",
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let result = client.fetch_server_stats().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NetError::Connection(_)),
            "expected Connection error, got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_zone_stats_returns_error_for_missing_zone() {
        // Use a port that nothing listens on
        let client = StatsHttpClient::new(
            "http://127.0.0.1:19999/json/v1",
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let zone = DomainName::new("nonexistent.test.").unwrap();
        let result = client.fetch_zone_stats(&zone).await;
        assert!(result.is_err());
    }

    #[test]
    fn full_server_stats_json_roundtrip() {
        let json = r#"{
            "boot_time": "2026-01-15T08:30:00Z",
            "config_time": "2026-01-15T08:30:05Z",
            "current_time": "2026-03-14T12:00:00Z",
            "version": "BIND 9.20.4 (Stable Release)",
            "opcodes": {
                "QUERY": 150432,
                "UPDATE": 23,
                "NOTIFY": 7
            },
            "rcodes": {
                "NOERROR": 145000,
                "NXDOMAIN": 5432,
                "SERVFAIL": 0
            },
            "qtypes": {
                "A": 90000,
                "AAAA": 50000,
                "MX": 10432
            },
            "nsstats": {},
            "zonestats": {}
        }"#;
        let raw: RawServerStats = serde_json::from_str(json).unwrap();
        let stats = ServerStats::from(raw);
        assert_eq!(stats.boot_time.as_deref(), Some("2026-01-15T08:30:00Z"));
        assert_eq!(stats.config_time.as_deref(), Some("2026-01-15T08:30:05Z"));
        assert_eq!(stats.current_time.as_deref(), Some("2026-03-14T12:00:00Z"));
        assert_eq!(
            stats.version.as_deref(),
            Some("BIND 9.20.4 (Stable Release)")
        );
    }

    #[test]
    fn zone_stats_class_parsing() {
        let cases = [
            ("IN", RecordClass::IN),
            ("CH", RecordClass::CH),
            ("HS", RecordClass::HS),
            ("CLASS42", RecordClass::Unknown(42)),
        ];
        for (class_str, expected) in cases {
            let raw = RawZoneEntry {
                name: "test.example.".into(),
                dns_class: Some(class_str.into()),
                serial: Some(1),
                zone_type: Some("primary".into()),
                rcodes: None,
            };
            let stats = zone_stats_from_raw(&raw).unwrap();
            assert_eq!(
                stats.class, expected,
                "class mismatch for input '{class_str}'"
            );
        }
    }

    #[test]
    fn zone_stats_appends_trailing_dot_to_bare_names() {
        let raw = RawZoneEntry {
            name: "example.com".into(),
            dns_class: None,
            serial: Some(100),
            zone_type: None,
            rcodes: None,
        };
        let stats = zone_stats_from_raw(&raw).unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
    }

    #[test]
    fn zone_stats_preserves_existing_trailing_dot() {
        let raw = RawZoneEntry {
            name: "example.com.".into(),
            dns_class: None,
            serial: Some(100),
            zone_type: None,
            rcodes: None,
        };
        let stats = zone_stats_from_raw(&raw).unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
    }

    #[tokio::test]
    #[ignore = "requires live BIND9 with statistics-channel on localhost:8053"]
    async fn integration_fetch_server_stats_from_live_bind9() {
        let client = StatsHttpClient::new(
            "http://127.0.0.1:8053/json/v1",
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        let stats = client.fetch_server_stats().await.unwrap();
        assert!(stats.version.is_some(), "version should be present");
        assert!(stats.boot_time.is_some(), "boot_time should be present");
    }

    #[tokio::test]
    #[ignore = "requires live BIND9 with statistics-channel on localhost:8053"]
    async fn integration_fetch_zone_stats_from_live_bind9() {
        let client = StatsHttpClient::new(
            "http://127.0.0.1:8053/json/v1",
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        let zone = DomainName::new("example.com.").unwrap();
        let stats = client.fetch_zone_stats(&zone).await.unwrap();
        assert_eq!(stats.name, zone);
    }
}
