// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Statistics-channel HTTP client for BIND9.
//!
//! Fetches server and zone statistics from the BIND9 statistics-channel
//! JSON API (typically at `http://localhost:8053/json/v1`).

use std::collections::BTreeMap;

use serde::Deserialize;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::{RecordClass, Serial};
use bind9_sdk_core::traits::{
    CounterSet, MemoryContextStats, MemoryStats, NamedCounter, ServerStats, TrafficHistogram,
    ViewStats, ZoneStats,
};

use crate::error::NetError;

/// Raw JSON structure from BIND9 statistics-channel `/json/v1/server`.
///
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawServerStats {
    json_stats_version: Option<String>,
    boot_time: Option<String>,
    config_time: Option<String>,
    current_time: Option<String>,
    version: Option<String>,
    #[serde(default)]
    opcodes: BTreeMap<String, u64>,
    #[serde(default)]
    rcodes: BTreeMap<String, u64>,
    #[serde(default)]
    views: BTreeMap<String, RawView>,
    #[serde(default)]
    sockstats: BTreeMap<String, u64>,
    memory: Option<RawMemoryStats>,
    #[serde(default)]
    traffic: BTreeMap<String, BTreeMap<String, u64>>,
}

#[derive(Debug, Default, Deserialize)]
struct RawView {
    resolver: Option<RawResolverStats>,
    #[serde(default)]
    zones: Vec<RawZoneEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct RawResolverStats {
    #[serde(default)]
    stats: BTreeMap<String, u64>,
    #[serde(default)]
    qtypes: BTreeMap<String, u64>,
    #[serde(default)]
    cache: BTreeMap<String, u64>,
    #[serde(default)]
    cachestats: BTreeMap<String, u64>,
    #[serde(default)]
    adb: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
struct RawMemoryStats {
    #[serde(rename = "InUse")]
    in_use: u64,
    #[serde(rename = "Malloced")]
    malloced: u64,
    #[serde(default)]
    contexts: Vec<RawMemoryContextStats>,
}

#[derive(Debug, Deserialize)]
struct RawMemoryContextStats {
    id: String,
    name: String,
    references: u64,
    malloced: u64,
    #[serde(rename = "inuse")]
    in_use: u64,
    pools: u64,
    hiwater: u64,
    lowater: u64,
}

/// Raw JSON structure for a single zone entry in `/json/v1/zones`.
#[derive(Debug, Default, Deserialize)]
struct RawZoneEntry {
    name: String,
    #[serde(rename = "class")]
    dns_class: Option<String>,
    serial: Option<u32>,
    #[serde(rename = "type")]
    zone_type: Option<String>,
    loaded: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawZonesResponse {
    #[serde(default)]
    views: BTreeMap<String, RawView>,
}

impl From<RawServerStats> for ServerStats {
    fn from(raw: RawServerStats) -> Self {
        let views = raw
            .views
            .into_iter()
            .filter_map(|(name, view)| {
                view.resolver.map(|resolver| {
                    let mut stats = ViewStats::default();
                    stats.name = name;
                    stats.resolver_stats = counter_set(resolver.stats);
                    stats.query_types = counter_set(resolver.qtypes);
                    stats.cache = counter_set(resolver.cache);
                    stats.cache_stats = counter_set(resolver.cachestats);
                    stats.adb = counter_set(resolver.adb);
                    stats
                })
            })
            .collect();
        let traffic = raw
            .traffic
            .into_iter()
            .map(|(name, buckets)| {
                let mut histogram = TrafficHistogram::default();
                histogram.name = name;
                histogram.buckets = counter_set(buckets);
                histogram
            })
            .collect();
        let memory = raw.memory.map(|memory| {
            let contexts = memory
                .contexts
                .into_iter()
                .map(|context| {
                    let mut stats = MemoryContextStats::default();
                    stats.id = context.id;
                    stats.name = context.name;
                    stats.references = context.references;
                    stats.malloced = context.malloced;
                    stats.in_use = context.in_use;
                    stats.pools = context.pools;
                    stats.high_water = context.hiwater;
                    stats.low_water = context.lowater;
                    stats
                })
                .collect();
            let mut stats = MemoryStats::default();
            stats.in_use = memory.in_use;
            stats.malloced = memory.malloced;
            stats.contexts = contexts;
            stats
        });

        let mut stats = ServerStats::default();
        stats.json_stats_version = raw.json_stats_version;
        stats.boot_time = raw.boot_time;
        stats.config_time = raw.config_time;
        stats.current_time = raw.current_time;
        stats.version = raw.version;
        stats.opcodes = counter_set(raw.opcodes);
        stats.rcodes = counter_set(raw.rcodes);
        stats.views = views;
        stats.socket = counter_set(raw.sockstats);
        stats.memory = memory;
        stats.traffic = traffic;
        stats
    }
}

fn counter_set(counters: BTreeMap<String, u64>) -> CounterSet {
    CounterSet::new(
        counters
            .into_iter()
            .map(|(name, value)| NamedCounter::new(name, value))
            .collect(),
    )
}

/// Convert a raw zone JSON entry to a typed `ZoneStats`.
///
/// Returns `NetError` if the zone name is not a valid DNS name.
fn zone_stats_from_raw(view: &str, raw: &RawZoneEntry) -> Result<ZoneStats, NetError> {
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

    Ok(ZoneStats::new_in_view(
        view.into(),
        name,
        class,
        serial,
        zone_type,
        raw.loaded.clone(),
    ))
}

fn parse_zones_response(body: RawZonesResponse) -> Result<Vec<ZoneStats>, NetError> {
    let mut zones = Vec::new();
    for (view_name, view) in body.views {
        for raw in view.zones {
            zones.push(zone_stats_from_raw(&view_name, &raw)?);
        }
    }

    zones.sort_by(|left, right| {
        left.name
            .to_string()
            .cmp(&right.name.to_string())
            .then_with(|| left.view.cmp(&right.view))
    });
    Ok(zones)
}

fn select_zone_stats(
    zones: Vec<ZoneStats>,
    zone: &DomainName,
    view: Option<&str>,
) -> Result<ZoneStats, NetError> {
    let mut matches = zones
        .into_iter()
        .filter(|candidate| {
            candidate.name == *zone && view.is_none_or(|view| candidate.view == view)
        })
        .collect::<Vec<_>>();

    match matches.len() {
        0 => {
            let view_suffix = view
                .map(|view| format!(" in view `{view}`"))
                .unwrap_or_default();
            Err(NetError::Protocol(format!(
                "zone `{}` not found{view_suffix} in statistics-channel response",
                zone.to_string().trim_end_matches('.')
            )))
        }
        1 => Ok(matches.remove(0)),
        _ => Err(NetError::Protocol(format!(
            "zone `{}` exists in multiple views; select a view explicitly",
            zone.to_string().trim_end_matches('.')
        ))),
    }
}

fn zones_endpoint(url: &str) -> String {
    if url.ends_with("/zones") {
        url.into()
    } else if let Some(base) = url.strip_suffix("/server") {
        format!("{base}/zones")
    } else {
        format!("{url}/zones")
    }
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
        let url = validate_stats_url(url)?;
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            url: url.to_string(),
            http,
        })
    }

    /// Create a stats client with a custom authorization header.
    ///
    /// Use when the statistics-channel is protected by HTTP auth.
    pub fn with_auth(
        url: &str,
        timeout: std::time::Duration,
        auth_header: &str,
    ) -> Result<Self, NetError> {
        let url = validate_stats_url(url)?;
        let mut headers = reqwest::header::HeaderMap::new();
        let header_value = reqwest::header::HeaderValue::from_str(auth_header)
            .map_err(|e| NetError::Connection(format!("invalid auth header: {e}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, header_value);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            url: url.to_string(),
            http,
        })
    }

    /// Fetch server-level statistics from the BIND9 statistics-channel.
    ///
    /// Fetches the configured endpoint. Pointing the client at `/json/v1`
    /// returns BIND's aggregate response, including socket, memory, traffic,
    /// and per-view resolver counters. A `/server` URL yields the documented
    /// server-only subset.
    pub async fn fetch_server_stats(&self) -> Result<ServerStats, NetError> {
        let response = self
            .http
            .get(&self.url)
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
    /// Queries the zones endpoint and searches for the named zone. Returns an
    /// error when the same zone exists in multiple views.
    pub async fn fetch_zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, NetError> {
        let zones = self.fetch_zones().await?;
        select_zone_stats(zones, zone, None)
    }

    /// Fetch zone-level statistics for a zone in one named BIND view.
    pub async fn fetch_zone_stats_in_view(
        &self,
        view: &str,
        zone: &DomainName,
    ) -> Result<ZoneStats, NetError> {
        let zones = self.fetch_zones().await?;
        select_zone_stats(zones, zone, Some(view))
    }

    /// Fetch all zones from all views exposed by the statistics channel.
    pub async fn fetch_zones(&self) -> Result<Vec<ZoneStats>, NetError> {
        let endpoint = zones_endpoint(&self.url);

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

        let body: RawZonesResponse = response
            .json()
            .await
            .map_err(|e| NetError::Protocol(format!("failed to parse zones JSON: {e}")))?;
        parse_zones_response(body)
    }
}

/// Parse and enforce the statistics-channel transport policy.
///
/// Plain HTTP is permitted only for loopback hosts. Remote endpoints must use
/// HTTPS because the statistics channel exposes operational metadata.
fn validate_stats_url(url: &str) -> Result<reqwest::Url, NetError> {
    if url.is_empty() {
        return Err(NetError::Connection("stats URL is empty".into()));
    }

    let normalized = url.strip_suffix('/').unwrap_or(url);
    let parsed = reqwest::Url::parse(normalized)
        .map_err(|e| NetError::Connection(format!("invalid stats URL: {e}")))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(NetError::Connection(format!(
            "unsupported stats URL scheme `{}`",
            parsed.scheme()
        )));
    }

    let is_loopback = parsed.host_str().is_some_and(|host| {
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        host.eq_ignore_ascii_case("localhost")
            || host.eq_ignore_ascii_case("localhost.")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });

    if parsed.scheme() == "http" && !is_loopback {
        return Err(NetError::TlsRequired {
            remote: parsed.to_string(),
        });
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_STATS_JSON: &str = r#"{
        "json-stats-version": "1.8",
        "boot-time": "2026-01-15T08:30:00Z",
        "config-time": "2026-01-15T08:30:05Z",
        "current-time": "2026-03-14T12:00:00Z",
        "version": "BIND 9.20.4 (Stable Release)",
        "opcodes": {"QUERY": 160, "UPDATE": 3},
        "rcodes": {"NOERROR": 155, "SERVFAIL": 5},
        "views": {
            "_default": {
                "resolver": {
                    "stats": {"Queryv4": 120, "BucketSize": 3},
                    "qtypes": {"A": 90, "AAAA": 30},
                    "cache": {"A": 8},
                    "cachestats": {"CacheHits": 10, "CacheMisses": 2},
                    "adb": {"nentries": 4}
                }
            }
        },
        "sockstats": {"UDP4Open": 6, "TCP4Accept": 42},
        "memory": {
            "InUse": 7201830,
            "Malloced": 7201830,
            "contexts": [{
                "id": "0xffffb1060000",
                "name": "OpenSSL",
                "references": 1,
                "malloced": 480104,
                "inuse": 480104,
                "pools": 0,
                "hiwater": 0,
                "lowater": 0
            }]
        },
        "traffic": {
            "dns-udp-requests-sizes-received-ipv4": {
                "0-15": 2,
                "16-31": 8
            }
        }
    }"#;

    #[test]
    fn deserialize_server_stats_json() {
        let raw: RawServerStats = serde_json::from_str(SERVER_STATS_JSON).unwrap();
        assert_eq!(raw.boot_time.as_deref(), Some("2026-01-15T08:30:00Z"));
        assert_eq!(raw.version.as_deref(), Some("BIND 9.20.4 (Stable Release)"));
        let stats = ServerStats::from(raw);
        assert_eq!(stats.json_stats_version.as_deref(), Some("1.8"));
        assert_eq!(stats.opcodes.get("QUERY"), Some(160));
        assert_eq!(stats.rcodes.get("SERVFAIL"), Some(5));
        assert_eq!(stats.socket.get("TCP4Accept"), Some(42));
        assert_eq!(stats.views[0].name, "_default");
        assert_eq!(stats.views[0].resolver_stats.get("Queryv4"), Some(120));
        assert_eq!(stats.views[0].cache_stats.get("CacheHits"), Some(10));
        assert_eq!(
            stats.memory.as_ref().map(|memory| memory.in_use),
            Some(7201830)
        );
        assert_eq!(stats.memory.as_ref().unwrap().contexts[0].name, "OpenSSL");
        assert_eq!(stats.traffic[0].buckets.get("16-31"), Some(8),);
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
        "loaded": "2026-03-14T11:58:00Z"
    }"#;

    #[test]
    fn deserialize_zone_entry_json() {
        let raw: RawZoneEntry = serde_json::from_str(ZONE_ENTRY_JSON).unwrap();
        assert_eq!(raw.name, "example.com");
        assert_eq!(raw.dns_class.as_deref(), Some("IN"));
        assert_eq!(raw.serial, Some(2026031401));
        assert_eq!(raw.zone_type.as_deref(), Some("primary"));
        assert_eq!(raw.loaded.as_deref(), Some("2026-03-14T11:58:00Z"));
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
            ..RawServerStats::default()
        };
        let stats = ServerStats::from(raw);
        assert_eq!(stats.boot_time.as_deref(), Some("2026-01-15T08:30:00Z"));
        assert_eq!(stats.version.as_deref(), Some("BIND 9.20.4"));
    }

    #[test]
    fn raw_server_stats_none_for_missing_fields() {
        let raw = RawServerStats::default();
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
            loaded: None,
        };
        let stats = zone_stats_from_raw("_default", &raw).unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
        assert_eq!(stats.view, "_default");
        assert_eq!(stats.class, RecordClass::IN);
        assert_eq!(stats.serial, Serial::new(2026031401));
        assert_eq!(stats.zone_type, "primary");
        assert_eq!(stats.loaded.as_deref(), None);
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
            loaded: None,
        };
        assert!(zone_stats_from_raw("_default", &raw).is_err());
    }

    #[test]
    fn parse_zones_response_returns_all_views() {
        let json = serde_json::json!({
            "views": {
                "_default": {
                    "zones": [
                        {
                            "name": "example.com",
                            "class": "IN",
                            "serial": 2026031401,
                            "type": "primary"
                        }
                    ]
                },
                "internal": {
                    "zones": [
                        {
                            "name": "corp.example",
                            "class": "IN",
                            "serial": 42,
                            "type": "secondary"
                        }
                    ]
                }
            }
        });

        let raw: RawZonesResponse = serde_json::from_value(json).unwrap();
        let zones = parse_zones_response(raw).unwrap();
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0].name, DomainName::new("corp.example.").unwrap());
        assert_eq!(zones[0].view, "internal");
        assert_eq!(zones[0].zone_type, "secondary");
        assert_eq!(zones[1].name, DomainName::new("example.com.").unwrap());
        assert_eq!(zones[1].view, "_default");
    }

    #[test]
    fn zone_selection_rejects_ambiguous_names_across_views() {
        let zone = DomainName::new("shared.example.").unwrap();
        let zones = vec![
            ZoneStats::new_in_view(
                "_default".into(),
                zone.clone(),
                RecordClass::IN,
                Serial::new(1),
                "primary".into(),
                None,
            ),
            ZoneStats::new_in_view(
                "internal".into(),
                zone.clone(),
                RecordClass::IN,
                Serial::new(2),
                "primary".into(),
                None,
            ),
        ];

        let error = select_zone_stats(zones, &zone, None).unwrap_err();
        assert!(error.to_string().contains("multiple views"));
    }

    #[test]
    fn zone_selection_can_target_a_specific_view() {
        let zone = DomainName::new("shared.example.").unwrap();
        let zones = vec![
            ZoneStats::new_in_view(
                "_default".into(),
                zone.clone(),
                RecordClass::IN,
                Serial::new(1),
                "primary".into(),
                None,
            ),
            ZoneStats::new_in_view(
                "internal".into(),
                zone.clone(),
                RecordClass::IN,
                Serial::new(2),
                "primary".into(),
                None,
            ),
        ];

        let selected = select_zone_stats(zones, &zone, Some("internal")).unwrap();
        assert_eq!(selected.view, "internal");
        assert_eq!(selected.serial, Serial::new(2));
    }

    #[test]
    fn zones_endpoint_replaces_server_suffix() {
        assert_eq!(
            zones_endpoint("https://stats.example/json/v1/server"),
            "https://stats.example/json/v1/zones"
        );
        assert_eq!(
            zones_endpoint("https://stats.example/json/v1"),
            "https://stats.example/json/v1/zones"
        );
    }

    #[test]
    fn parse_zones_response_rejects_malformed_zone_entry() {
        let json = serde_json::json!({
            "views": {
                "_default": {
                    "zones": [
                        {
                            "name": 42,
                            "class": "IN"
                        }
                    ]
                }
            }
        });

        assert!(serde_json::from_value::<RawZonesResponse>(json).is_err());
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

    #[test]
    fn stats_http_client_allows_localhost_domain_over_http() {
        let client = StatsHttpClient::new(
            "http://localhost:8053/json/v1",
            std::time::Duration::from_secs(10),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn stats_http_client_allows_ipv6_loopback_over_http() {
        let client = StatsHttpClient::new(
            "http://[::1]:8053/json/v1",
            std::time::Duration::from_secs(10),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn stats_http_client_rejects_remote_plaintext() {
        let err = match StatsHttpClient::new(
            "http://192.0.2.10:8053/json/v1",
            std::time::Duration::from_secs(10),
        ) {
            Ok(_) => panic!("remote plaintext stats URL must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, NetError::TlsRequired { .. }));
    }

    #[test]
    fn stats_http_client_allows_remote_https() {
        let client = StatsHttpClient::new(
            "https://stats.example.com/json/v1",
            std::time::Duration::from_secs(10),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn stats_http_client_rejects_non_http_scheme() {
        let err = match StatsHttpClient::new(
            "file:///var/run/named.stats",
            std::time::Duration::from_secs(10),
        ) {
            Ok(_) => panic!("non-HTTP stats URL must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, NetError::Connection(_)));
        assert!(err.to_string().contains("unsupported stats URL scheme"));
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
            "boot-time": "2026-01-15T08:30:00Z",
            "config-time": "2026-01-15T08:30:05Z",
            "current-time": "2026-03-14T12:00:00Z",
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
                loaded: None,
            };
            let stats = zone_stats_from_raw("_default", &raw).unwrap();
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
            loaded: None,
        };
        let stats = zone_stats_from_raw("_default", &raw).unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
    }

    #[test]
    fn zone_stats_preserves_existing_trailing_dot() {
        let raw = RawZoneEntry {
            name: "example.com.".into(),
            dns_class: None,
            serial: Some(100),
            zone_type: None,
            loaded: None,
        };
        let stats = zone_stats_from_raw("_default", &raw).unwrap();
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
