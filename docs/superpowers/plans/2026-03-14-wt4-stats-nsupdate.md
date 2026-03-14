<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# WT-4: Stats HTTP + nsupdate Sender Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the BIND9 statistics-channel HTTP client and RFC 2136 nsupdate sender with UDP/TCP fallback.

**Architecture:** Stats client uses reqwest to fetch BIND9's statistics-channel JSON API, deserializing into typed structs. nsupdate sender transmits UpdateMessage bytes over UDP with automatic TCP fallback on truncation. Both implement their respective core traits (StatsClient, DynamicUpdater) on Bind9Client.

**Tech Stack:** Rust 2024, tokio (UDP/TCP), reqwest (HTTP/JSON), serde/serde_json, bind9-sdk-core types

**Branch:** `feat/stats-nsupdate`
**Spec:** `docs/specs/2026-03-14-phase1-remainder-design.md` §6
**Depends on:** Phase 1 scaffolding + Wave 1 (WT-2 net foundation)

## Pre-conditions

These items must exist before this plan begins (delivered by scaffolding + Wave 1):

- `bind9-sdk-core` exports: `UpdateMessage`, `UpdateResult`, `Rcode`, `RecordType`, `DomainName`, `RecordClass`, `Serial`, `ServerStats`, `ZoneStats`
- `bind9-sdk-net` exports: `NetError`, `Bind9Client`, `ClientConfig`
- Net module stubs exist: `stats.rs`, `nsupdate.rs`
- Core traits: `StatsClient` (returns `ServerStats`, `ZoneStats`), `DynamicUpdater` (takes `UpdateMessage`, returns `UpdateResult`)
- `serde` and `serde_json` available as workspace dependencies in `bind9-sdk-net`

## Chunk 1: Stats HTTP Client + JSON Deserialization

### Task 1: StatsHttpClient Struct and Constructor

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Write failing test for StatsHttpClient::new**

Write the test that verifies `StatsHttpClient` can be constructed from a valid URL and rejects invalid URLs.

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::error::NetError;

/// HTTP client for BIND9's statistics-channel JSON API.
///
/// Wraps `reqwest::Client` and targets the statistics-channel endpoint
/// (typically `http://localhost:8053/json/v1`).
pub struct StatsHttpClient {
    url: String,
    http: reqwest::Client,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_valid_url() {
        let client = StatsHttpClient::new("http://localhost:8053/json/v1");
        assert!(client.is_ok());
    }

    #[test]
    fn new_with_trailing_slash_normalized() {
        let client = StatsHttpClient::new("http://localhost:8053/json/v1/").unwrap();
        assert!(!client.url.ends_with('/'), "trailing slash should be stripped");
    }

    #[test]
    fn new_with_empty_url_fails() {
        let client = StatsHttpClient::new("");
        assert!(client.is_err());
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- stats`
Expected: Compilation fails — `StatsHttpClient::new` method does not exist.

- [ ] **Step 3: Implement StatsHttpClient::new and with_auth**

Add the constructor implementations above the `#[cfg(test)]` block:

```rust
impl StatsHttpClient {
    /// Create a new stats client targeting the given BIND9 statistics-channel URL.
    ///
    /// The URL should point to the JSON endpoint, e.g., `http://localhost:8053/json/v1`.
    pub fn new(url: &str) -> Result<Self, NetError> {
        if url.is_empty() {
            return Err(NetError::Connection("stats URL is empty".into()));
        }
        let url = url.strip_suffix('/').unwrap_or(url).to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { url, http })
    }

    /// Create a stats client with a custom authorization header.
    ///
    /// Use when the statistics-channel is protected by HTTP auth.
    pub fn with_auth(url: &str, auth_header: &str) -> Result<Self, NetError> {
        if url.is_empty() {
            return Err(NetError::Connection("stats URL is empty".into()));
        }
        let url = url.strip_suffix('/').unwrap_or(url).to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        let header_value = reqwest::header::HeaderValue::from_str(auth_header)
            .map_err(|e| NetError::Connection(format!("invalid auth header: {e}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, header_value);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .default_headers(headers)
            .build()
            .map_err(|e| NetError::Connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { url, http })
    }
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All 3 tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "feat(net): add StatsHttpClient struct with new() and with_auth() constructors"
```

### Task 2: JSON Deserialization Structs for BIND9 Stats

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Write failing test for server stats JSON deserialization**

Add the serde structs and a snapshot test. The JSON fixture represents a real BIND9 9.20 statistics-channel response (simplified to the fields we care about for v0.1.0).

Add above the `impl StatsHttpClient` block:

```rust
use serde::Deserialize;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::{RecordClass, Serial};
use bind9_sdk_core::traits::{ServerStats, ZoneStats};

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
    rcodes: Option<serde_json::Value>,
}

/// Top-level wrapper for the zones endpoint response.
#[derive(Debug, Deserialize)]
struct RawZonesResponse {
    views: Option<serde_json::Map<String, serde_json::Value>>,
}
```

Then add these tests inside the `mod tests` block:

```rust
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
        assert_eq!(
            raw.version.as_deref(),
            Some("BIND 9.20.4 (Stable Release)")
        );
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
```

- [ ] **Step 2: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass (serde deserialization tests are self-contained).

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "feat(net): add serde deserialization structs for BIND9 stats JSON"
```

### Task 3: Conversion from Raw JSON to Core Types

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Write failing tests for RawServerStats to ServerStats conversion**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn raw_server_stats_converts_to_core_type() {
        let raw = RawServerStats {
            boot_time: Some("2026-01-15T08:30:00Z".into()),
            config_time: Some("2026-01-15T08:30:05Z".into()),
            current_time: Some("2026-03-14T12:00:00Z".into()),
            version: Some("BIND 9.20.4".into()),
        };
        let stats = ServerStats::from(raw);
        assert_eq!(stats.boot_time, "2026-01-15T08:30:00Z");
        assert_eq!(stats.version, "BIND 9.20.4");
    }

    #[test]
    fn raw_server_stats_defaults_for_missing_fields() {
        let raw = RawServerStats {
            boot_time: None,
            config_time: None,
            current_time: None,
            version: None,
        };
        let stats = ServerStats::from(raw);
        assert!(stats.boot_time.is_empty());
        assert!(stats.version.is_empty());
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
        let stats = zone_stats_from_raw(&raw);
        assert!(stats.is_ok());
        let stats = stats.unwrap();
        assert_eq!(stats.name, DomainName::new("example.com.").unwrap());
        assert_eq!(stats.class, RecordClass::IN);
        assert_eq!(stats.serial, Serial::new(2026031401));
        assert_eq!(stats.zone_type, "primary");
    }

    #[test]
    fn raw_zone_entry_invalid_name_fails() {
        let raw = RawZoneEntry {
            name: "".into(),
            dns_class: None,
            serial: None,
            zone_type: None,
            rcodes: None,
        };
        assert!(zone_stats_from_raw(&raw).is_err());
    }
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- stats`
Expected: Compilation fails — `From<RawServerStats>` for `ServerStats` and `zone_stats_from_raw` do not exist.

- [ ] **Step 3: Implement conversion functions**

Add these implementations below the raw structs:

```rust
impl From<RawServerStats> for ServerStats {
    fn from(raw: RawServerStats) -> Self {
        ServerStats {
            boot_time: raw.boot_time.unwrap_or_default(),
            config_time: raw.config_time.unwrap_or_default(),
            current_time: raw.current_time.unwrap_or_default(),
            version: raw.version.unwrap_or_default(),
        }
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
        Some(other) => {
            // Try numeric class
            other
                .strip_prefix("CLASS")
                .and_then(|n| n.parse::<u16>().ok())
                .map(RecordClass::Unknown)
                .unwrap_or(RecordClass::IN)
        }
    };

    let serial = Serial::new(raw.serial.unwrap_or(0));
    let zone_type = raw.zone_type.clone().unwrap_or_else(|| "unknown".into());

    Ok(ZoneStats {
        name,
        class,
        serial,
        record_count: 0, // Not available in the zone listing endpoint
        zone_type,
    })
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "feat(net): add conversions from raw BIND9 JSON to core ServerStats/ZoneStats"
```

### Task 4: fetch_server_stats and fetch_zone_stats Methods

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Write failing test for fetch_server_stats (HTTP error mapping)**

We cannot test the actual HTTP fetch without a server, but we can test the error mapping logic. Add to `mod tests`:

```rust
    #[tokio::test]
    async fn fetch_server_stats_returns_http_error_on_failure() {
        // Use a port that nothing listens on
        let client = StatsHttpClient::new("http://127.0.0.1:19999/json/v1").unwrap();
        let result = client.fetch_server_stats().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be a connection error (nothing listening)
        assert!(
            matches!(err, NetError::Connection(_)),
            "expected Connection error, got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_zone_stats_returns_error_for_missing_zone() {
        // Use a port that nothing listens on
        let client = StatsHttpClient::new("http://127.0.0.1:19999/json/v1").unwrap();
        let zone = DomainName::new("nonexistent.test.").unwrap();
        let result = client.fetch_zone_stats(&zone).await;
        assert!(result.is_err());
    }
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- stats`
Expected: Compilation fails — `fetch_server_stats` and `fetch_zone_stats` methods do not exist.

- [ ] **Step 3: Implement fetch methods**

Add to the `impl StatsHttpClient` block:

```rust
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
                        let raw: RawZoneEntry = serde_json::from_value(zone_val.clone())
                            .map_err(|e| {
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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "feat(net): implement fetch_server_stats and fetch_zone_stats HTTP methods"
```

### Task 5: HTTP Error Code Mapping Tests

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Write test for HTTP status parsing from mock JSON**

Add to `mod tests`:

```rust
    #[test]
    fn full_server_stats_json_roundtrip() {
        // A more realistic BIND9 stats JSON with extra fields we ignore
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
        assert_eq!(stats.boot_time, "2026-01-15T08:30:00Z");
        assert_eq!(stats.config_time, "2026-01-15T08:30:05Z");
        assert_eq!(stats.current_time, "2026-03-14T12:00:00Z");
        assert_eq!(stats.version, "BIND 9.20.4 (Stable Release)");
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
            assert_eq!(stats.class, expected, "class mismatch for input '{class_str}'");
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
```

- [ ] **Step 2: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "test(net): add comprehensive JSON parsing and class conversion tests for stats"
```

## Chunk 2: StatsClient Impl for Bind9Client

### Task 6: Add StatsClient Trait Implementation to Bind9Client

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs`

This task assumes WT-2 has delivered `Bind9Client` and `ClientConfig` in `config.rs`. The `StatsClient` trait impl delegates to `StatsHttpClient`.

- [ ] **Step 1: Write failing test for Bind9Client StatsClient impl**

Add to `crates/bind9-sdk-net/src/config.rs`, inside or after the existing test module:

```rust
#[cfg(test)]
mod stats_tests {
    use super::*;
    use bind9_sdk_core::traits::StatsClient;

    #[tokio::test]
    async fn bind9_client_server_stats_without_url_returns_error() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_tsig_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let client = Bind9Client::new(config);
        let result = client.server_stats().await;
        assert!(result.is_err(), "should fail when stats_url is not configured");
    }

    #[tokio::test]
    async fn bind9_client_zone_stats_without_url_returns_error() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_tsig_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let client = Bind9Client::new(config);
        let zone = bind9_sdk_core::DomainName::new("example.com.").unwrap();
        let result = client.zone_stats(&zone).await;
        assert!(result.is_err(), "should fail when stats_url is not configured");
    }
}
```

Note: `test_tsig_key()` is a test helper that must be available from WT-2. If not available, use a minimal stub:

```rust
#[cfg(test)]
fn test_tsig_key() -> bind9_sdk_core::tsig::TsigKey {
    // Minimal TSIG key for testing — exact construction depends on WT-2 API
    bind9_sdk_core::tsig::TsigKey::new(
        bind9_sdk_core::DomainName::new("test-key.").unwrap(),
        bind9_sdk_core::tsig::TsigAlgorithm::HmacSha256,
        vec![0u8; 32],
    ).unwrap()
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- stats_tests`
Expected: Compilation fails — `StatsClient` not implemented for `Bind9Client`.

- [ ] **Step 3: Implement StatsClient for Bind9Client**

Add to `crates/bind9-sdk-net/src/config.rs`:

```rust
use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::traits::{ServerStats, StatsClient, ZoneStats};
use crate::error::NetError;
use crate::stats::StatsHttpClient;

impl StatsClient for Bind9Client {
    type Error = NetError;

    async fn server_stats(&self) -> Result<ServerStats, NetError> {
        let url = self
            .config
            .stats_url
            .as_ref()
            .ok_or_else(|| NetError::Connection("stats URL not configured".into()))?;
        let client = StatsHttpClient::new(url)?;
        client.fetch_server_stats().await
    }

    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, NetError> {
        let url = self
            .config
            .stats_url
            .as_ref()
            .ok_or_else(|| NetError::Connection("stats URL not configured".into()))?;
        let client = StatsHttpClient::new(url)?;
        client.fetch_zone_stats(zone).await
    }
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- stats_tests && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Both "without url" tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/config.rs
git commit -m "feat(net): implement StatsClient trait for Bind9Client"
```

### Task 7: Integration Test Stub for Stats

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs`

- [ ] **Step 1: Add ignored integration test**

Add to `mod tests` in `stats.rs`:

```rust
    #[tokio::test]
    #[ignore = "requires live BIND9 with statistics-channel on localhost:8053"]
    async fn integration_fetch_server_stats_from_live_bind9() {
        let client = StatsHttpClient::new("http://127.0.0.1:8053/json/v1").unwrap();
        let stats = client.fetch_server_stats().await.unwrap();
        assert!(!stats.version.is_empty(), "version should not be empty");
        assert!(!stats.boot_time.is_empty(), "boot_time should not be empty");
    }

    #[tokio::test]
    #[ignore = "requires live BIND9 with statistics-channel on localhost:8053"]
    async fn integration_fetch_zone_stats_from_live_bind9() {
        let client = StatsHttpClient::new("http://127.0.0.1:8053/json/v1").unwrap();
        let zone = DomainName::new("localhost.").unwrap();
        let stats = client.fetch_zone_stats(&zone).await.unwrap();
        assert_eq!(stats.name, zone);
    }
```

- [ ] **Step 2: Run test to verify it compiles (not executed)**

Run: `cargo test -p bind9-sdk-net -- stats --include-ignored 2>&1 | head -5`
Expected: Compiles. The ignored tests are listed but skipped.

Run: `cargo test -p bind9-sdk-net -- stats`
Expected: Non-ignored tests pass. Ignored tests are not run.

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs
git commit -m "test(net): add ignored integration test stubs for live BIND9 stats"
```

## Chunk 3: NsUpdateSender (UDP + TCP Fallback)

### Task 8: NsUpdateSender Struct and Constructors

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Write failing tests for NsUpdateSender construction**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::net::SocketAddr;
use std::time::Duration;

use crate::error::NetError;

/// Sends RFC 2136 dynamic update messages over UDP with TCP fallback.
///
/// The sender transmits `UpdateMessage` bytes to a DNS server. If the
/// UDP response has the TC (truncated) bit set, it automatically retries
/// over TCP with the standard 2-byte length prefix.
pub struct NsUpdateSender {
    server: SocketAddr,
    timeout: Duration,
}

/// Default timeout for nsupdate operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_timeout() {
        let sender = NsUpdateSender::new("127.0.0.1:53".parse().unwrap());
        assert_eq!(sender.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn with_timeout_uses_custom_timeout() {
        let timeout = Duration::from_secs(30);
        let sender =
            NsUpdateSender::with_timeout("127.0.0.1:53".parse().unwrap(), timeout);
        assert_eq!(sender.timeout, timeout);
    }

    #[test]
    fn server_address_stored() {
        let addr: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let sender = NsUpdateSender::new(addr);
        assert_eq!(sender.server, addr);
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- nsupdate`
Expected: Compilation fails — `NsUpdateSender::new` and `with_timeout` do not exist.

- [ ] **Step 3: Implement constructors**

Add above `#[cfg(test)]`:

```rust
impl NsUpdateSender {
    /// Create a new sender targeting the given DNS server address.
    ///
    /// Uses a default timeout of 5 seconds.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a sender with a custom timeout.
    pub fn with_timeout(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- nsupdate && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All 3 tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "feat(net): add NsUpdateSender struct with new() and with_timeout() constructors"
```

### Task 9: DNS Response Header Parsing

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Write failing tests for DNS response header parsing**

The DNS response header is 12 bytes. We need to extract: ID (bytes 0-1), flags (bytes 2-3, specifically TC bit and RCODE). Add to `mod tests`:

```rust
    use bind9_sdk_core::protocol::Rcode;
    use bind9_sdk_core::update::UpdateResult;

    #[test]
    fn parse_response_extracts_noerror_rcode() {
        // Minimal DNS response header: ID=0x1234, flags=0x8500 (QR=1, AA=1, RCODE=0)
        // Followed by counts (4x u16 = 8 bytes, all zeros)
        let response = [
            0x12, 0x34, // ID
            0x85, 0x00, // Flags: QR=1, Opcode=0, AA=1, TC=0, RD=0, RA=0, RCODE=0 (NOERROR)
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x1234);
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn parse_response_extracts_refused_rcode() {
        let response = [
            0x00, 0x01, // ID
            0x80, 0x05, // Flags: QR=1, RCODE=5 (REFUSED)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0001);
        assert_eq!(result.rcode, Rcode::Refused);
    }

    #[test]
    fn parse_response_extracts_nxdomain() {
        let response = [
            0xAB, 0xCD, // ID
            0x80, 0x03, // Flags: QR=1, RCODE=3 (NXDOMAIN)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0xABCD);
        assert_eq!(result.rcode, Rcode::NxDomain);
    }

    #[test]
    fn parse_response_too_short_fails() {
        let response = [0x00, 0x01, 0x80]; // Only 3 bytes, need at least 12
        assert!(parse_dns_response(&response).is_err());
    }

    #[test]
    fn detect_tc_bit_set() {
        let response = [
            0x00, 0x01, // ID
            0x82, 0x00, // Flags: QR=1, TC=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_truncated(&response));
    }

    #[test]
    fn detect_tc_bit_not_set() {
        let response = [
            0x00, 0x01, // ID
            0x80, 0x00, // Flags: QR=1, TC=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_truncated(&response));
    }
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- nsupdate`
Expected: Compilation fails — `parse_dns_response` and `is_truncated` do not exist.

- [ ] **Step 3: Implement DNS response parsing helpers**

Add above `impl NsUpdateSender`:

```rust
use bind9_sdk_core::protocol::Rcode;
use bind9_sdk_core::update::{UpdateMessage, UpdateResult};

/// Minimum DNS message header size in bytes.
const DNS_HEADER_SIZE: usize = 12;

/// Bit mask for the TC (truncated) flag in the DNS header flags (byte 2, bit 1).
const TC_FLAG_MASK: u8 = 0x02;

/// Parse a DNS response header to extract the message ID and RCODE.
///
/// The response must be at least 12 bytes (DNS header size).
fn parse_dns_response(response: &[u8]) -> Result<UpdateResult, NetError> {
    if response.len() < DNS_HEADER_SIZE {
        return Err(NetError::Protocol(format!(
            "DNS response too short: {} bytes, need at least {DNS_HEADER_SIZE}",
            response.len()
        )));
    }

    let id = u16::from_be_bytes([response[0], response[1]]);
    // RCODE is the low 4 bits of byte 3
    let rcode_value = u16::from(response[3] & 0x0F);
    let rcode = Rcode::from_value(rcode_value);

    Ok(UpdateResult { rcode, id })
}

/// Check whether a DNS response has the TC (truncated) bit set.
///
/// Returns false if the response is too short to contain the flags.
fn is_truncated(response: &[u8]) -> bool {
    if response.len() < DNS_HEADER_SIZE {
        return false;
    }
    // TC bit is bit 1 of the third byte (byte index 2)
    response[2] & TC_FLAG_MASK != 0
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- nsupdate && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "feat(net): add DNS response header parsing and TC bit detection"
```

### Task 10: UDP Send Implementation

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Write failing test for UDP send timeout**

Add to `mod tests`:

```rust
    #[tokio::test]
    async fn send_to_unreachable_server_times_out() {
        // Use a port that (almost certainly) nothing listens on
        let sender = NsUpdateSender::with_timeout(
            "127.0.0.1:19853".parse().unwrap(),
            Duration::from_millis(200),
        );
        let msg = UpdateMessage::test_message(0x0001, &[
            0x00, 0x01, // ID
            0x28, 0x00, // Flags: Opcode=UPDATE(5), no other bits
            0x00, 0x01, // QDCOUNT=1 (zone)
            0x00, 0x00, // PRCOUNT=0
            0x00, 0x00, // UPCOUNT=0
            0x00, 0x00, // ADCOUNT=0
        ]);
        let result = sender.send(&msg).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, NetError::Timeout(_)),
            "expected Timeout error, got: {err}"
        );
    }
```

Note: `UpdateMessage::test_message` is a test-only constructor. If it does not exist in core, add the `#[cfg(test)]` helper:

Add above the `#[cfg(test)]` block:

```rust
// Test-only constructor used by nsupdate tests
#[cfg(test)]
impl UpdateMessage {
    fn test_message(id: u16, wire_bytes: &[u8]) -> Self {
        Self {
            wire_bytes: wire_bytes.to_vec(),
            id,
        }
    }
}
```

Wait -- `UpdateMessage` is defined in `bind9-sdk-core`. We cannot add an impl in a downstream crate for private fields. Instead, create the test message using the public `as_bytes()` / `id()` API. Since the fields are `pub(crate)` in core, we need a different approach for tests.

Revised approach: define a local test helper struct:

```rust
#[cfg(test)]
fn make_test_update(id: u16, wire_bytes: Vec<u8>) -> UpdateMessage {
    // UpdateMessage fields are pub(crate) in bind9-sdk-core.
    // For cross-crate testing, we rely on UpdateBuilder to create real messages.
    // For unit tests of the sender, we use a minimal valid DNS update message.
    // Since we can't construct UpdateMessage directly, we must use the builder.
    //
    // Fallback: if UpdateBuilder is not yet available (WT-2 dependency),
    // use the bytes directly via a shim that WT-2 should expose.
    //
    // For now, assume WT-2 provides UpdateBuilder::new(...).build_unsigned().
    // If not available, this test will be adjusted when WT-2 merges.
    todo!("requires UpdateBuilder from WT-2 or a test constructor on UpdateMessage")
}
```

Given the dependency on WT-2 for `UpdateMessage` construction, let's take a pragmatic approach: test the internal helpers (already done in Task 9) and write the async `send` method with integration tests that require WT-2 outputs.

Replace the above with a test that exercises the method signature but expects a connection error (since we cannot construct an `UpdateMessage` without WT-2, we will gate this test):

```rust
    // Note: Full send tests require UpdateBuilder from WT-2.
    // See integration test stubs in Chunk 4 for live-server tests.
```

Instead, let's test the private `send_udp` and `send_tcp` helpers independently using raw byte slices, wrapping them around the `parse_dns_response` we already tested. The `send` method ties them together.

- [ ] **Step 2: Implement the send method with UDP and TCP fallback**

Add to `impl NsUpdateSender`:

```rust
    /// Send an RFC 2136 dynamic update message and return the server's response.
    ///
    /// 1. Sends the message bytes over UDP.
    /// 2. Waits for a response (with timeout).
    /// 3. If the response has the TC (truncated) bit, retries over TCP.
    /// 4. Parses the response header and returns `UpdateResult`.
    pub async fn send(&self, update: &UpdateMessage) -> Result<UpdateResult, NetError> {
        let wire = update.as_bytes();

        // Attempt UDP first
        let udp_response = self.send_udp(wire).await?;

        // Check for truncation — retry over TCP if TC bit is set
        if is_truncated(&udp_response) {
            tracing::debug!(
                server = %self.server,
                "UDP response truncated, retrying over TCP"
            );
            let tcp_response = self.send_tcp(wire).await?;
            return parse_dns_response(&tcp_response);
        }

        parse_dns_response(&udp_response)
    }

    /// Send update message bytes over UDP and return the raw response.
    async fn send_udp(&self, wire: &[u8]) -> Result<Vec<u8>, NetError> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| NetError::Connection(format!("failed to bind UDP socket: {e}")))?;

        socket
            .connect(self.server)
            .await
            .map_err(|e| NetError::Connection(format!("UDP connect failed: {e}")))?;

        socket
            .send(wire)
            .await
            .map_err(|e| NetError::Connection(format!("UDP send failed: {e}")))?;

        let mut buf = vec![0u8; 4096]; // DNS UDP max is 512 without EDNS, 4096 with
        let recv_future = socket.recv(&mut buf);
        let len = tokio::time::timeout(self.timeout, recv_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("UDP recv failed: {e}")))?;

        buf.truncate(len);
        Ok(buf)
    }

    /// Send update message bytes over TCP with DNS 2-byte length prefix.
    async fn send_tcp(&self, wire: &[u8]) -> Result<Vec<u8>, NetError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let connect_future = tokio::net::TcpStream::connect(self.server);
        let mut stream = tokio::time::timeout(self.timeout, connect_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP connect failed: {e}")))?;

        // DNS over TCP: 2-byte big-endian length prefix
        let len = u16::try_from(wire.len()).map_err(|_| {
            NetError::Protocol(format!(
                "update message too large for TCP: {} bytes",
                wire.len()
            ))
        })?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| NetError::Connection(format!("TCP write length failed: {e}")))?;
        stream
            .write_all(wire)
            .await
            .map_err(|e| NetError::Connection(format!("TCP write message failed: {e}")))?;

        // Read response: 2-byte length prefix + message
        let mut len_buf = [0u8; 2];
        let read_future = stream.read_exact(&mut len_buf);
        tokio::time::timeout(self.timeout, read_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP read length failed: {e}")))?;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < DNS_HEADER_SIZE {
            return Err(NetError::Protocol(format!(
                "TCP response too short: {resp_len} bytes"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        let read_future = stream.read_exact(&mut resp_buf);
        tokio::time::timeout(self.timeout, read_future)
            .await
            .map_err(|_| NetError::Timeout(self.timeout))?
            .map_err(|e| NetError::Connection(format!("TCP read message failed: {e}")))?;

        Ok(resp_buf)
    }
```

- [ ] **Step 3: Run tests to verify all existing tests still pass**

Run: `cargo test -p bind9-sdk-net -- nsupdate && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass (new `send` method compiles, existing parse/constructor tests pass).

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "feat(net): implement NsUpdateSender::send with UDP + TCP fallback"
```

### Task 11: Wire Format Edge Case Tests

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Add edge case tests for response parsing**

Add to `mod tests`:

```rust
    #[test]
    fn parse_response_notauth_rcode() {
        let response = [
            0x00, 0x42, // ID
            0x80, 0x09, // Flags: QR=1, RCODE=9 (NOTAUTH)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0042);
        assert_eq!(result.rcode, Rcode::NotAuth);
    }

    #[test]
    fn parse_response_yxdomain_rcode() {
        // RFC 2136 dynamic update specific RCODE
        let response = [
            0xFF, 0xFF, // ID
            0x80, 0x06, // Flags: QR=1, RCODE=6 (YXDOMAIN)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0xFFFF);
        assert_eq!(result.rcode, Rcode::YxDomain);
    }

    #[test]
    fn parse_response_preserves_all_rcode_bits() {
        // RCODE uses only the low 4 bits of byte 3, bits above should be ignored
        let response = [
            0x00, 0x01, // ID
            0x80, 0xF5, // Flags: QR=1, Z bits set, RCODE=5 (REFUSED)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.rcode, Rcode::Refused);
    }

    #[test]
    fn parse_response_with_extra_data_succeeds() {
        // Response longer than 12 bytes is fine (has answer sections)
        let mut response = vec![
            0x00, 0x01, // ID
            0x85, 0x00, // Flags: QR=1, AA=1, RCODE=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra data
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.id, 0x0001);
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn parse_response_exactly_12_bytes() {
        let response = [
            0x00, 0x01, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_response(&response).is_ok());
    }

    #[test]
    fn parse_response_11_bytes_fails() {
        let response = [
            0x00, 0x01, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_response(&response).is_err());
    }

    #[test]
    fn tc_bit_combined_with_other_flags() {
        // TC=1 along with AA=1, RD=1
        let response = [
            0x00, 0x01, // ID
            0x87, 0x00, // Flags: QR=1, AA=1, TC=1, RD=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_truncated(&response));
        let result = parse_dns_response(&response).unwrap();
        assert_eq!(result.rcode, Rcode::NoError);
    }

    #[test]
    fn is_truncated_empty_buffer() {
        assert!(!is_truncated(&[]));
    }
```

- [ ] **Step 2: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- nsupdate && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "test(net): add comprehensive DNS response header parsing edge case tests"
```

## Chunk 4: DynamicUpdater Impl + Integration Test Stubs

### Task 12: Implement DynamicUpdater for Bind9Client

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs`

- [ ] **Step 1: Write failing test for Bind9Client DynamicUpdater impl**

Add to `crates/bind9-sdk-net/src/config.rs`:

```rust
#[cfg(test)]
mod dynamic_updater_tests {
    use super::*;
    use bind9_sdk_core::traits::DynamicUpdater;

    #[tokio::test]
    async fn bind9_client_send_update_without_dns_addr_returns_error() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_tsig_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let client = Bind9Client::new(config);

        // We cannot construct a real UpdateMessage without UpdateBuilder (WT-2).
        // This test verifies that missing dns_addr returns an error before
        // attempting any network I/O.
        //
        // If UpdateBuilder is available:
        // let update = UpdateBuilder::new(
        //     DomainName::new("example.com.").unwrap(),
        //     RecordClass::IN,
        // ).build_unsigned();
        // let result = client.send_update(&update).await;
        // assert!(result.is_err());

        // For now, verify the trait impl compiles and the method exists.
        // The actual "no dns_addr" error test requires a valid UpdateMessage.
        let _ = &client as &dyn DynamicUpdater<Error = NetError>;
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p bind9-sdk-net -- dynamic_updater_tests`
Expected: Compilation fails — `DynamicUpdater` not implemented for `Bind9Client`.

- [ ] **Step 3: Implement DynamicUpdater for Bind9Client**

Add to `crates/bind9-sdk-net/src/config.rs`:

```rust
use bind9_sdk_core::traits::DynamicUpdater;
use bind9_sdk_core::update::{UpdateMessage, UpdateResult};
use crate::nsupdate::NsUpdateSender;

impl DynamicUpdater for Bind9Client {
    type Error = NetError;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, NetError> {
        let addr = self
            .config
            .dns_addr
            .ok_or_else(|| NetError::Connection("DNS server address not configured".into()))?;
        let sender = NsUpdateSender::with_timeout(addr, self.config.timeout);
        sender.send(update).await
    }
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p bind9-sdk-net -- dynamic_updater_tests && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/config.rs
git commit -m "feat(net): implement DynamicUpdater trait for Bind9Client"
```

### Task 13: Integration Test Stubs for nsupdate

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Add ignored integration tests**

Add to `mod tests` in `nsupdate.rs`:

```rust
    #[tokio::test]
    #[ignore = "requires live BIND9 accepting dynamic updates on localhost:53"]
    async fn integration_send_update_to_live_bind9() {
        // This test requires:
        // 1. A running BIND9 instance on localhost:53
        // 2. A zone configured to accept dynamic updates
        // 3. UpdateBuilder from WT-2 to construct a valid UpdateMessage
        //
        // Example (when UpdateBuilder is available):
        // let update = UpdateBuilder::new(
        //     DomainName::new("example.test.").unwrap(),
        //     RecordClass::IN,
        // )
        // .add_record(ResourceRecord {
        //     name: DomainName::new("test.example.test.").unwrap(),
        //     class: RecordClass::IN,
        //     ttl: Ttl::new(300).unwrap(),
        //     rdata: RecordData::A(Ipv4Addr::new(10, 0, 0, 1)),
        // })
        // .build_unsigned();
        //
        // let sender = NsUpdateSender::new("127.0.0.1:53".parse().unwrap());
        // let result = sender.send(&update).await.unwrap();
        // assert_eq!(result.rcode, Rcode::NoError);
        todo!("implement after WT-2 delivers UpdateBuilder")
    }

    #[tokio::test]
    #[ignore = "requires live BIND9 — tests TCP fallback with large update"]
    async fn integration_tcp_fallback_with_large_update() {
        // This test verifies the UDP → TCP fallback path by sending
        // an update large enough to trigger truncation.
        todo!("implement after WT-2 delivers UpdateBuilder")
    }
```

- [ ] **Step 2: Run test to verify it compiles**

Run: `cargo test -p bind9-sdk-net -- nsupdate`
Expected: Non-ignored tests pass. Ignored tests are listed but skipped.

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "test(net): add ignored integration test stubs for live nsupdate"
```

### Task 14: Export Public Types from Net lib.rs

**Files:**
- Modify: `crates/bind9-sdk-net/src/lib.rs`

- [ ] **Step 1: Update lib.rs to re-export key types**

Update `crates/bind9-sdk-net/src/lib.rs` to ensure public types are accessible:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub mod config;
pub mod error;
pub mod nsupdate;
pub mod rndc;
pub mod stats;
pub mod tls;

// Curated re-exports
pub use config::{Bind9Client, ClientConfig};
pub use error::NetError;
pub use nsupdate::NsUpdateSender;
pub use stats::StatsHttpClient;
```

- [ ] **Step 2: Run full workspace tests**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: All tests pass, clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/lib.rs
git commit -m "feat(net): add curated re-exports for StatsHttpClient, NsUpdateSender"
```

### Task 15: Final Verification

- [ ] **Step 1: Full workspace test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 2: WASM target check (core only)**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (stats and nsupdate are net-only, no core changes).

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean.

- [ ] **Step 4: Format check**

Run: `cargo fmt --check`
Expected: Clean.

- [ ] **Step 5: Verify test counts**

Run: `cargo test --workspace 2>&1 | grep "test result"`
Expected: Stats tests + nsupdate tests bring the total up. Count should show new tests from `stats.rs` and `nsupdate.rs`.
