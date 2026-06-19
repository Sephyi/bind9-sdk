// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! rndc command types and response parsing.
//!
//! Each `RndcCommand` variant maps to a BIND9 `rndc` subcommand.
//! The `to_command_string()` method produces the command text sent
//! inside the ISC message `_data` field.

use std::fmt;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::RecordClass;
use bind9_sdk_core::traits::{FrozenZone, ServerStatus};

/// An rndc command to send to a BIND9 server.
///
/// Covers all rndc commands available in BIND9 9.20.
/// Use `Raw` for commands not yet represented by a named variant.
///
/// # Examples
///
/// ```ignore
/// let cmd = RndcCommand::Status;
/// assert_eq!(cmd.to_command_string(), "status");
///
/// let cmd = RndcCommand::ReloadZone { zone: "example.com".into() };
/// assert_eq!(cmd.to_command_string(), "reload example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RndcCommand {
    /// Query server status.
    Status,
    /// Reload all zones and configuration.
    Reload,
    /// Reload a specific zone.
    ReloadZone { zone: String },
    /// Refresh a secondary zone from its primary.
    Refresh { zone: String },
    /// Force a zone retransfer from primary.
    Retransfer { zone: String },
    /// Freeze a zone (stop dynamic updates).
    Freeze { zone: String },
    /// Thaw a frozen zone (resume dynamic updates).
    Thaw { zone: String },
    /// Synchronize zone journal to zone file.
    /// If `zone` is `None`, syncs all zones.
    Sync { zone: Option<String> },
    /// Flush all caches.
    Flush,
    /// Flush a specific name from cache.
    FlushName { name: String },
    /// Dump statistics to the statistics file.
    Stats,
    /// Dump the database to the dump file.
    DumpDb,
    /// Send NOTIFY for a zone.
    Notify { zone: String },
    /// Set debug trace level.
    /// If `level` is `None`, increments by 1.
    Trace { level: Option<u32> },
    /// Disable debug tracing.
    NoTrace,
    /// Reload configuration and add/remove zones.
    Reconfig,
    /// Sign a zone with DNSSEC keys.
    Sign { zone: String },
    /// Enable or disable DNSSEC validation.
    Validation { enable: bool },
    /// Add a zone at runtime.
    AddZone { zone: String, config: String },
    /// Modify a zone's configuration at runtime.
    ModZone { zone: String, config: String },
    /// Delete a zone at runtime.
    DelZone { zone: String },
    /// Show a zone's runtime configuration.
    ShowZone { zone: String },
    /// Managed-keys operations.
    Managed { subcommand: String },
    /// Query zone status.
    ZoneStatus { zone: String },
    /// Negative Trust Anchor operations.
    /// - `domain: None` = list all NTAs
    /// - `domain: Some(d), lifetime: Some(l)` = add NTA
    /// - `domain: Some(d), lifetime: None` = remove NTA
    NtA {
        domain: Option<String>,
        lifetime: Option<u32>,
    },
    /// Query DNSSEC status for a zone.
    DnssecStatus { zone: String },
    /// Check DS record publication status for a zone.
    DnssecCheckDs { zone: String },
    /// Raw command string -- escape hatch for commands not yet in the enum.
    Raw(String),
}

impl RndcCommand {
    /// Convert to the command string sent in the rndc wire protocol.
    ///
    /// This is the text placed in the `_data` map's `type` field of the
    /// ISC binary message.
    pub fn to_command_string(&self) -> String {
        match self {
            Self::Status => "status".to_string(),
            Self::Reload => "reload".to_string(),
            Self::ReloadZone { zone } => format!("reload {zone}"),
            Self::Refresh { zone } => format!("refresh {zone}"),
            Self::Retransfer { zone } => format!("retransfer {zone}"),
            Self::Freeze { zone } => format!("freeze {zone}"),
            Self::Thaw { zone } => format!("thaw {zone}"),
            Self::Sync { zone: Some(z) } => format!("sync {z}"),
            Self::Sync { zone: None } => "sync".to_string(),
            Self::Flush => "flush".to_string(),
            Self::FlushName { name } => format!("flush {name}"),
            Self::Stats => "stats".to_string(),
            Self::DumpDb => "dumpdb".to_string(),
            Self::Notify { zone } => format!("notify {zone}"),
            Self::Trace { level: Some(l) } => format!("trace {l}"),
            Self::Trace { level: None } => "trace".to_string(),
            Self::NoTrace => "notrace".to_string(),
            Self::Reconfig => "reconfig".to_string(),
            Self::Sign { zone } => format!("sign {zone}"),
            Self::Validation { enable: true } => "validation on".to_string(),
            Self::Validation { enable: false } => "validation off".to_string(),
            Self::AddZone { zone, config } => format!("addzone {zone} {config}"),
            Self::ModZone { zone, config } => format!("modzone {zone} {config}"),
            Self::DelZone { zone } => format!("delzone {zone}"),
            Self::ShowZone { zone } => format!("showzone {zone}"),
            Self::Managed { subcommand } => format!("managed-keys {subcommand}"),
            Self::ZoneStatus { zone } => format!("zonestatus {zone}"),
            Self::NtA {
                domain: None,
                lifetime: _,
            } => "nta -dump".to_string(),
            Self::NtA {
                domain: Some(d),
                lifetime: Some(l),
            } => format!("nta -lifetime {l} {d}"),
            Self::NtA {
                domain: Some(d),
                lifetime: None,
            } => format!("nta -remove {d}"),
            Self::DnssecStatus { zone } => format!("dnssec -status {zone}"),
            Self::DnssecCheckDs { zone } => format!("dnssec -checkds {zone}"),
            Self::Raw(cmd) => cmd.clone(),
        }
    }
}

impl fmt::Display for RndcCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_command_string())
    }
}

/// Response from an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RndcResponse {
    /// The text output from the server (may be multi-line).
    pub text: String,
    /// Parsed result status.
    pub result: RndcResult,
}

/// Result status of an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RndcResult {
    /// Command succeeded.
    Success,
    /// Command failed with an error.
    Error {
        /// Numeric error code from the server (if provided).
        code: u32,
        /// Human-readable error message.
        message: String,
    },
}

impl RndcResponse {
    /// Whether the command succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self.result, RndcResult::Success)
    }

    /// Parse a response from the raw text returned by BIND9.
    ///
    /// BIND9 rndc responses typically start with "rndc: " for errors,
    /// or contain the result text directly for successful commands.
    ///
    /// TODO: Verify response format against BIND9 source / wire captures.
    pub(crate) fn from_text(text: &str) -> Self {
        let is_error = text.starts_with("rndc: ")
            || text.starts_with("unknown command")
            || text.starts_with("not found");

        if is_error {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Error {
                    code: 1,
                    message: text.to_string(),
                },
            }
        } else {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Success,
            }
        }
    }
}

/// Parse the output of `rndc status` into a `ServerStatus` struct.
///
/// # Expected format (BIND9 9.20)
///
/// ```text
/// version: BIND 9.20.0 (Stable Release) <id:abc123>
/// running on myhost: Linux x86_64
/// boot time: Mon, 01 Jan 2026 00:00:00 GMT
/// last configured: Mon, 01 Jan 2026 00:00:00 GMT
/// configuration file: /etc/named.conf
/// CPUs found: 4
/// worker threads: 4
/// number of zones: 42 (0 automatic)
/// debug level: 0
/// server is up and running
/// ```
///
/// TODO: Verify format against BIND9 9.20 output. The format may vary
/// slightly between BIND9 minor versions.
pub(crate) fn parse_server_status(text: &str) -> ServerStatus {
    let version = extract_field(text, "version:").unwrap_or_else(|| "unknown".to_string());

    let running_since = extract_field(text, "boot time:");

    let zone_count = extract_field(text, "number of zones:")
        .and_then(|s| {
            // "42 (0 automatic)" -> try to parse the first number
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let server_up = text.contains("server is up and running");

    ServerStatus::new(
        version,
        running_since,
        zone_count,
        server_up,
        text.to_string(),
    )
}

/// Extract the value after a field label from multi-line text.
///
/// Given text like "version: BIND 9.20.0\nboot time: Mon..." and
/// label "version:", returns Some("BIND 9.20.0").
fn extract_field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(label) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Construct a `FrozenZone` from the zone name used in a freeze command.
///
/// The rndc `freeze` command response does not contain structured data --
/// it just confirms success. The `FrozenZone` is constructed from the
/// command parameters.
pub(crate) fn make_frozen_zone(zone_name: &DomainName) -> FrozenZone {
    FrozenZone::new(zone_name.clone(), RecordClass::IN)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- RndcCommand serialization tests --

    #[test]
    fn command_status() {
        assert_eq!(RndcCommand::Status.to_command_string(), "status");
    }

    #[test]
    fn command_reload() {
        assert_eq!(RndcCommand::Reload.to_command_string(), "reload");
    }

    #[test]
    fn command_reload_zone() {
        let cmd = RndcCommand::ReloadZone {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "reload example.com");
    }

    #[test]
    fn command_refresh() {
        let cmd = RndcCommand::Refresh {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "refresh example.com");
    }

    #[test]
    fn command_retransfer() {
        let cmd = RndcCommand::Retransfer {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "retransfer example.com");
    }

    #[test]
    fn command_freeze() {
        let cmd = RndcCommand::Freeze {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "freeze example.com");
    }

    #[test]
    fn command_thaw() {
        let cmd = RndcCommand::Thaw {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "thaw example.com");
    }

    #[test]
    fn command_sync_all() {
        let cmd = RndcCommand::Sync { zone: None };
        assert_eq!(cmd.to_command_string(), "sync");
    }

    #[test]
    fn command_sync_zone() {
        let cmd = RndcCommand::Sync {
            zone: Some("example.com".into()),
        };
        assert_eq!(cmd.to_command_string(), "sync example.com");
    }

    #[test]
    fn command_flush() {
        assert_eq!(RndcCommand::Flush.to_command_string(), "flush");
    }

    #[test]
    fn command_flush_name() {
        let cmd = RndcCommand::FlushName {
            name: "stale.example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "flush stale.example.com");
    }

    #[test]
    fn command_stats() {
        assert_eq!(RndcCommand::Stats.to_command_string(), "stats");
    }

    #[test]
    fn command_dumpdb() {
        assert_eq!(RndcCommand::DumpDb.to_command_string(), "dumpdb");
    }

    #[test]
    fn command_notify() {
        let cmd = RndcCommand::Notify {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "notify example.com");
    }

    #[test]
    fn command_trace_increment() {
        let cmd = RndcCommand::Trace { level: None };
        assert_eq!(cmd.to_command_string(), "trace");
    }

    #[test]
    fn command_trace_level() {
        let cmd = RndcCommand::Trace { level: Some(3) };
        assert_eq!(cmd.to_command_string(), "trace 3");
    }

    #[test]
    fn command_notrace() {
        assert_eq!(RndcCommand::NoTrace.to_command_string(), "notrace");
    }

    #[test]
    fn command_reconfig() {
        assert_eq!(RndcCommand::Reconfig.to_command_string(), "reconfig");
    }

    #[test]
    fn command_sign() {
        let cmd = RndcCommand::Sign {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "sign example.com");
    }

    #[test]
    fn command_validation_on() {
        let cmd = RndcCommand::Validation { enable: true };
        assert_eq!(cmd.to_command_string(), "validation on");
    }

    #[test]
    fn command_validation_off() {
        let cmd = RndcCommand::Validation { enable: false };
        assert_eq!(cmd.to_command_string(), "validation off");
    }

    #[test]
    fn command_addzone() {
        let cmd = RndcCommand::AddZone {
            zone: "new.example.com".into(),
            config: "{ type primary; file \"new.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "addzone new.example.com { type primary; file \"new.zone\"; };"
        );
    }

    #[test]
    fn command_modzone() {
        let cmd = RndcCommand::ModZone {
            zone: "example.com".into(),
            config: "{ type primary; file \"updated.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "modzone example.com { type primary; file \"updated.zone\"; };"
        );
    }

    #[test]
    fn command_delzone() {
        let cmd = RndcCommand::DelZone {
            zone: "old.example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "delzone old.example.com");
    }

    #[test]
    fn command_showzone() {
        let cmd = RndcCommand::ShowZone {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "showzone example.com");
    }

    #[test]
    fn command_managed_keys() {
        let cmd = RndcCommand::Managed {
            subcommand: "status".into(),
        };
        assert_eq!(cmd.to_command_string(), "managed-keys status");
    }

    #[test]
    fn command_zonestatus() {
        let cmd = RndcCommand::ZoneStatus {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "zonestatus example.com");
    }

    #[test]
    fn command_nta_list() {
        let cmd = RndcCommand::NtA {
            domain: None,
            lifetime: None,
        };
        assert_eq!(cmd.to_command_string(), "nta -dump");
    }

    #[test]
    fn command_nta_add() {
        let cmd = RndcCommand::NtA {
            domain: Some("bad.example.com".into()),
            lifetime: Some(3600),
        };
        assert_eq!(
            cmd.to_command_string(),
            "nta -lifetime 3600 bad.example.com"
        );
    }

    #[test]
    fn command_nta_remove() {
        let cmd = RndcCommand::NtA {
            domain: Some("bad.example.com".into()),
            lifetime: None,
        };
        assert_eq!(cmd.to_command_string(), "nta -remove bad.example.com");
    }

    #[test]
    fn command_dnssec_status() {
        let cmd = RndcCommand::DnssecStatus {
            zone: "example.com".into(),
        };
        assert_eq!(cmd.to_command_string(), "dnssec -status example.com");
    }

    #[test]
    fn command_dnssec_checkds() {
        let published = RndcCommand::DnssecCheckDs {
            zone: "example.com".into(),
            state: DsState::Published,
        };
        assert_eq!(
            published.to_command_string(),
            "dnssec -checkds published example.com"
        );

        let withdrawn = RndcCommand::DnssecCheckDs {
            zone: "example.com".into(),
            state: DsState::Withdrawn,
        };
        assert_eq!(
            withdrawn.to_command_string(),
            "dnssec -checkds withdrawn example.com"
        );
    }

    #[test]
    fn command_raw() {
        let cmd = RndcCommand::Raw("custom-command arg1 arg2".into());
        assert_eq!(cmd.to_command_string(), "custom-command arg1 arg2");
    }

    #[test]
    fn command_display_matches_command_string() {
        let cmd = RndcCommand::Status;
        assert_eq!(format!("{cmd}"), cmd.to_command_string());
    }

    // -- RndcResponse tests --

    #[test]
    fn response_success() {
        let resp = RndcResponse::from_text("version: BIND 9.20.0\nserver is up and running");
        assert!(resp.is_success());
        assert!(resp.text.contains("BIND 9.20.0"));
    }

    #[test]
    fn response_error_rndc_prefix() {
        let resp = RndcResponse::from_text("rndc: connect failed: connection refused");
        assert!(!resp.is_success());
        if let RndcResult::Error { message, .. } = &resp.result {
            assert!(message.contains("connect failed"));
        } else {
            panic!("expected error result");
        }
    }

    #[test]
    fn response_is_success_returns_false_for_error() {
        let resp = RndcResponse {
            text: "failed".into(),
            result: RndcResult::Error {
                code: 1,
                message: "failed".into(),
            },
        };
        assert!(!resp.is_success());
    }

    #[test]
    fn response_unknown_command() {
        let resp = RndcResponse::from_text("unknown command");
        assert!(!resp.is_success());
    }

    #[test]
    fn response_not_found() {
        let resp = RndcResponse::from_text("not found");
        assert!(!resp.is_success());
    }

    #[test]
    fn response_zone_name_with_error_is_not_false_positive() {
        // Zone names containing "error" should NOT be treated as errors (F-015)
        let resp = RndcResponse::from_text("zone error.example.com/IN: loaded serial 2024010101");
        assert!(
            resp.is_success(),
            "zone name containing 'error' must not trigger false positive"
        );
    }

    // -- ServerStatus parsing tests --

    #[test]
    fn parse_status_full_output() {
        let text = "\
version: BIND 9.20.0 (Stable Release) <id:abc123>
running on myhost: Linux x86_64
boot time: Mon, 01 Jan 2026 00:00:00 GMT
last configured: Mon, 01 Jan 2026 00:00:00 GMT
configuration file: /etc/named.conf
CPUs found: 4
worker threads: 4
number of zones: 42 (0 automatic)
debug level: 0
xfers running: 0
server is up and running";

        let status = parse_server_status(text);
        assert!(status.version.contains("BIND 9.20.0"));
        assert_eq!(
            status.running_since,
            Some("Mon, 01 Jan 2026 00:00:00 GMT".into())
        );
        assert_eq!(status.zone_count, 42);
        assert!(status.server_up);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn parse_status_missing_version() {
        let text = "server is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.version, "unknown");
        assert!(status.server_up);
    }

    #[test]
    fn parse_status_server_down() {
        let text = "version: BIND 9.20.0\nserver is shutting down";
        let status = parse_server_status(text);
        assert!(!status.server_up);
    }

    #[test]
    fn parse_status_no_boot_time() {
        let text = "version: BIND 9.20.0\nserver is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.running_since, None);
    }

    #[test]
    fn parse_status_preserves_raw_text() {
        let text = "version: BIND 9.20.0\nsome custom output";
        let status = parse_server_status(text);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn extract_field_finds_label() {
        let text = "version: BIND 9.20.0\nboot time: Monday";
        assert_eq!(extract_field(text, "version:"), Some("BIND 9.20.0".into()));
        assert_eq!(extract_field(text, "boot time:"), Some("Monday".into()));
    }

    #[test]
    fn extract_field_returns_none_for_missing() {
        let text = "version: BIND 9.20.0";
        assert_eq!(extract_field(text, "missing:"), None);
    }

    #[test]
    fn extract_field_handles_leading_whitespace() {
        let text = "  version: BIND 9.20.0";
        assert_eq!(extract_field(text, "version:"), Some("BIND 9.20.0".into()));
    }

    // -- FrozenZone construction tests --

    #[test]
    fn make_frozen_zone_from_domain_name() {
        let name = DomainName::new("example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
        assert_eq!(frozen.class, RecordClass::IN);
    }

    #[test]
    fn make_frozen_zone_preserves_name() {
        let name = DomainName::new("sub.domain.example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
    }
}
