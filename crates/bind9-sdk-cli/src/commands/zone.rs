// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Zone management CLI commands.

use std::path::PathBuf;

use clap::Subcommand;
use serde::Serialize;

use tokio_stream::StreamExt;

use bind9_sdk::core::{DiffEntry, TransferRecord, ZoneFile};
use bind9_sdk::net::{Bind9Client, ClientConfig, StatsHttpClient, TransferClient};
use bind9_sdk::{DomainName, NamedControl};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::{print_message, print_output, print_success};

/// Zone management subcommands.
#[derive(Subcommand, Debug)]
pub enum ZoneCommand {
    /// List all zones on the server.
    List,

    /// Show zone status via rndc.
    Status {
        /// Zone name (e.g., `example.com`).
        zone: String,
    },

    /// Reload a zone via rndc.
    Reload {
        /// Zone name (e.g., `example.com`).
        zone: String,
    },

    /// Export a zone via AXFR transfer.
    Export {
        /// Zone name (e.g., `example.com`).
        zone: String,
    },

    /// Diff two zone files.
    Diff {
        /// Path to the first zone file (old).
        file_a: PathBuf,
        /// Path to the second zone file (new).
        file_b: PathBuf,
    },
}

/// Serializable diff result for JSON output.
#[derive(Debug, Serialize)]
struct DiffResult {
    added: usize,
    removed: usize,
    ttl_changed: usize,
    total: usize,
    diff: String,
}

#[derive(Debug, Serialize)]
struct ZoneList {
    zones: Vec<ZoneListEntry>,
}

#[derive(Debug, Serialize)]
struct ZoneListEntry {
    name: String,
    class: String,
    serial: u32,
    zone_type: String,
}

impl std::fmt::Display for ZoneList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for zone in &self.zones {
            writeln!(
                f,
                "{}\t{}\t{}\t{}",
                zone.name, zone.class, zone.serial, zone.zone_type
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct ZoneStatus {
    zone: String,
    status: String,
}

impl std::fmt::Display for ZoneStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.status)
    }
}

#[derive(Debug, Serialize)]
struct ZoneExport {
    zone: String,
    record_count: usize,
    records: Vec<String>,
}

impl std::fmt::Display for ZoneExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for record in &self.records {
            writeln!(f, "{record}")?;
        }
        write!(
            f,
            "; Transfer complete: {} records for {}",
            self.record_count, self.zone
        )
    }
}

impl std::fmt::Display for DiffResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.diff)
    }
}

/// Execute a zone subcommand.
pub async fn execute(
    cmd: &ZoneCommand,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    match cmd {
        ZoneCommand::List => execute_list(format, config).await,
        ZoneCommand::Status { zone } => execute_status(zone, format, config).await,
        ZoneCommand::Reload { zone } => execute_reload(zone, format, config).await,
        ZoneCommand::Export { zone } => execute_export(zone, format, config).await,
        ZoneCommand::Diff { file_a, file_b } => execute_diff(file_a, file_b, format),
    }
}

async fn execute_list(format: OutputFormat, config: Option<ClientConfig>) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let stats_url = config.stats_url.as_deref().ok_or_else(|| {
        CliError::Config(
            "stats_url must be configured for zone list; rndc does not expose a zone-name list"
                .into(),
        )
    })?;
    let client = StatsHttpClient::new(stats_url, config.timeout)?;
    let zones = client.fetch_zones().await?;
    let output = ZoneList {
        zones: zones
            .into_iter()
            .map(|zone| ZoneListEntry {
                name: zone.name.to_string(),
                class: zone.class.to_string(),
                serial: zone.serial.value(),
                zone_type: zone.zone_type,
            })
            .collect(),
    };
    print_output(format, &output);
    Ok(())
}

async fn execute_status(
    zone: &str,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let client = Bind9Client::new(config);
    let name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    let status = client.zone_status(&name).await?;
    print_output(
        format,
        &ZoneStatus {
            zone: name.to_string(),
            status,
        },
    );
    Ok(())
}

async fn execute_reload(
    zone: &str,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let client = Bind9Client::new(config);
    let name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    client.reload_zone(&name).await.map_err(CliError::Net)?;
    print_success(format, &format!("zone {name} reloaded"));
    Ok(())
}

async fn execute_export(
    zone: &str,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let dns_addr = config.dns_addr.ok_or_else(|| {
        CliError::Config(
            "dns_port must be configured for zone export (AXFR uses TCP port 53)".into(),
        )
    })?;
    let name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;

    // Connect to the DNS server for AXFR transfer over TCP.
    let client = TransferClient::connect(dns_addr, None)
        .await
        .map_err(CliError::Net)?;

    // Start the AXFR transfer, optionally signed with TSIG.
    let stream = client
        .axfr(name.clone(), Some(&config.rndc_key))
        .await
        .map_err(CliError::Net)?;

    // The stream returned by axfr is not Unpin, so we must pin it.
    tokio::pin!(stream);

    // Collect the complete result so JSON mode emits exactly one document.
    let mut records = Vec::new();
    while let Some(result) = stream.next().await {
        let transfer_record = result.map_err(CliError::Net)?;
        let rr = match &transfer_record {
            TransferRecord::BeginSoa(rr)
            | TransferRecord::Record(rr)
            | TransferRecord::EndSoa(rr) => rr,
            _ => continue,
        };
        records.push(format_record(rr));
    }

    print_output(
        format,
        &ZoneExport {
            zone: name.to_string(),
            record_count: records.len(),
            records,
        },
    );
    Ok(())
}

/// Format a `ResourceRecord` as a zone file line.
fn format_record(rr: &bind9_sdk::ResourceRecord) -> String {
    use bind9_sdk::core::zone::ZoneFile;
    use bind9_sdk::{DomainName, Zone};

    // Build a minimal zone file containing just this record to leverage
    // the existing serializer for rdata formatting.
    let root = DomainName::root();
    let zf = ZoneFile {
        origin: root.clone(),
        default_ttl: Some(rr.ttl),
        zone: Zone {
            name: root,
            class: rr.class,
            records: vec![rr.clone()],
        },
    };
    let serialized = zf.serialize();
    // The serialized output includes $ORIGIN and $TTL lines; extract just the record line.
    serialized
        .lines()
        .skip_while(|line| line.starts_with('$'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn execute_diff(file_a: &PathBuf, file_b: &PathBuf, format: OutputFormat) -> Result<(), CliError> {
    let content_a = std::fs::read_to_string(file_a)?;
    let content_b = std::fs::read_to_string(file_b)?;

    let zone_a = ZoneFile::parse(&content_a).map_err(CliError::Core)?;
    let zone_b = ZoneFile::parse(&content_b).map_err(CliError::Core)?;

    let diff = zone_a.zone.diff(&zone_b.zone);

    if diff.is_empty() {
        print_message(format, "zones are identical");
        return Ok(());
    }

    let mut added = 0usize;
    let mut removed = 0usize;
    let mut ttl_changed = 0usize;

    for entry in diff.entries() {
        match entry {
            DiffEntry::Added(_) => added += 1,
            DiffEntry::Removed(_) => removed += 1,
            DiffEntry::TtlChanged { .. } => ttl_changed += 1,
            _ => {}
        }
    }

    let diff_text = format!("{diff}");
    let result = DiffResult {
        added,
        removed,
        ttl_changed,
        total: diff.len(),
        diff: diff_text,
    };
    print_output(format, &result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_zone_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    const ZONE_A: &str = "\
$ORIGIN example.com.
$TTL 3600
@  IN SOA ns1.example.com. admin.example.com. 2026031401 3600 900 604800 86400
@  IN NS  ns1.example.com.
@  IN A   192.0.2.1
www IN A   192.0.2.2
";

    const ZONE_B: &str = "\
$ORIGIN example.com.
$TTL 3600
@  IN SOA ns1.example.com. admin.example.com. 2026031402 3600 900 604800 86400
@  IN NS  ns1.example.com.
@  IN A   192.0.2.1
www IN A   192.0.2.2
new IN A   192.0.2.3
";

    #[test]
    fn diff_identical_zones() {
        let f1 = write_zone_file(ZONE_A);
        let f2 = write_zone_file(ZONE_A);
        let result = execute_diff(
            &f1.path().to_path_buf(),
            &f2.path().to_path_buf(),
            OutputFormat::Text,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn diff_zones_with_additions() {
        let f1 = write_zone_file(ZONE_A);
        let f2 = write_zone_file(ZONE_B);
        let result = execute_diff(
            &f1.path().to_path_buf(),
            &f2.path().to_path_buf(),
            OutputFormat::Text,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn diff_nonexistent_file_returns_error() {
        let f1 = write_zone_file(ZONE_A);
        let result = execute_diff(
            &f1.path().to_path_buf(),
            &PathBuf::from("/tmp/nonexistent-zone-file.zone"),
            OutputFormat::Text,
        );
        assert!(result.is_err());
    }

    #[test]
    fn zone_export_serializes_as_one_json_document() {
        let output = ZoneExport {
            zone: "example.com.".into(),
            record_count: 2,
            records: vec![
                "example.com. 3600 IN A 192.0.2.1".into(),
                "www.example.com. 3600 IN A 192.0.2.2".into(),
            ],
        };

        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["zone"], "example.com.");
        assert_eq!(parsed["record_count"], 2);
        assert_eq!(parsed["records"].as_array().unwrap().len(), 2);
    }
}
