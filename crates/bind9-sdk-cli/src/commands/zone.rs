// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Zone management CLI commands.

use std::path::PathBuf;

use clap::Subcommand;
use serde::Serialize;

use bind9_sdk::core::{DiffEntry, ZoneFile};
use bind9_sdk::net::{Bind9Client, ClientConfig};
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
    let client = Bind9Client::new(config);
    // Bind9Client does not implement ZoneManager (no AXFR-based zone listing yet).
    // Use rndc status to show basic server info including zone count.
    let status = client.status().await.map_err(CliError::Net)?;
    print_message(
        format,
        &format!(
            "Server: {} (zones: {})\nUse 'zone status <zone>' for per-zone details.",
            status.version, status.zone_count
        ),
    );
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
    let status = client.status().await.map_err(CliError::Net)?;
    print_message(
        format,
        &format!(
            "Server: {} (zones: {})\nZone: {}",
            status.version, status.zone_count, name
        ),
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
    let _config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    // AXFR zone export requires TransferClient (TCP stream to port 53).
    // This is a stub — full implementation needs dns_addr and TSIG key.
    print_message(
        format,
        &format!("zone export for {name} requires AXFR transfer (not yet wired to CLI)"),
    );
    Ok(())
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
}
