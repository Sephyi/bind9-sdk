// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CLI command structure using clap derive.

pub mod auth;
pub mod dnssec;
pub mod record;
pub mod stats;
pub mod zone;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// bind9 — CLI tool for BIND9 DNS server management.
///
/// Manage zones, records, DNSSEC, and server statistics using the
/// bind9-sdk Rust library. Supports rndc wire protocol, RFC 2136
/// dynamic updates, and the BIND9 statistics-channel JSON API.
#[derive(Parser, Debug)]
#[command(name = "bind9", version, about, long_about = None)]
pub struct Cli {
    /// Server hostname or IP address (overrides config file).
    #[arg(long, global = true)]
    pub server: Option<String>,

    /// rndc control port (overrides config file).
    #[arg(long, global = true)]
    pub port: Option<u16>,

    /// DNS port for dynamic updates and zone transfers (overrides config file).
    #[arg(long, global = true)]
    pub dns_port: Option<u16>,

    /// Statistics-channel JSON API URL (overrides config file).
    #[arg(long, global = true)]
    pub stats_url: Option<String>,

    /// Permit plaintext rndc over a separately protected network such as WireGuard.
    #[arg(long, global = true)]
    pub protected_rndc: bool,

    /// TSIG key name for rndc authentication.
    #[arg(long, global = true)]
    pub key_name: Option<String>,

    /// Base64-encoded TSIG key secret.
    #[arg(long, global = true)]
    pub key_secret: Option<String>,

    /// Output format.
    #[arg(long, global = true, default_value = "text")]
    pub output: OutputFormat,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// JSON output for programmatic consumption.
    Json,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Zone management commands.
    #[command(subcommand)]
    Zone(zone::ZoneCommand),

    /// DNS record management commands.
    #[command(subcommand)]
    Record(record::RecordCommand),

    /// DNSSEC management commands.
    #[command(subcommand)]
    Dnssec(dnssec::DnssecCommand),

    /// Manage TSIG key credentials in the OS credential store.
    #[command(subcommand)]
    Auth(auth::AuthCommand),

    /// Fetch server statistics from the BIND9 statistics-channel.
    Stats,

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parser_accepts_protected_rndc_flag() {
        let cli = Cli::try_parse_from(["bind9", "--protected-rndc", "stats"]).unwrap();
        assert!(cli.protected_rndc);
        assert!(matches!(cli.command, Command::Stats));
    }

    #[test]
    fn cli_parser_accepts_stats_url_for_zone_list() {
        let cli = Cli::try_parse_from([
            "bind9",
            "--stats-url",
            "http://127.0.0.1:8053/json/v1",
            "zone",
            "list",
        ])
        .unwrap();
        assert_eq!(
            cli.stats_url.as_deref(),
            Some("http://127.0.0.1:8053/json/v1")
        );
        assert!(matches!(
            cli.command,
            Command::Zone(zone::ZoneCommand::List)
        ));
    }
}
