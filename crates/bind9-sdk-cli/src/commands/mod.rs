// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! CLI command structure using clap derive.

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

    /// Fetch server statistics from the BIND9 statistics-channel.
    Stats,

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}
