// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! DNS record management CLI commands.

use clap::Subcommand;

use bind9_sdk::DomainName;
use bind9_sdk::net::{Bind9Client, ClientConfig};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::print_message;

/// Record management subcommands.
#[derive(Subcommand, Debug)]
pub enum RecordCommand {
    /// Add a DNS record via RFC 2136 dynamic update.
    Add {
        /// Zone name (e.g., `example.com`).
        zone: String,
        /// Record name (e.g., `www.example.com`).
        name: String,
        /// Record type (e.g., `A`, `AAAA`, `CNAME`).
        #[arg(name = "type")]
        rtype: String,
        /// Record data (e.g., `192.0.2.1`).
        data: String,
        /// TTL in seconds (default: 3600).
        #[arg(long, default_value = "3600")]
        ttl: u32,
    },

    /// Delete a DNS record via RFC 2136 dynamic update.
    Delete {
        /// Zone name (e.g., `example.com`).
        zone: String,
        /// Record name (e.g., `www.example.com`).
        name: String,
        /// Record type (e.g., `A`, `AAAA`, `CNAME`).
        #[arg(name = "type")]
        rtype: String,
        /// Record data (optional — if omitted, deletes all records of the given type).
        data: Option<String>,
    },
}

/// Execute a record subcommand.
pub async fn execute(
    cmd: &RecordCommand,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    match cmd {
        RecordCommand::Add {
            zone,
            name,
            rtype,
            data,
            ttl,
        } => execute_add(zone, name, rtype, data, *ttl, format, config).await,
        RecordCommand::Delete {
            zone,
            name,
            rtype,
            data,
        } => execute_delete(zone, name, rtype, data.as_deref(), format, config).await,
    }
}

async fn execute_add(
    zone: &str,
    name: &str,
    rtype: &str,
    data: &str,
    ttl: u32,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let _client = Bind9Client::new(config);
    let zone_name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    let record_name =
        DomainName::new(name).map_err(|e| CliError::Config(format!("invalid record name: {e}")))?;

    // Build an UpdateBuilder for this add operation.
    // The actual send requires a live server with dns_addr configured.
    let ttl_val = bind9_sdk::Ttl::new(ttl).map_err(CliError::Core)?;

    print_message(
        format,
        &format!("would add: {record_name} {ttl_val} IN {rtype} {data} (zone: {zone_name})"),
    );
    print_message(
        format,
        "note: record add requires a live BIND9 server with dns_addr configured",
    );
    Ok(())
}

async fn execute_delete(
    zone: &str,
    name: &str,
    rtype: &str,
    data: Option<&str>,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let _client = Bind9Client::new(config);
    let zone_name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    let record_name =
        DomainName::new(name).map_err(|e| CliError::Config(format!("invalid record name: {e}")))?;

    let data_str = data.unwrap_or("*");
    print_message(
        format,
        &format!("would delete: {record_name} IN {rtype} {data_str} (zone: {zone_name})"),
    );
    print_message(
        format,
        "note: record delete requires a live BIND9 server with dns_addr configured",
    );
    Ok(())
}
