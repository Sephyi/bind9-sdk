// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! DNSSEC management CLI commands.

use clap::Subcommand;

use bind9_sdk::net::ClientConfig;

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::print_message;

/// DNSSEC management subcommands.
#[derive(Subcommand, Debug)]
pub enum DnssecCommand {
    /// Show DNSSEC status for a zone.
    Status {
        /// Zone name (e.g., `example.com`).
        zone: String,
    },

    /// Check DS record publication status at the parent.
    Checkds {
        /// Zone name (e.g., `example.com`).
        zone: String,
    },
}

/// Execute a DNSSEC subcommand.
pub async fn execute(
    cmd: &DnssecCommand,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    match cmd {
        DnssecCommand::Status { zone } => execute_status(zone, format, config).await,
        DnssecCommand::Checkds { zone } => execute_checkds(zone, format, config).await,
    }
}

async fn execute_status(
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

    // This would use Bind9Client to send RndcCommand::DnssecStatus and parse
    // the response via DnssecStatus::parse(). Requires a live BIND9 server.
    print_message(
        format,
        &format!("dnssec status for zone {zone} requires a live BIND9 server"),
    );
    Ok(())
}

async fn execute_checkds(
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

    // This would use Bind9Client to send RndcCommand::DnssecCheckDs and parse
    // the response via DsCheckResult::parse(). Requires a live BIND9 server.
    print_message(
        format,
        &format!("dnssec checkds for zone {zone} requires a live BIND9 server"),
    );
    Ok(())
}
