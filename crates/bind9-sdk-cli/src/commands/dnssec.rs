// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! DNSSEC management CLI commands.

use clap::{Subcommand, ValueEnum};
use serde::Serialize;

use bind9_sdk::DomainName;
use bind9_sdk::net::rndc::command::DsState;
use bind9_sdk::net::rndc::dnssec::{DnssecKeyInfo, KeyRole};
use bind9_sdk::net::{Bind9Client, ClientConfig};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::{print_output, print_success};

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
        /// Parent DS state to record in BIND's DNSSEC policy engine.
        #[arg(value_enum)]
        state: CheckDsState,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CheckDsState {
    Published,
    Withdrawn,
}

impl CheckDsState {
    fn to_rndc(self) -> DsState {
        match self {
            Self::Published => DsState::Published,
            Self::Withdrawn => DsState::Withdrawn,
        }
    }
}

#[derive(Debug, Serialize)]
struct DnssecStatusOutput {
    zone: String,
    policy: String,
    keys: Vec<DnssecKeyOutput>,
}

#[derive(Debug, Serialize)]
struct DnssecKeyOutput {
    tag: u16,
    algorithm: Option<String>,
    role: String,
    state: String,
}

impl From<DnssecKeyInfo> for DnssecKeyOutput {
    fn from(key: DnssecKeyInfo) -> Self {
        let role = match key.role {
            KeyRole::Ksk => "KSK",
            KeyRole::Zsk => "ZSK",
            KeyRole::Csk => "CSK",
            _ => "unknown",
        };
        Self {
            tag: key.tag,
            algorithm: key.algorithm,
            role: role.into(),
            state: key.state,
        }
    }
}

impl std::fmt::Display for DnssecStatusOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "zone: {}", self.zone)?;
        writeln!(f, "dnssec-policy: {}", self.policy)?;
        for key in &self.keys {
            let algorithm = key
                .algorithm
                .as_deref()
                .map(|value| format!(" ({value})"))
                .unwrap_or_default();
            writeln!(
                f,
                "key: {}{} {}, state: {}",
                key.tag, algorithm, key.role, key.state
            )?;
        }
        Ok(())
    }
}

/// Execute a DNSSEC subcommand.
pub async fn execute(
    cmd: &DnssecCommand,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    match cmd {
        DnssecCommand::Status { zone } => execute_status(zone, format, config).await,
        DnssecCommand::Checkds { zone, state } => {
            execute_checkds(zone, *state, format, config).await
        }
    }
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
    let zone =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    let status = Bind9Client::new(config).dnssec_status(&zone).await?;
    print_output(
        format,
        &DnssecStatusOutput {
            zone: zone.to_string(),
            policy: status.policy,
            keys: status.keys.into_iter().map(Into::into).collect(),
        },
    );
    Ok(())
}

async fn execute_checkds(
    zone: &str,
    state: CheckDsState,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let zone =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    Bind9Client::new(config)
        .dnssec_checkds(&zone, state.to_rndc())
        .await?;
    print_success(
        format,
        &format!("recorded parent DS state for {zone}: {state:?}"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bind9_sdk::net::rndc::command::DsState;

    #[test]
    fn checkds_state_maps_to_rndc_state() {
        assert_eq!(CheckDsState::Published.to_rndc(), DsState::Published);
        assert_eq!(CheckDsState::Withdrawn.to_rndc(), DsState::Withdrawn);
    }

    #[test]
    fn dnssec_status_output_is_structured_json() {
        let output = DnssecStatusOutput {
            zone: "example.com.".into(),
            policy: "default".into(),
            keys: vec![DnssecKeyOutput {
                tag: 12345,
                algorithm: Some("ECDSAP256SHA256".into()),
                role: "KSK".into(),
                state: "OMNIPRESENT".into(),
            }],
        };
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["zone"], "example.com.");
        assert_eq!(value["keys"][0]["tag"], 12345);
        assert_eq!(value["keys"][0]["algorithm"], "ECDSAP256SHA256");
    }
}
