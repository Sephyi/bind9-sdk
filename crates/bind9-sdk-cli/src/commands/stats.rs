// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Server statistics CLI command.

use bind9_sdk::StatsClient;
use bind9_sdk::net::{Bind9Client, ClientConfig};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::print_message;

/// Execute the stats command.
pub async fn execute(format: OutputFormat, config: Option<ClientConfig>) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;

    let client = Bind9Client::new(config);
    let stats = client.server_stats().await.map_err(CliError::Net)?;

    if let Some(version) = &stats.version {
        print_message(format, &format!("BIND version: {version}"));
    }
    if let Some(boot_time) = &stats.boot_time {
        print_message(format, &format!("Boot time:    {boot_time}"));
    }
    if let Some(config_time) = &stats.config_time {
        print_message(format, &format!("Config time:  {config_time}"));
    }
    if let Some(current_time) = &stats.current_time {
        print_message(format, &format!("Current time: {current_time}"));
    }

    Ok(())
}
