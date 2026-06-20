// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! bind9 CLI — command-line tool for BIND9 DNS server management.

mod commands;
mod config;
mod connect;
mod error;
mod keyring;
mod output;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

use commands::{Cli, Command};
use connect::build_client_config;
use error::CliError;

fn main() -> ExitCode {
    // Initialize tracing from BIND9_LOG or RUST_LOG environment variable.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("BIND9_LOG")
                .or_else(|_| EnvFilter::try_from_default_env())
                .unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let rt = match build_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: failed to create Tokio runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            let code = e.exit_code();
            ExitCode::from(code as u8)
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    // Handle commands that don't need server config.
    match &cli.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(*shell, &mut cmd, "bind9", &mut std::io::stdout());
            return Ok(());
        }
        Command::Auth(auth_cmd) => {
            return commands::auth::execute(auth_cmd);
        }
        _ => {}
    }

    let format = cli.output;

    // Build client config from CLI args + config file.
    let config = build_client_config(&cli)?;

    match &cli.command {
        Command::Zone(zone_cmd) => commands::zone::execute(zone_cmd, format, config).await,
        Command::Record(record_cmd) => commands::record::execute(record_cmd, format, config).await,
        Command::Dnssec(dnssec_cmd) => commands::dnssec::execute(dnssec_cmd, format, config).await,
        Command::Stats => commands::stats::execute(format, config).await,
        Command::Auth(_) | Command::Completions { .. } => Ok(()),
    }
}

fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_construction_is_fallible_and_succeeds() {
        let runtime = build_runtime().unwrap();
        drop(runtime);
    }
}
