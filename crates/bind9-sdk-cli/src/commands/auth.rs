// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `bind9 auth` subcommands for managing TSIG key credentials.

use clap::Subcommand;
use secrecy::SecretString;

use crate::error::CliError;
use crate::keyring;

/// Authentication credential management commands.
#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Store a TSIG key secret in the OS credential store (macOS Keychain,
    /// Linux Secret Service, Windows Credential Manager).
    SetKey {
        /// Server profile identifier (e.g., `127.0.0.1:953` or a profile name).
        /// Must match the server address used in other commands.
        #[arg(long)]
        profile: String,

        /// Base64-encoded TSIG key secret. If omitted, reads from stdin.
        #[arg(long)]
        secret: Option<String>,
    },

    /// Remove a TSIG key secret from the OS credential store.
    DeleteKey {
        /// Server profile identifier to remove.
        #[arg(long)]
        profile: String,
    },
}

pub fn execute(cmd: &AuthCommand) -> Result<(), CliError> {
    match cmd {
        AuthCommand::SetKey { profile, secret } => {
            let secret_value = match secret {
                Some(s) => SecretString::from(s.clone()),
                None => {
                    eprint!("Enter base64-encoded TSIG key secret: ");
                    let line = rpassword::read_password()?;
                    SecretString::from(line.trim().to_owned())
                }
            };

            keyring::set_secret(profile, &secret_value)?;
            eprintln!("Stored TSIG key secret for profile '{profile}' in OS credential store.");
            Ok(())
        }
        AuthCommand::DeleteKey { profile } => {
            keyring::delete_secret(profile)?;
            eprintln!("Deleted TSIG key secret for profile '{profile}' from OS credential store.");
            Ok(())
        }
    }
}
