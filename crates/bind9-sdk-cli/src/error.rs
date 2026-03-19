// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CLI error type.

/// CLI error type encompassing all failure modes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// Network operation failed.
    #[error(transparent)]
    Net(#[from] bind9_sdk::net::NetError),

    /// Core operation failed.
    #[error(transparent)]
    Core(#[from] bind9_sdk::CoreError),

    /// Config file parse error.
    #[error("config error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML deserialization error.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// OS credential store (keyring) error.
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}

impl CliError {
    /// Return the appropriate process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::Toml(_) => 2,
            _ => 1,
        }
    }
}
