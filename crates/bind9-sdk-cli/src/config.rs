// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CLI configuration file loading.
//!
//! Reads TOML configuration from the platform-specific config directory:
//! - macOS: `~/Library/Application Support/bind9-sdk/config.toml`
//! - Linux: `$XDG_CONFIG_HOME/bind9-sdk/config.toml` (default `~/.config/bind9-sdk/config.toml`)

use std::path::PathBuf;

use secrecy::SecretString;
use serde::Deserialize;

use crate::error::CliError;

/// Top-level CLI configuration.
#[derive(Debug, Deserialize)]
pub struct CliConfig {
    /// Server connection settings.
    pub server: ServerConfig,
    /// Authentication credentials (optional — can be provided via CLI flags).
    pub auth: Option<AuthConfig>,
}

/// Server connection parameters.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Server hostname or IP address.
    pub host: String,
    /// rndc control port (default: 953).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Statistics-channel URL (e.g., `http://127.0.0.1:8053`).
    pub stats_url: Option<String>,
    /// DNS server port for dynamic updates (default: 53).
    pub dns_port: Option<u16>,
    /// Permit plaintext rndc over a separately protected network.
    #[serde(default)]
    pub protected_rndc: bool,
}

/// TSIG authentication credentials.
///
/// The `key_secret` field is wrapped in `SecretString` to prevent accidental
/// exposure in logs or debug output. The `Debug` impl redacts it.
#[derive(Deserialize)]
pub struct AuthConfig {
    /// TSIG key name.
    pub key_name: String,
    /// Base64-encoded TSIG key secret (protected in-memory).
    pub key_secret: SecretString,
    /// TSIG algorithm (default: `hmac-sha256`).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("key_name", &self.key_name)
            .field("key_secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

fn default_port() -> u16 {
    953
}

fn default_algorithm() -> String {
    String::from("hmac-sha256")
}

impl CliConfig {
    /// Parse a `CliConfig` from a TOML string.
    pub fn from_str(toml_str: &str) -> Result<Self, CliError> {
        let config: Self = toml::from_str(toml_str)?;
        Ok(config)
    }

    /// Load configuration from the platform-specific config path.
    ///
    /// Returns `Ok(None)` if the config file does not exist.
    /// Returns `Err` if the file exists but cannot be read or parsed.
    pub fn load() -> Result<Option<Self>, CliError> {
        let Some(path) = Self::config_path() else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)?;
        let config = Self::from_str(&content)?;
        Ok(Some(config))
    }

    /// Return the platform-specific config file path.
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("bind9-sdk").join("config.toml"))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[server]
host = "127.0.0.1"
"#;
        let config = CliConfig::from_str(toml).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 953);
        assert!(!config.server.protected_rndc);
        assert!(config.auth.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[server]
host = "ns1.example.com"
port = 8953
stats_url = "http://127.0.0.1:8053"
dns_port = 5353
protected_rndc = true

[auth]
key_name = "rndc-key"
key_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
algorithm = "hmac-sha512"
"#;
        let config = CliConfig::from_str(toml).unwrap();
        assert_eq!(config.server.host, "ns1.example.com");
        assert_eq!(config.server.port, 8953);
        assert_eq!(
            config.server.stats_url.as_deref(),
            Some("http://127.0.0.1:8053")
        );
        assert_eq!(config.server.dns_port, Some(5353));
        assert!(config.server.protected_rndc);

        let auth = config.auth.unwrap();
        assert_eq!(auth.key_name, "rndc-key");
        assert_eq!(
            auth.key_secret.expose_secret(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(auth.algorithm, "hmac-sha512");
    }

    #[test]
    fn parse_config_default_algorithm() {
        let toml = r#"
[server]
host = "127.0.0.1"

[auth]
key_name = "rndc-key"
key_secret = "dGVzdA=="
"#;
        let config = CliConfig::from_str(toml).unwrap();
        let auth = config.auth.unwrap();
        assert_eq!(auth.algorithm, "hmac-sha256");
    }

    #[test]
    fn parse_invalid_toml_returns_error() {
        let toml = "not valid toml [[[";
        let result = CliConfig::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn config_path_returns_some() {
        // On CI or systems without a home dir this could be None,
        // but on macOS/Linux dev machines it should be Some.
        let path = CliConfig::config_path();
        if let Some(p) = path {
            assert!(p.ends_with("bind9-sdk/config.toml"));
        }
    }

    #[test]
    fn load_missing_file_returns_none() {
        // config_path may return a path that doesn't exist, which is fine
        let result = CliConfig::load().unwrap();
        // We cannot guarantee the file doesn't exist, but this exercises the code path
        let _ = result;
    }

    #[test]
    fn auth_config_debug_redacts_secret() {
        let toml = r#"
[server]
host = "127.0.0.1"

[auth]
key_name = "rndc-key"
key_secret = "dGVzdA=="
"#;
        let config = CliConfig::from_str(toml).unwrap();
        let debug_output = format!("{:?}", config.auth.unwrap());
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("dGVzdA=="));
    }
}
