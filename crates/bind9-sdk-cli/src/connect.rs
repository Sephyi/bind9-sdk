// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Build SDK client configuration from CLI args and config file.
//!
//! Secret resolution order:
//! 1. CLI `--key-secret` flag (highest priority)
//! 2. OS credential store via `keyring` crate
//! 3. Config file `[auth].key_secret` (lowest priority, fallback)

use std::net::{SocketAddr, ToSocketAddrs};

use bind9_sdk::DomainName;
use bind9_sdk::core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk::net::{ClientConfig, RndcTransportPolicy};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, warn};

use crate::commands::Cli;
use crate::config::CliConfig;
use crate::error::CliError;

/// Build a `ClientConfig` from CLI arguments merged with the config file.
///
/// CLI arguments take precedence over config file values.
/// Returns `None` if neither CLI args nor config file provide enough
/// information to connect (no server address or no key).
pub fn build_client_config(cli: &Cli) -> Result<Option<ClientConfig>, CliError> {
    let file_config = CliConfig::load()?;

    // Resolve server address
    let host = cli
        .server
        .as_deref()
        .or(file_config.as_ref().map(|c| c.server.host.as_str()));

    let port = cli
        .port
        .or(file_config.as_ref().map(|c| c.server.port))
        .unwrap_or(953);

    let Some(host) = host else {
        return Ok(None);
    };

    // Resolve auth
    let key_name = cli.key_name.as_deref().or(file_config
        .as_ref()
        .and_then(|c| c.auth.as_ref())
        .map(|a| a.key_name.as_str()));

    // Secret resolution: CLI flag > keyring > config file
    let key_secret: Option<SecretString> = if let Some(ref cli_secret) = cli.key_secret {
        debug!("using TSIG key secret from CLI flag");
        Some(SecretString::from(cli_secret.clone()))
    } else {
        // Try the OS credential store first, using host:port as the profile.
        let profile = format!("{host}:{port}");
        let keyring_secret = crate::keyring::get_secret(&profile).unwrap_or_else(|e| {
            debug!(error = %e, "keyring lookup failed, falling back to config file");
            None
        });

        if keyring_secret.is_some() {
            debug!("using TSIG key secret from OS credential store");
            keyring_secret
        } else if let Some(file_secret) = file_config
            .as_ref()
            .and_then(|c| c.auth.as_ref())
            .map(|a| &a.key_secret)
        {
            warn!(
                "using TSIG key secret from plaintext config file — \
                 this is insecure; use `bind9 auth set-key` to store \
                 the secret in your OS credential store instead"
            );
            Some(SecretString::from(file_secret.expose_secret().to_owned()))
        } else {
            None
        }
    };

    let (Some(key_name), Some(key_secret)) = (key_name, key_secret) else {
        return Ok(None);
    };

    let algorithm_str = file_config
        .as_ref()
        .and_then(|c| c.auth.as_ref())
        .map(|a| a.algorithm.as_str())
        .unwrap_or("hmac-sha256");

    let algorithm = parse_algorithm(algorithm_str)?;

    let key_domain = DomainName::new(key_name)
        .or_else(|_| DomainName::new(&format!("{key_name}.")))
        .map_err(|e| CliError::Config(format!("invalid key name '{key_name}': {e}")))?;

    let tsig_key = TsigKey::from_base64(key_domain, algorithm, key_secret.expose_secret())
        .map_err(|e| CliError::Config(format!("invalid key secret: {e}")))?;

    let addr: SocketAddr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| {
            CliError::Config(format!(
                "cannot resolve server address '{host}:{port}': {e}"
            ))
        })?
        .next()
        .ok_or_else(|| CliError::Config(format!("no addresses found for '{host}:{port}'")))?;

    let mut config = ClientConfig::new(addr, tsig_key);
    let protected_rndc = cli.protected_rndc
        || file_config
            .as_ref()
            .is_some_and(|config| config.server.protected_rndc);
    if protected_rndc {
        warn!(
            "protected-network rndc enabled; ensure the complete route is encrypted and \
             peer-authenticated (for example, by WireGuard)"
        );
        config.rndc_transport = RndcTransportPolicy::ProtectedNetwork;
    }

    // Set optional fields — CLI --dns-port takes precedence over config file
    let dns_port = cli
        .dns_port
        .or(file_config.as_ref().and_then(|c| c.server.dns_port));
    if let Some(dns_port) = dns_port {
        let dns_addr: SocketAddr = format!("{host}:{dns_port}")
            .to_socket_addrs()
            .map_err(|e| {
                CliError::Config(format!(
                    "cannot resolve DNS address '{host}:{dns_port}': {e}"
                ))
            })?
            .next()
            .ok_or_else(|| {
                CliError::Config(format!("no addresses found for '{host}:{dns_port}'"))
            })?;
        config.dns_addr = Some(dns_addr);
    }

    config.stats_url = resolve_stats_url(
        cli.stats_url.as_deref(),
        file_config
            .as_ref()
            .and_then(|config| config.server.stats_url.as_deref()),
    );

    Ok(Some(config))
}

fn resolve_stats_url(cli_url: Option<&str>, configured_url: Option<&str>) -> Option<String> {
    cli_url.or(configured_url).map(str::to_owned)
}

/// Parse a TSIG algorithm string into a `TsigAlgorithm`.
fn parse_algorithm(s: &str) -> Result<TsigAlgorithm, CliError> {
    match s.to_lowercase().as_str() {
        "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
        #[allow(deprecated)]
        "hmac-sha1" => Ok(TsigAlgorithm::HmacSha1),
        other => Err(CliError::Config(format!(
            "unsupported TSIG algorithm: {other} (supported: hmac-sha256, hmac-sha512)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_algorithm_sha256() {
        assert!(matches!(
            parse_algorithm("hmac-sha256").unwrap(),
            TsigAlgorithm::HmacSha256
        ));
    }

    #[test]
    fn parse_algorithm_sha512() {
        assert!(matches!(
            parse_algorithm("hmac-sha512").unwrap(),
            TsigAlgorithm::HmacSha512
        ));
    }

    #[test]
    fn parse_algorithm_case_insensitive() {
        assert!(matches!(
            parse_algorithm("HMAC-SHA256").unwrap(),
            TsigAlgorithm::HmacSha256
        ));
    }

    #[test]
    fn parse_algorithm_unsupported() {
        assert!(parse_algorithm("hmac-md5").is_err());
    }

    #[test]
    fn stats_url_resolution_prefers_cli_and_falls_back_to_config() {
        // Reserved .test names make clear this unit test performs no network I/O.
        assert_eq!(
            resolve_stats_url(
                Some("https://cli.example.test/json/v1"),
                Some("https://config.example.test/json/v1"),
            ),
            Some("https://cli.example.test/json/v1".into())
        );
        assert_eq!(
            resolve_stats_url(None, Some("https://config.example.test/json/v1")),
            Some("https://config.example.test/json/v1".into())
        );
        assert_eq!(resolve_stats_url(None, None), None);
    }
}
