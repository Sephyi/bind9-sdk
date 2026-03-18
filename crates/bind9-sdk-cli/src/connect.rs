// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Build SDK client configuration from CLI args and config file.

use std::net::SocketAddr;

use bind9_sdk::core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk::net::ClientConfig;
use bind9_sdk::DomainName;

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

    let key_secret = cli.key_secret.as_deref().or(file_config
        .as_ref()
        .and_then(|c| c.auth.as_ref())
        .map(|a| a.key_secret.as_str()));

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

    let tsig_key = TsigKey::from_base64(key_domain, algorithm, key_secret)
        .map_err(|e| CliError::Config(format!("invalid key secret: {e}")))?;

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| CliError::Config(format!("invalid server address '{host}:{port}': {e}")))?;

    let mut config = ClientConfig::new(addr, tsig_key);

    // Set optional fields — CLI --dns-port takes precedence over config file
    let dns_port = cli
        .dns_port
        .or(file_config.as_ref().and_then(|c| c.server.dns_port));
    if let Some(dns_port) = dns_port {
        let dns_addr: SocketAddr = format!("{host}:{dns_port}").parse().map_err(|e| {
            CliError::Config(format!("invalid DNS address '{host}:{dns_port}': {e}"))
        })?;
        config.dns_addr = Some(dns_addr);
    }

    if let Some(ref file_cfg) = file_config {
        if let Some(ref stats_url) = file_cfg.server.stats_url {
            config.stats_url = Some(stats_url.clone());
        }
    }

    Ok(Some(config))
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
}
