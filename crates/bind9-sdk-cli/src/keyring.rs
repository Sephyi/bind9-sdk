// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! OS credential store integration for TSIG key secrets.
//!
//! Uses the `keyring` crate to store and retrieve base64-encoded TSIG key
//! secrets from the platform credential store (macOS Keychain, Linux Secret
//! Service, Windows Credential Manager).
//!
//! The service name is `bind9-sdk` and the username incorporates the server
//! address or profile name to support multiple configurations.

use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, warn};

/// The keyring service name used for all bind9-sdk credentials.
const SERVICE_NAME: &str = "bind9-sdk";

/// Build a keyring username from a profile identifier.
///
/// The profile is typically the server address (e.g., `127.0.0.1:953`) or
/// a named profile from the config file. This ensures distinct credentials
/// for different BIND9 servers.
fn keyring_username(profile: &str) -> String {
    format!("tsig-key:{profile}")
}

/// Retrieve the TSIG key secret from the OS credential store.
///
/// Returns `Ok(Some(secret))` if a credential is found, `Ok(None)` if no
/// credential is stored for this profile, or `Err` on unexpected failures.
pub fn get_secret(profile: &str) -> Result<Option<SecretString>, keyring::Error> {
    let username = keyring_username(profile);
    let entry = keyring::Entry::new(SERVICE_NAME, &username)?;

    match entry.get_password() {
        Ok(password) => {
            debug!(
                profile,
                "retrieved TSIG key secret from OS credential store"
            );
            Ok(Some(SecretString::from(password)))
        }
        Err(keyring::Error::NoEntry) => {
            debug!(profile, "no TSIG key secret found in OS credential store");
            Ok(None)
        }
        Err(e) => {
            warn!(profile, error = %e, "failed to read from OS credential store");
            Err(e)
        }
    }
}

/// Store the TSIG key secret in the OS credential store.
///
/// Overwrites any existing credential for this profile.
pub fn set_secret(profile: &str, secret: &SecretString) -> Result<(), keyring::Error> {
    let username = keyring_username(profile);
    let entry = keyring::Entry::new(SERVICE_NAME, &username)?;
    entry.set_password(secret.expose_secret())?;
    debug!(profile, "stored TSIG key secret in OS credential store");
    Ok(())
}

/// Delete the TSIG key secret from the OS credential store.
///
/// Returns `Ok(())` even if no credential existed for this profile.
pub fn delete_secret(profile: &str) -> Result<(), keyring::Error> {
    let username = keyring_username(profile);
    let entry = keyring::Entry::new(SERVICE_NAME, &username)?;

    match entry.delete_credential() {
        Ok(()) => {
            debug!(profile, "deleted TSIG key secret from OS credential store");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_username_format() {
        assert_eq!(keyring_username("127.0.0.1:953"), "tsig-key:127.0.0.1:953");
        assert_eq!(keyring_username("production"), "tsig-key:production");
    }

    // Note: actual keyring get/set/delete tests require a live OS credential
    // store and are not suitable for CI. They should be run as integration
    // tests with `--ignored`.
}
