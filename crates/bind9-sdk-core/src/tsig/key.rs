// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use base64::prelude::*;
use digest::Mac;
use hmac::Hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::domain::DomainName;
use crate::error::CoreError;

use super::TsigAlgorithm;

/// A TSIG key for DNS message authentication (RFC 8945).
///
/// Holds HMAC key material that is automatically zeroed on drop via
/// `zeroize::Zeroizing`. Does not implement `Clone` to prevent
/// accidental key duplication. The `Debug` impl redacts key material.
pub struct TsigKey {
    pub(super) name: DomainName,
    pub(super) algorithm: TsigAlgorithm,
    pub(super) key_material: Zeroizing<Vec<u8>>,
}

impl TsigKey {
    /// Create a new TSIG key from raw key material bytes.
    ///
    /// Returns an error if `key_material` is empty. Logs a warning via
    /// `tracing` if the key is shorter than the algorithm's recommended length
    /// (requires the `std` feature).
    pub fn new(
        name: DomainName,
        algorithm: TsigAlgorithm,
        key_material: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if key_material.is_empty() {
            return Err(CoreError::Tsig("key material must not be empty".into()));
        }
        #[cfg(feature = "std")]
        if key_material.len() < algorithm.key_length() {
            tracing::warn!(
                key_name = %name,
                algorithm = %algorithm,
                actual_len = key_material.len(),
                recommended_len = algorithm.key_length(),
                "TSIG key shorter than algorithm's recommended length"
            );
        }
        Ok(Self {
            name,
            algorithm,
            key_material: Zeroizing::new(key_material),
        })
    }

    /// Create a TSIG key from a base64-encoded string.
    ///
    /// This is the format used in `rndc.conf` and `named.conf` key statements.
    /// Whitespace in the base64 string is stripped before decoding.
    pub fn from_base64(
        name: DomainName,
        algorithm: TsigAlgorithm,
        base64_key: &str,
    ) -> Result<Self, CoreError> {
        let cleaned: String = base64_key.chars().filter(|c| !c.is_whitespace()).collect();

        if cleaned.is_empty() {
            return Err(CoreError::Tsig("base64 key string is empty".into()));
        }

        let decoded = BASE64_STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| CoreError::Tsig(alloc::format!("invalid base64: {e}")))?;

        Self::new(name, algorithm, decoded)
    }

    /// Generate a new TSIG key with random key material.
    ///
    /// Uses `getrandom` for cryptographically secure random bytes.
    /// The key length matches the algorithm's recommended key size.
    ///
    /// **Requires the `std` feature** — not available in `no_std`/WASM builds.
    #[cfg(feature = "std")]
    pub fn generate(name: DomainName, algorithm: TsigAlgorithm) -> Result<Self, CoreError> {
        let len = algorithm.key_length();
        let mut material = alloc::vec![0u8; len];
        getrandom::fill(&mut material)
            .map_err(|e| CoreError::Tsig(alloc::format!("random generation failed: {e}")))?;
        Self::new(name, algorithm, material)
    }

    /// The key name (a DNS domain name).
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// The HMAC algorithm for this key.
    pub fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Raw key material bytes (test-only accessor).
    #[cfg(test)]
    pub(super) fn material(&self) -> &[u8] {
        &self.key_material
    }

    /// Compute an HMAC over the given message bytes.
    ///
    /// Returns the raw MAC bytes. The length depends on the algorithm:
    /// - HmacSha256: 32 bytes
    /// - HmacSha512: 64 bytes
    /// - HmacSha1: 20 bytes
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        #[allow(deprecated)]
        match self.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha512 => {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha1 => {
                let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Verify an HMAC over the given message bytes.
    ///
    /// Returns `Ok(())` if the MAC matches, or `Err(CoreError::Tsig)` if
    /// verification fails (wrong MAC, wrong length, tampered message).
    pub fn verify(&self, message: &[u8], mac: &[u8]) -> Result<(), CoreError> {
        #[allow(deprecated)]
        match self.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA256 verification failed".into()))
            }
            TsigAlgorithm::HmacSha512 => {
                let mut hmac = <Hmac<Sha512> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA512 verification failed".into()))
            }
            TsigAlgorithm::HmacSha1 => {
                let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(&self.key_material)
                    .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA1 verification failed".into()))
            }
        }
    }
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}
