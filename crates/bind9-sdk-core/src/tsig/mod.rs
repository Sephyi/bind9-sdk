// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! TSIG DNS message authentication (RFC 8945).
//!
//! This module provides types for TSIG key management ([`TsigKey`]),
//! TSIG record construction and wire parsing ([`TsigRecord`]), and the
//! HMAC algorithms supported by this SDK ([`TsigAlgorithm`]).

mod key;
mod record;
mod wire;

#[cfg(test)]
mod tests;

pub use self::key::TsigKey;
pub use self::record::TsigRecord;

use core::fmt;

/// TSIG HMAC algorithms supported by this SDK.
///
/// Maps to the algorithm names defined in RFC 8945 §6.
/// `HmacSha256` is the recommended default. `HmacSha1` is provided only
/// for legacy BIND9 compatibility and is marked deprecated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TsigAlgorithm {
    /// HMAC-SHA256 (recommended)
    HmacSha256,
    /// HMAC-SHA512
    HmacSha512,
    /// HMAC-SHA1 (legacy only)
    #[deprecated(note = "HMAC-SHA1 is weak; use HmacSha256 or HmacSha512 for new deployments")]
    HmacSha1,
}

impl TsigAlgorithm {
    /// The DNS algorithm name used in TSIG records (RFC 8945 §6).
    ///
    /// Returns the canonical name in absolute form (with trailing dot).
    pub fn dns_name(&self) -> &'static str {
        #[allow(deprecated)]
        match self {
            Self::HmacSha256 => "hmac-sha256.",
            Self::HmacSha512 => "hmac-sha512.",
            Self::HmacSha1 => "hmac-sha1.",
        }
    }

    /// The recommended key length in bytes for this algorithm.
    ///
    /// For HMAC algorithms, this equals the hash output size.
    pub fn key_length(&self) -> usize {
        #[allow(deprecated)]
        match self {
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
            Self::HmacSha1 => 20,
        }
    }

    /// The MAC (message authentication code) output length in bytes.
    pub fn mac_length(&self) -> usize {
        self.key_length()
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.dns_name();
        f.write_str(name.strip_suffix('.').unwrap_or(name))
    }
}
