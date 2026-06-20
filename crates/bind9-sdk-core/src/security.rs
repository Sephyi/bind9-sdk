// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Typed operational security warnings and policy (PRD REQ-LOG-5,
//! REQ-SEC-DEFAULT-2/3).
//!
//! These types let the SDK surface security-relevant conditions —
//! deprecated TSIG algorithms, weak DNSSEC algorithms, near-expiry
//! signatures, and cleartext transfers — through a typed API rather than only
//! through `tracing`, so callers can react programmatically and a
//! [`SecurityPolicy`] can fail closed. No variant ever carries key material.

use alloc::string::String;

use crate::rdata::RecordData;
use crate::tsig::TsigAlgorithm;

/// Severity classification for a [`SecurityWarning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Severity {
    /// Informational; no action required.
    Info,
    /// Weak configuration that should be addressed.
    Warning,
    /// Actively unsafe; should be rejected under a strict policy.
    Critical,
}

/// A typed operational security condition surfaced to the caller.
///
/// Variants describe *what* is unsafe in machine-readable form. They never
/// contain TSIG secrets, key material, or other credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityWarning {
    /// A deprecated TSIG MAC algorithm is in use (RFC 8945; HMAC-SHA1).
    DeprecatedTsigAlgorithm {
        /// The deprecated algorithm.
        algorithm: TsigAlgorithm,
    },
    /// A weak or deprecated DNSSEC signing algorithm (RFC 9904).
    WeakDnssecAlgorithm {
        /// IANA DNSSEC algorithm number.
        algorithm: u8,
    },
    /// An RRSIG is within the configured expiry warning window (or expired).
    NearExpiryRrsig {
        /// Record type the signature covers.
        covered_type: u16,
        /// Key tag of the signing key.
        key_tag: u16,
        /// Seconds until expiry; negative if already expired.
        seconds_remaining: i64,
    },
    /// Zone data was transferred over an unencrypted channel.
    CleartextTransfer,
}

impl SecurityWarning {
    /// Severity of this warning.
    pub fn severity(&self) -> Severity {
        match self {
            // Expired signatures are critical; near-expiry is a warning.
            Self::NearExpiryRrsig {
                seconds_remaining, ..
            } if *seconds_remaining < 0 => Severity::Critical,
            Self::NearExpiryRrsig { .. } => Severity::Warning,
            Self::DeprecatedTsigAlgorithm { .. } => Severity::Warning,
            Self::WeakDnssecAlgorithm { .. } => Severity::Warning,
            Self::CleartextTransfer => Severity::Warning,
        }
    }

    /// A non-secret, human-readable description suitable for logs and reports.
    pub fn message(&self) -> String {
        match self {
            Self::DeprecatedTsigAlgorithm { algorithm } => {
                alloc::format!("deprecated TSIG algorithm in use: {}", algorithm.dns_name())
            }
            Self::WeakDnssecAlgorithm { algorithm } => {
                alloc::format!("weak or deprecated DNSSEC algorithm {algorithm} (RFC 9904)")
            }
            Self::NearExpiryRrsig {
                covered_type,
                key_tag,
                seconds_remaining,
            } => alloc::format!(
                "RRSIG (type {covered_type}, key tag {key_tag}) expires in {seconds_remaining}s"
            ),
            Self::CleartextTransfer => String::from("zone transferred over an unencrypted channel"),
        }
    }
}

/// How the SDK reacts to a [`SecurityWarning`] (PRD REQ-SEC-DEFAULT-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SecurityPolicy {
    /// Surface warnings but allow the operation to proceed.
    #[default]
    Warn,
    /// Reject any operation that raises a warning at or above `Warning`.
    DenyOnWarning,
    /// Reject only operations that raise a `Critical` warning.
    DenyOnCritical,
}

impl SecurityPolicy {
    /// Whether a warning of the given severity must be rejected under this policy.
    pub fn rejects(&self, severity: Severity) -> bool {
        match self {
            Self::Warn => false,
            Self::DenyOnWarning => severity >= Severity::Warning,
            Self::DenyOnCritical => severity >= Severity::Critical,
        }
    }
}

/// Whether a TSIG algorithm is deprecated and should raise a warning.
#[allow(deprecated)]
pub fn tsig_algorithm_is_deprecated(algorithm: TsigAlgorithm) -> bool {
    matches!(algorithm, TsigAlgorithm::HmacSha1)
}

/// Whether a DNSSEC algorithm number is weak or deprecated per RFC 9904.
///
/// Covers RSAMD5 (1), DSA (3), RSASHA1 (5), DSA-NSEC3-SHA1 (6),
/// RSASHA1-NSEC3-SHA1 (7), and ECC-GOST (12).
pub fn dnssec_algorithm_is_weak(algorithm: u8) -> bool {
    matches!(algorithm, 1 | 3 | 5 | 6 | 7 | 12)
}

/// Whether a DNSSEC algorithm *mnemonic* (as reported by BIND `rndc
/// dnssec -status`, e.g. `RSASHA1`) is weak or deprecated per RFC 9904.
///
/// Matching is case-insensitive. Unknown names are treated as not-weak so the
/// SDK never produces a false security warning for an algorithm it cannot map.
pub fn dnssec_algorithm_name_is_weak(name: &str) -> bool {
    // RFC 9904 / IANA mnemonics for the deprecated set (1/3/5/6/7/12).
    const WEAK: [&str; 7] = [
        "RSAMD5",
        "DSA",
        "RSASHA1",
        "DSA-NSEC3-SHA1",
        "NSEC3DSA",
        "RSASHA1-NSEC3-SHA1",
        "ECC-GOST",
    ];
    WEAK.iter().any(|w| w.eq_ignore_ascii_case(name))
}

/// Classify a record's DNSSEC/RRSIG material against the current time.
///
/// Returns a [`SecurityWarning`] when an RRSIG is within `warn_window_secs` of
/// expiry (or already expired), or when its signing algorithm is weak.
/// `now_unix` is the current Unix timestamp; pass a trusted clock value (the
/// `no_std` core does not read the clock itself).
pub fn classify_rrsig(
    rdata: &RecordData,
    now_unix: u32,
    warn_window_secs: u32,
) -> Option<SecurityWarning> {
    let RecordData::Rrsig {
        type_covered,
        algorithm,
        signature_expiration,
        key_tag,
        ..
    } = rdata
    else {
        return None;
    };

    if dnssec_algorithm_is_weak(*algorithm) {
        return Some(SecurityWarning::WeakDnssecAlgorithm {
            algorithm: *algorithm,
        });
    }

    let seconds_remaining = i64::from(*signature_expiration) - i64::from(now_unix);
    if seconds_remaining <= i64::from(warn_window_secs) {
        return Some(SecurityWarning::NearExpiryRrsig {
            covered_type: *type_covered,
            key_tag: *key_tag,
            seconds_remaining,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deprecated_tsig_is_flagged() {
        #[allow(deprecated)]
        let weak = TsigAlgorithm::HmacSha1;
        assert!(tsig_algorithm_is_deprecated(weak));
        assert!(!tsig_algorithm_is_deprecated(TsigAlgorithm::HmacSha256));
        assert!(!tsig_algorithm_is_deprecated(TsigAlgorithm::HmacSha512));
    }

    #[test]
    fn weak_dnssec_algorithms_match_rfc_9904() {
        for weak in [1u8, 3, 5, 6, 7, 12] {
            assert!(dnssec_algorithm_is_weak(weak), "alg {weak} should be weak");
        }
        // ECDSAP256SHA256 (13) and ED25519 (15) are recommended.
        assert!(!dnssec_algorithm_is_weak(13));
        assert!(!dnssec_algorithm_is_weak(15));
    }

    #[test]
    fn weak_dnssec_algorithm_names_are_flagged() {
        assert!(dnssec_algorithm_name_is_weak("RSASHA1"));
        assert!(dnssec_algorithm_name_is_weak("rsasha1-nsec3-sha1"));
        assert!(dnssec_algorithm_name_is_weak("ECC-GOST"));
        assert!(!dnssec_algorithm_name_is_weak("ECDSAP256SHA256"));
        assert!(!dnssec_algorithm_name_is_weak("ED25519"));
        assert!(!dnssec_algorithm_name_is_weak("unknown-future-alg"));
    }

    #[test]
    fn policy_rejects_by_severity() {
        assert!(!SecurityPolicy::Warn.rejects(Severity::Critical));
        assert!(SecurityPolicy::DenyOnWarning.rejects(Severity::Warning));
        assert!(SecurityPolicy::DenyOnWarning.rejects(Severity::Critical));
        assert!(!SecurityPolicy::DenyOnCritical.rejects(Severity::Warning));
        assert!(SecurityPolicy::DenyOnCritical.rejects(Severity::Critical));
    }

    fn rrsig(algorithm: u8, expiration: u32) -> RecordData {
        RecordData::Rrsig {
            type_covered: 1,
            algorithm,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: expiration,
            signature_inception: 0,
            key_tag: 12345,
            signer_name: crate::DomainName::new("example.com.").unwrap(),
            signature: alloc::vec![1, 2, 3],
        }
    }

    #[test]
    fn near_expiry_rrsig_is_flagged() {
        // Expires in 1 hour; warn window is 1 day -> warning.
        let warning = classify_rrsig(&rrsig(13, 3600), 0, 86_400).unwrap();
        assert_eq!(warning.severity(), Severity::Warning);
        assert!(matches!(warning, SecurityWarning::NearExpiryRrsig { .. }));
    }

    #[test]
    fn expired_rrsig_is_critical() {
        // now=7200, expired at 3600 -> -3600s, critical.
        let warning = classify_rrsig(&rrsig(13, 3600), 7200, 86_400).unwrap();
        assert_eq!(warning.severity(), Severity::Critical);
    }

    #[test]
    fn weak_algorithm_takes_precedence() {
        let warning = classify_rrsig(&rrsig(5, 0), 0, 0).unwrap();
        assert!(matches!(
            warning,
            SecurityWarning::WeakDnssecAlgorithm { algorithm: 5 }
        ));
    }

    #[test]
    fn healthy_rrsig_is_not_flagged() {
        // Strong algorithm, far from expiry.
        assert!(classify_rrsig(&rrsig(13, 1_000_000), 0, 3600).is_none());
    }

    #[test]
    fn warning_messages_carry_no_secrets() {
        #[allow(deprecated)]
        let w = SecurityWarning::DeprecatedTsigAlgorithm {
            algorithm: TsigAlgorithm::HmacSha1,
        };
        assert!(w.message().contains("hmac-sha1"));
    }
}
