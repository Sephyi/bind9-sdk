// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! DNSSEC/KASP response parsing for rndc commands.
//!
//! Parses the text output of `rndc dnssec -status` and `rndc dnssec -checkds`
//! into structured types for programmatic consumption.

use crate::error::NetError;

/// DNSSEC status for a zone, parsed from `rndc dnssec -status` output.
///
/// Contains the DNSSEC policy name and information about each key
/// managed by the KASP (Key and Signing Policy) engine.
#[derive(Debug, Clone)]
pub struct DnssecStatus {
    /// The DNSSEC policy name (e.g., "default", "custom").
    pub policy: String,
    /// Keys managed by the KASP engine for this zone.
    pub keys: Vec<DnssecKeyInfo>,
}

/// Information about a single DNSSEC key managed by KASP.
#[derive(Debug, Clone)]
pub struct DnssecKeyInfo {
    /// Key tag (RFC 4034 Appendix B) identifying this key.
    pub tag: u16,
    /// Role of this key in the DNSSEC signing hierarchy.
    pub role: KeyRole,
    /// Current KASP state (e.g., "OMNIPRESENT", "RUMOURED", "HIDDEN").
    pub state: String,
}

/// Role of a DNSSEC key in the signing hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRole {
    /// Key Signing Key — signs the DNSKEY RRset.
    Ksk,
    /// Zone Signing Key — signs all other RRsets.
    Zsk,
    /// Combined Signing Key — serves both KSK and ZSK roles.
    Csk,
}

/// Result of a `rndc dnssec -checkds` query.
///
/// Indicates whether the CDS RRset has been published to or withdrawn
/// from the parent zone.
#[derive(Debug, Clone)]
pub struct DsCheckResult {
    /// Whether the CDS RRset is published at the parent.
    pub published: bool,
    /// Whether the CDS RRset has been withdrawn from the parent.
    pub withdrawn: bool,
}

impl DnssecStatus {
    /// Parse the text output of `rndc dnssec -status <zone>`.
    ///
    /// # Expected format
    ///
    /// ```text
    /// dnssec-policy: default
    /// key: 12345 (KSK), state: OMNIPRESENT
    /// key: 54321 (ZSK), state: RUMOURED
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `NetError::Protocol` if the policy line is missing.
    pub fn parse(raw: &str) -> Result<Self, NetError> {
        let mut policy = String::new();
        let mut keys = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();

            if let Some(rest) = trimmed.strip_prefix("dnssec-policy:") {
                policy = rest.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("key:") {
                if let Some(key_info) = parse_key_line(rest.trim()) {
                    keys.push(key_info);
                }
            }
        }

        if policy.is_empty() {
            return Err(NetError::Protocol(
                "dnssec status response missing dnssec-policy field".to_string(),
            ));
        }

        Ok(DnssecStatus { policy, keys })
    }
}

/// Parse a key info line like `12345 (KSK), state: OMNIPRESENT`.
fn parse_key_line(line: &str) -> Option<DnssecKeyInfo> {
    // Expected: "12345 (KSK), state: OMNIPRESENT"
    let tag_end = line.find(' ')?;
    let tag: u16 = line[..tag_end].parse().ok()?;

    let role = if line.contains("(KSK)") {
        KeyRole::Ksk
    } else if line.contains("(ZSK)") {
        KeyRole::Zsk
    } else if line.contains("(CSK)") {
        KeyRole::Csk
    } else {
        return None;
    };

    let state = line
        .split("state:")
        .nth(1)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    Some(DnssecKeyInfo { tag, role, state })
}

impl DsCheckResult {
    /// Parse the text output of `rndc dnssec -checkds <zone>`.
    ///
    /// # Expected format
    ///
    /// ```text
    /// CDS RRset is published: yes
    /// CDS RRset is withdrawn: no
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `NetError::Protocol` if neither field is found.
    pub fn parse(raw: &str) -> Result<Self, NetError> {
        let mut published = false;
        let mut withdrawn = false;
        let mut found_any = false;

        for line in raw.lines() {
            let trimmed = line.trim();

            if let Some(rest) = trimmed.strip_prefix("CDS RRset is published:") {
                published = rest.trim().eq_ignore_ascii_case("yes");
                found_any = true;
            } else if let Some(rest) = trimmed.strip_prefix("CDS RRset is withdrawn:") {
                withdrawn = rest.trim().eq_ignore_ascii_case("yes");
                found_any = true;
            }
        }

        if !found_any {
            return Err(NetError::Protocol(
                "checkds response missing CDS RRset status fields".to_string(),
            ));
        }

        Ok(DsCheckResult {
            published,
            withdrawn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dnssec_status_response() {
        let raw = "dnssec-policy: default\nkey: 12345 (KSK), state: OMNIPRESENT\n";
        let status = DnssecStatus::parse(raw).unwrap();
        assert_eq!(status.policy, "default");
        assert_eq!(status.keys.len(), 1);
        assert_eq!(status.keys[0].tag, 12345);
        assert_eq!(status.keys[0].role, KeyRole::Ksk);
        assert_eq!(status.keys[0].state, "OMNIPRESENT");
    }

    #[test]
    fn parse_dnssec_status_multiple_keys() {
        let raw = "\
dnssec-policy: custom
key: 12345 (KSK), state: OMNIPRESENT
key: 54321 (ZSK), state: RUMOURED
";
        let status = DnssecStatus::parse(raw).unwrap();
        assert_eq!(status.policy, "custom");
        assert_eq!(status.keys.len(), 2);
        assert_eq!(status.keys[0].tag, 12345);
        assert_eq!(status.keys[0].role, KeyRole::Ksk);
        assert_eq!(status.keys[1].tag, 54321);
        assert_eq!(status.keys[1].role, KeyRole::Zsk);
    }

    #[test]
    fn parse_dnssec_status_csk() {
        let raw = "dnssec-policy: default\nkey: 11111 (CSK), state: HIDDEN\n";
        let status = DnssecStatus::parse(raw).unwrap();
        assert_eq!(status.keys[0].role, KeyRole::Csk);
        assert_eq!(status.keys[0].state, "HIDDEN");
    }

    #[test]
    fn parse_dnssec_status_missing_policy() {
        let raw = "key: 12345 (KSK), state: OMNIPRESENT\n";
        let err = DnssecStatus::parse(raw).unwrap_err();
        assert!(err.to_string().contains("missing dnssec-policy"));
    }

    #[test]
    fn parse_ds_check_result() {
        let raw = "CDS RRset is published: yes\nCDS RRset is withdrawn: no\n";
        let result = DsCheckResult::parse(raw).unwrap();
        assert!(result.published);
        assert!(!result.withdrawn);
    }

    #[test]
    fn parse_ds_check_withdrawn() {
        let raw = "CDS RRset is published: no\nCDS RRset is withdrawn: yes\n";
        let result = DsCheckResult::parse(raw).unwrap();
        assert!(!result.published);
        assert!(result.withdrawn);
    }

    #[test]
    fn parse_ds_check_missing_fields() {
        let raw = "some unrelated output\n";
        let err = DsCheckResult::parse(raw).unwrap_err();
        assert!(err.to_string().contains("missing CDS RRset"));
    }
}
