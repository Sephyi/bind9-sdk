// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! DNSSEC/KASP response parsing for rndc commands.
//!
//! Parses the text output of `rndc dnssec -status` into structured types.
//! `rndc dnssec -checkds` is a state-changing command and is represented by
//! [`DsState`](crate::rndc::command::DsState), not by a response parser.

use crate::error::NetError;

/// DNSSEC status for a zone, parsed from `rndc dnssec -status` output.
///
/// Contains the DNSSEC policy name and information about each key
/// managed by the KASP (Key and Signing Policy) engine.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DnssecStatus {
    /// The DNSSEC policy name (e.g., "default", "custom").
    pub policy: String,
    /// Keys managed by the KASP engine for this zone.
    pub keys: Vec<DnssecKeyInfo>,
}

/// Information about a single DNSSEC key managed by KASP.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DnssecKeyInfo {
    /// Key tag (RFC 4034 Appendix B) identifying this key.
    pub tag: u16,
    /// DNSSEC algorithm name reported by BIND, when present.
    pub algorithm: Option<String>,
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

impl DnssecStatus {
    /// Keys signing this zone with a weak or deprecated DNSSEC algorithm
    /// (RFC 9904), reported through a typed API rather than only via tracing
    /// (PRD REQ-LOG-5). Returns the offending [`DnssecKeyInfo`] entries.
    pub fn weak_algorithm_keys(&self) -> Vec<&DnssecKeyInfo> {
        self.keys
            .iter()
            .filter(|k| {
                k.algorithm
                    .as_deref()
                    .is_some_and(bind9_sdk_core::dnssec_algorithm_name_is_weak)
            })
            .collect()
    }

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
        let mut current_key = None;

        for line in raw.lines() {
            let trimmed = line.trim();

            if let Some(rest) = trimmed.strip_prefix("dnssec-policy:") {
                policy = rest.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("key:") {
                let key_info = parse_key_line(rest.trim())?;
                keys.push(key_info);
                current_key = Some(keys.len() - 1);
            } else if let Some(goal) = trimmed.strip_prefix("- goal:")
                && let Some(index) = current_key
            {
                keys[index].state = goal.trim().to_string();
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
fn parse_key_line(line: &str) -> Result<DnssecKeyInfo, NetError> {
    let tag_end = line.find(' ').ok_or_else(|| {
        NetError::Protocol(format!("malformed dnssec key line (missing tag): {line}"))
    })?;
    let tag: u16 = line[..tag_end]
        .parse()
        .map_err(|_| NetError::Protocol(format!("invalid dnssec key tag: {line}")))?;

    let open = line.find('(').ok_or_else(|| {
        NetError::Protocol(format!(
            "malformed dnssec key line (missing algorithm): {line}"
        ))
    })?;
    let close = line[open + 1..]
        .find(')')
        .map(|offset| open + 1 + offset)
        .ok_or_else(|| {
            NetError::Protocol(format!("malformed dnssec key line (missing `)`): {line}"))
        })?;
    let parenthetical = &line[open + 1..close];
    let suffix = line[close + 1..].trim().trim_start_matches(',').trim();

    let (algorithm, role) = match parenthetical {
        "KSK" => (None, KeyRole::Ksk),
        "ZSK" => (None, KeyRole::Zsk),
        "CSK" => (None, KeyRole::Csk),
        algorithm => {
            let role_text = suffix
                .split([',', ' '])
                .find(|part| !part.is_empty())
                .ok_or_else(|| {
                    NetError::Protocol(format!("dnssec key line missing key role: {line}"))
                })?;
            let role = match role_text {
                "KSK" => KeyRole::Ksk,
                "ZSK" => KeyRole::Zsk,
                "CSK" => KeyRole::Csk,
                _ => {
                    return Err(NetError::Protocol(format!(
                        "unsupported dnssec key role `{role_text}`: {line}"
                    )));
                }
            };
            (Some(algorithm.to_string()), role)
        }
    };

    let state = line
        .split("state:")
        .nth(1)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    Ok(DnssecKeyInfo {
        tag,
        algorithm,
        role,
        state,
    })
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
    fn weak_algorithm_keys_flags_deprecated_signers() {
        let status = DnssecStatus {
            policy: "custom".into(),
            keys: vec![
                DnssecKeyInfo {
                    tag: 1,
                    algorithm: Some("RSASHA1".into()),
                    role: KeyRole::Ksk,
                    state: "OMNIPRESENT".into(),
                },
                DnssecKeyInfo {
                    tag: 2,
                    algorithm: Some("ECDSAP256SHA256".into()),
                    role: KeyRole::Zsk,
                    state: "OMNIPRESENT".into(),
                },
            ],
        };
        let weak = status.weak_algorithm_keys();
        assert_eq!(weak.len(), 1);
        assert_eq!(weak[0].tag, 1);
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
    fn parse_dnssec_status_bind_9_20_multiline_key() {
        let raw = "\
dnssec-policy: default
current time:  Fri Jun 19 19:59:55 2026

key: 61161 (ECDSAP256SHA256), CSK
  published:      yes - since Fri Jun 19 19:58:51 2026
  key signing:    yes - since Fri Jun 19 19:58:51 2026
  zone signing:   yes - since Fri Jun 19 19:58:51 2026

  No rollover scheduled
  - goal:           omnipresent
  - dnskey:         rumoured
  - ds:             hidden
  - zone rrsig:     rumoured
  - key rrsig:      rumoured
";
        let status = DnssecStatus::parse(raw).unwrap();
        assert_eq!(status.policy, "default");
        assert_eq!(status.keys.len(), 1);
        assert_eq!(status.keys[0].tag, 61161);
        assert_eq!(status.keys[0].algorithm.as_deref(), Some("ECDSAP256SHA256"));
        assert_eq!(status.keys[0].role, KeyRole::Csk);
        assert_eq!(status.keys[0].state, "omnipresent");
    }

    #[test]
    fn parse_dnssec_status_missing_policy() {
        let raw = "key: 12345 (KSK), state: OMNIPRESENT\n";
        let err = DnssecStatus::parse(raw).unwrap_err();
        assert!(err.to_string().contains("missing dnssec-policy"));
    }
}
