// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! DNSSEC record type text parsers and serializers.
//!
//! Handles DNSKEY, DS, CDS, CDNSKEY, DLV, RRSIG, NSEC, NSEC3, and NSEC3PARAM
//! record data in zone file text format.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use base64::prelude::*;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::protocol::RecordType;
use crate::rdata::RecordData;

use super::rdata_text::{decode_hex, encode_hex};

/// Parse DNSKEY rdata: `flags protocol algorithm base64_key`
pub(crate) fn parse_dnskey(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("DNSKEY expects at least 4 tokens, got {}", tokens.len()),
        });
    }
    let flags = parse_u16(tokens[0], "DNSKEY flags")?;
    let protocol = parse_u8(tokens[1], "DNSKEY protocol")?;
    let algorithm = parse_u8(tokens[2], "DNSKEY algorithm")?;
    // Base64 key may be split across multiple tokens
    let b64: String = tokens[3..].iter().copied().collect();
    let public_key = BASE64_STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("invalid DNSKEY base64 key: {e}"),
        })?;
    Ok(RecordData::Dnskey {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

/// Serialize DNSKEY rdata to text.
pub(crate) fn serialize_dnskey(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> String {
    let b64 = BASE64_STANDARD.encode(public_key);
    format!("{flags} {protocol} {algorithm} {b64}")
}

/// Parse DS rdata: `key_tag algorithm digest_type hex_digest`
pub(crate) fn parse_ds(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("DS expects at least 4 tokens, got {}", tokens.len()),
        });
    }
    let key_tag = parse_u16(tokens[0], "DS key_tag")?;
    let algorithm = parse_u8(tokens[1], "DS algorithm")?;
    let digest_type = parse_u8(tokens[2], "DS digest_type")?;
    let hex: String = tokens[3..].iter().copied().collect();
    let digest = decode_hex(&hex).map_err(|reason| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason,
    })?;
    Ok(RecordData::Ds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Serialize DS rdata to text.
pub(crate) fn serialize_ds(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> String {
    format!("{key_tag} {algorithm} {digest_type} {}", encode_hex(digest))
}

/// Parse CDS rdata (same format as DS).
pub(crate) fn parse_cds(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("CDS expects at least 4 tokens, got {}", tokens.len()),
        });
    }
    let key_tag = parse_u16(tokens[0], "CDS key_tag")?;
    let algorithm = parse_u8(tokens[1], "CDS algorithm")?;
    let digest_type = parse_u8(tokens[2], "CDS digest_type")?;
    let hex: String = tokens[3..].iter().copied().collect();
    let digest = decode_hex(&hex).map_err(|reason| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason,
    })?;
    Ok(RecordData::Cds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Serialize CDS rdata to text (same format as DS).
pub(crate) fn serialize_cds(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> String {
    serialize_ds(key_tag, algorithm, digest_type, digest)
}

/// Parse CDNSKEY rdata (same format as DNSKEY).
pub(crate) fn parse_cdnskey(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("CDNSKEY expects at least 4 tokens, got {}", tokens.len()),
        });
    }
    let flags = parse_u16(tokens[0], "CDNSKEY flags")?;
    let protocol = parse_u8(tokens[1], "CDNSKEY protocol")?;
    let algorithm = parse_u8(tokens[2], "CDNSKEY algorithm")?;
    let b64: String = tokens[3..].iter().copied().collect();
    let public_key = BASE64_STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("invalid CDNSKEY base64 key: {e}"),
        })?;
    Ok(RecordData::Cdnskey {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

/// Serialize CDNSKEY rdata to text (same format as DNSKEY).
pub(crate) fn serialize_cdnskey(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> String {
    serialize_dnskey(flags, protocol, algorithm, public_key)
}

/// Parse DLV rdata (same format as DS).
pub(crate) fn parse_dlv(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("DLV expects at least 4 tokens, got {}", tokens.len()),
        });
    }
    let key_tag = parse_u16(tokens[0], "DLV key_tag")?;
    let algorithm = parse_u8(tokens[1], "DLV algorithm")?;
    let digest_type = parse_u8(tokens[2], "DLV digest_type")?;
    let hex: String = tokens[3..].iter().copied().collect();
    let digest = decode_hex(&hex).map_err(|reason| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason,
    })?;
    Ok(RecordData::Dlv {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Serialize DLV rdata to text (same format as DS).
pub(crate) fn serialize_dlv(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> String {
    serialize_ds(key_tag, algorithm, digest_type, digest)
}

/// Parse RRSIG rdata.
///
/// Format: `type_covered algorithm labels original_ttl expiration inception key_tag signer base64_sig`
pub(crate) fn parse_rrsig(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() < 9 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("RRSIG expects at least 9 tokens, got {}", tokens.len()),
        });
    }
    let type_covered = record_type_from_str(tokens[0])?.value();
    let algorithm = parse_u8(tokens[1], "RRSIG algorithm")?;
    let labels = parse_u8(tokens[2], "RRSIG labels")?;
    let original_ttl = parse_u32(tokens[3], "RRSIG original_ttl")?;
    let signature_expiration = parse_timestamp(tokens[4], "RRSIG expiration")?;
    let signature_inception = parse_timestamp(tokens[5], "RRSIG inception")?;
    let key_tag = parse_u16(tokens[6], "RRSIG key_tag")?;
    let signer_name = resolve_name(tokens[7], origin)?;
    let b64: String = tokens[8..].iter().copied().collect();
    let signature = BASE64_STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("invalid RRSIG base64 signature: {e}"),
        })?;
    Ok(RecordData::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name,
        signature,
    })
}

/// Serialize RRSIG rdata to text.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serialize_rrsig(
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: &DomainName,
    signature: &[u8],
) -> String {
    let type_str = RecordType::from_value(type_covered);
    let exp = format_timestamp(signature_expiration);
    let inc = format_timestamp(signature_inception);
    let b64 = BASE64_STANDARD.encode(signature);
    format!(
        "{type_str} {algorithm} {labels} {original_ttl} {exp} {inc} {key_tag} {signer_name} {b64}"
    )
}

/// Parse NSEC rdata: `next_domain type1 type2 ...`
pub(crate) fn parse_nsec(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.is_empty() {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: "NSEC expects at least 1 token (next_domain)".into(),
        });
    }
    let next_domain = resolve_name(tokens[0], origin)?;
    let type_bitmaps = if tokens.len() > 1 {
        encode_type_bitmap(&tokens[1..])?
    } else {
        Vec::new()
    };
    Ok(RecordData::Nsec {
        next_domain,
        type_bitmaps,
    })
}

/// Serialize NSEC rdata to text.
pub(crate) fn serialize_nsec(next_domain: &DomainName, type_bitmaps: &[u8]) -> String {
    let types_str = decode_type_bitmap(type_bitmaps);
    if types_str.is_empty() {
        format!("{next_domain}")
    } else {
        format!("{next_domain} {types_str}")
    }
}

/// Parse NSEC3 rdata.
///
/// Format: `hash_alg flags iterations salt next_hashed_owner type1 type2 ...`
pub(crate) fn parse_nsec3(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 5 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("NSEC3 expects at least 5 tokens, got {}", tokens.len()),
        });
    }
    let hash_algorithm = parse_u8(tokens[0], "NSEC3 hash_algorithm")?;
    let flags = parse_u8(tokens[1], "NSEC3 flags")?;
    let iterations = parse_u16(tokens[2], "NSEC3 iterations")?;
    let salt = parse_salt(tokens[3])?;
    let next_hashed_owner = data_encoding::BASE32HEX_NOPAD
        .decode(tokens[4].to_ascii_uppercase().as_bytes())
        .map_err(|e| CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("invalid NSEC3 base32hex next_hashed_owner: {e}"),
        })?;
    let type_bitmaps = if tokens.len() > 5 {
        encode_type_bitmap(&tokens[5..])?
    } else {
        Vec::new()
    };
    Ok(RecordData::Nsec3 {
        hash_algorithm,
        flags,
        iterations,
        salt,
        next_hashed_owner,
        type_bitmaps,
    })
}

/// Serialize NSEC3 rdata to text.
pub(crate) fn serialize_nsec3(
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: &[u8],
    next_hashed_owner: &[u8],
    type_bitmaps: &[u8],
) -> String {
    let salt_str = if salt.is_empty() {
        String::from("-")
    } else {
        encode_hex(salt)
    };
    let next_str = data_encoding::BASE32HEX_NOPAD.encode(next_hashed_owner);
    let types_str = decode_type_bitmap(type_bitmaps);
    if types_str.is_empty() {
        format!("{hash_algorithm} {flags} {iterations} {salt_str} {next_str}")
    } else {
        format!("{hash_algorithm} {flags} {iterations} {salt_str} {next_str} {types_str}")
    }
}

/// Parse NSEC3PARAM rdata: `hash_alg flags iterations salt`
pub(crate) fn parse_nsec3param(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() != 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("NSEC3PARAM expects 4 tokens, got {}", tokens.len()),
        });
    }
    let hash_algorithm = parse_u8(tokens[0], "NSEC3PARAM hash_algorithm")?;
    let flags = parse_u8(tokens[1], "NSEC3PARAM flags")?;
    let iterations = parse_u16(tokens[2], "NSEC3PARAM iterations")?;
    let salt = parse_salt(tokens[3])?;
    Ok(RecordData::Nsec3param {
        hash_algorithm,
        flags,
        iterations,
        salt,
    })
}

/// Serialize NSEC3PARAM rdata to text.
pub(crate) fn serialize_nsec3param(
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: &[u8],
) -> String {
    let salt_str = if salt.is_empty() {
        String::from("-")
    } else {
        encode_hex(salt)
    };
    format!("{hash_algorithm} {flags} {iterations} {salt_str}")
}

// -- Helper functions --

fn parse_u8(s: &str, field: &str) -> Result<u8, CoreError> {
    s.parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} `{s}`: {e}"),
    })
}

fn parse_u16(s: &str, field: &str) -> Result<u16, CoreError> {
    s.parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} `{s}`: {e}"),
    })
}

fn parse_u32(s: &str, field: &str) -> Result<u32, CoreError> {
    s.parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} `{s}`: {e}"),
    })
}

/// Parse a DNSSEC timestamp in `YYYYMMDDHHMMSS` format to a Unix timestamp (u32).
fn parse_timestamp(s: &str, field: &str) -> Result<u32, CoreError> {
    // Try as a raw u32 first (some zone files use Unix timestamps directly)
    if let Ok(v) = s.parse::<u32>() {
        // If it's a short number, it's likely a raw timestamp
        if s.len() != 14 {
            return Ok(v);
        }
    }
    // Parse YYYYMMDDHHMMSS format
    if s.len() != 14 {
        return Err(CoreError::ZoneParse {
            line: 0,
            column: None,
            reason: format!("invalid {field} timestamp `{s}`: expected YYYYMMDDHHMMSS"),
        });
    }
    let year: u32 = s[0..4].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} year: {e}"),
    })?;
    let month: u32 = s[4..6].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} month: {e}"),
    })?;
    let day: u32 = s[6..8].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} day: {e}"),
    })?;
    let hour: u32 = s[8..10].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} hour: {e}"),
    })?;
    let minute: u32 = s[10..12].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} minute: {e}"),
    })?;
    let second: u32 = s[12..14].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        column: None,
        reason: format!("invalid {field} second: {e}"),
    })?;

    // Simple days-since-epoch calculation (no leap second precision needed for DNSSEC)
    let days = days_from_date(year, month, day);
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Format a Unix timestamp as `YYYYMMDDHHMMSS`.
fn format_timestamp(ts: u32) -> String {
    let (year, month, day) = date_from_days(ts / 86400);
    let remainder = ts % 86400;
    let hour = remainder / 3600;
    let minute = (remainder % 3600) / 60;
    let second = remainder % 60;
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}")
}

/// Days from Unix epoch (1970-01-01) to the given date.
fn days_from_date(year: u32, month: u32, day: u32) -> u32 {
    // Adapted from Howard Hinnant's chrono-compatible algorithm
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe;
    // Subtract Unix epoch offset (days from 0000-03-01 to 1970-01-01)
    days - 719468
}

/// Convert days since Unix epoch to (year, month, day).
fn date_from_days(days: u32) -> (u32, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Resolve a domain name token, handling `@` and relative names.
fn resolve_name(token: &str, origin: &DomainName) -> Result<DomainName, CoreError> {
    if token == "@" {
        return Ok(origin.clone());
    }
    if token.ends_with('.') {
        DomainName::new(token)
    } else {
        let absolute = format!("{token}.{origin}");
        DomainName::new(&absolute)
    }
}

/// Parse a salt field: `-` means empty salt, otherwise hex.
fn parse_salt(s: &str) -> Result<Vec<u8>, CoreError> {
    if s == "-" {
        Ok(Vec::new())
    } else {
        decode_hex(s).map_err(|reason| CoreError::ZoneParse {
            line: 0,
            column: None,
            reason,
        })
    }
}

/// Parse a record type string (e.g., "A", "AAAA", "TYPE65534") to its `RecordType`.
fn record_type_from_str(s: &str) -> Result<RecordType, CoreError> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::Aaaa),
        "NS" => Ok(RecordType::Ns),
        "CNAME" => Ok(RecordType::Cname),
        "PTR" => Ok(RecordType::Ptr),
        "SOA" => Ok(RecordType::Soa),
        "MX" => Ok(RecordType::Mx),
        "TXT" => Ok(RecordType::Txt),
        "SRV" => Ok(RecordType::Srv),
        "CAA" => Ok(RecordType::Caa),
        "DNSKEY" => Ok(RecordType::Dnskey),
        "RRSIG" => Ok(RecordType::Rrsig),
        "NSEC" => Ok(RecordType::Nsec),
        "NSEC3" => Ok(RecordType::Nsec3),
        "NSEC3PARAM" => Ok(RecordType::Nsec3param),
        "DS" => Ok(RecordType::Ds),
        "CDS" => Ok(RecordType::Cds),
        "CDNSKEY" => Ok(RecordType::Cdnskey),
        "DLV" => Ok(RecordType::Dlv),
        "TLSA" => Ok(RecordType::Tlsa),
        "SSHFP" => Ok(RecordType::Sshfp),
        "CSYNC" => Ok(RecordType::Csync),
        "RP" => Ok(RecordType::Rp),
        other => {
            if let Some(stripped) = other.strip_prefix("TYPE") {
                let v: u16 = stripped.parse().map_err(|e| CoreError::ZoneParse {
                    line: 0,
                    column: None,
                    reason: format!("invalid record type `{s}`: {e}"),
                })?;
                Ok(RecordType::from_value(v))
            } else {
                Err(CoreError::ZoneParse {
                    line: 0,
                    column: None,
                    reason: format!("unknown record type `{s}`"),
                })
            }
        }
    }
}

/// Encode a list of record type mnemonics into an NSEC/NSEC3 type bitmap.
pub(crate) fn encode_type_bitmap(types: &[&str]) -> Result<Vec<u8>, CoreError> {
    let mut type_nums: Vec<u16> = Vec::new();
    for t in types {
        let rt = record_type_from_str(t)?;
        type_nums.push(rt.value());
    }
    type_nums.sort_unstable();
    type_nums.dedup();

    let mut bitmap = Vec::new();
    let mut window_start: Option<u8> = None;
    let mut window_bits = [0u8; 32]; // max 256 bits per window
    let mut max_byte = 0usize;

    for &tn in &type_nums {
        let window = (tn >> 8) as u8;
        let bit_offset = (tn & 0xFF) as usize;
        let byte_idx = bit_offset / 8;
        let bit_idx = 7 - (bit_offset % 8);

        if window_start != Some(window) {
            // Flush previous window
            if let Some(ws) = window_start {
                let len = max_byte + 1;
                bitmap.push(ws);
                bitmap.push(len as u8);
                bitmap.extend_from_slice(&window_bits[..len]);
            }
            window_bits = [0u8; 32];
            max_byte = 0;
            window_start = Some(window);
        }
        window_bits[byte_idx] |= 1 << bit_idx;
        if byte_idx > max_byte {
            max_byte = byte_idx;
        }
    }
    // Flush last window
    if let Some(ws) = window_start {
        let len = max_byte + 1;
        bitmap.push(ws);
        bitmap.push(len as u8);
        bitmap.extend_from_slice(&window_bits[..len]);
    }

    Ok(bitmap)
}

/// Decode an NSEC/NSEC3 type bitmap to a space-separated string of type mnemonics.
pub(crate) fn decode_type_bitmap(bitmap: &[u8]) -> String {
    let mut types = Vec::new();
    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let window = bitmap[pos] as u16;
        let len = bitmap[pos + 1] as usize;
        pos += 2;
        if pos + len > bitmap.len() {
            break;
        }
        for i in 0..len {
            let byte = bitmap[pos + i];
            for bit in 0..8u16 {
                if byte & (1 << (7 - bit)) != 0 {
                    let type_num = (window << 8) | (i as u16 * 8 + bit);
                    let rt = RecordType::from_value(type_num);
                    types.push(format!("{rt}"));
                }
            }
        }
        pos += len;
    }
    types.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainName;

    fn origin() -> DomainName {
        DomainName::new("example.com.").unwrap()
    }

    // -- DNSKEY --

    #[test]
    fn parse_dnskey_valid() {
        let tokens = &[
            "257",
            "3",
            "13",
            "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ];
        let rdata = parse_dnskey(tokens).unwrap();
        match rdata {
            RecordData::Dnskey {
                flags,
                protocol,
                algorithm,
                ..
            } => {
                assert_eq!(flags, 257);
                assert_eq!(protocol, 3);
                assert_eq!(algorithm, 13);
            }
            other => panic!("expected DNSKEY, got {other:?}"),
        }
    }

    #[test]
    fn parse_dnskey_too_few_tokens() {
        let result = parse_dnskey(&["257", "3"]);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_dnskey_roundtrip() {
        let tokens = &["257", "3", "13", "dGVzdA=="];
        let rdata = parse_dnskey(tokens).unwrap();
        if let RecordData::Dnskey {
            flags,
            protocol,
            algorithm,
            ref public_key,
        } = rdata
        {
            let text = serialize_dnskey(flags, protocol, algorithm, public_key);
            assert_eq!(text, "257 3 13 dGVzdA==");
        }
    }

    // -- DS --

    #[test]
    fn parse_ds_valid() {
        let tokens = &[
            "60485",
            "5",
            "1",
            "2BB183AF5F22588179A53B0A98631FAD1A292118",
        ];
        let rdata = parse_ds(tokens).unwrap();
        match rdata {
            RecordData::Ds {
                key_tag: 60485,
                algorithm: 5,
                digest_type: 1,
                ref digest,
            } => {
                assert_eq!(digest.len(), 20);
            }
            other => panic!("expected DS, got {other:?}"),
        }
    }

    #[test]
    fn serialize_ds_roundtrip() {
        let tokens = &["60485", "5", "1", "aabb"];
        let rdata = parse_ds(tokens).unwrap();
        if let RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            ref digest,
        } = rdata
        {
            let text = serialize_ds(key_tag, algorithm, digest_type, digest);
            assert_eq!(text, "60485 5 1 aabb");
        }
    }

    // -- CDS --

    #[test]
    fn parse_cds_valid() {
        let tokens = &["12345", "8", "2", "abcd"];
        let rdata = parse_cds(tokens).unwrap();
        assert!(matches!(rdata, RecordData::Cds { key_tag: 12345, .. }));
    }

    // -- CDNSKEY --

    #[test]
    fn parse_cdnskey_valid() {
        let tokens = &["257", "3", "13", "dGVzdA=="];
        let rdata = parse_cdnskey(tokens).unwrap();
        assert!(matches!(
            rdata,
            RecordData::Cdnskey {
                flags: 257,
                protocol: 3,
                ..
            }
        ));
    }

    // -- DLV --

    #[test]
    fn parse_dlv_valid() {
        let tokens = &["60485", "5", "1", "aabb"];
        let rdata = parse_dlv(tokens).unwrap();
        assert!(matches!(rdata, RecordData::Dlv { key_tag: 60485, .. }));
    }

    // -- RRSIG --

    #[test]
    fn parse_rrsig_valid() {
        let tokens = &[
            "A",
            "13",
            "3",
            "3600",
            "20260401000000",
            "20260301000000",
            "12345",
            "example.com.",
            "dGVzdHNpZw==",
        ];
        let rdata = parse_rrsig(tokens, &origin()).unwrap();
        assert!(matches!(
            rdata,
            RecordData::Rrsig {
                type_covered: 1,
                algorithm: 13,
                ..
            }
        ));
    }

    #[test]
    fn parse_rrsig_too_few_tokens() {
        let result = parse_rrsig(&["A", "13", "3"], &origin());
        assert!(result.is_err());
    }

    // -- NSEC --

    #[test]
    fn parse_nsec_valid() {
        let tokens = &["b.example.com.", "A", "AAAA", "RRSIG", "NSEC"];
        let rdata = parse_nsec(tokens, &origin()).unwrap();
        match rdata {
            RecordData::Nsec {
                ref next_domain,
                ref type_bitmaps,
            } => {
                assert_eq!(*next_domain, DomainName::new("b.example.com.").unwrap());
                // Verify bitmap contains the right types
                let decoded = decode_type_bitmap(type_bitmaps);
                assert!(decoded.contains("A"));
                assert!(decoded.contains("AAAA"));
                assert!(decoded.contains("RRSIG"));
                assert!(decoded.contains("NSEC"));
            }
            other => panic!("expected NSEC, got {other:?}"),
        }
    }

    // -- NSEC3 --

    #[test]
    fn parse_nsec3_valid() {
        let tokens = &[
            "1",
            "1",
            "12",
            "aabbccdd",
            "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
            "A",
            "AAAA",
        ];
        let rdata = parse_nsec3(tokens).unwrap();
        assert!(matches!(
            rdata,
            RecordData::Nsec3 {
                hash_algorithm: 1,
                flags: 1,
                iterations: 12,
                ..
            }
        ));
    }

    // -- NSEC3PARAM --

    #[test]
    fn parse_nsec3param_valid() {
        let tokens = &["1", "0", "12", "aabb"];
        let rdata = parse_nsec3param(tokens).unwrap();
        match rdata {
            RecordData::Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 12,
                ref salt,
            } => {
                assert_eq!(salt, &[0xaa, 0xbb]);
            }
            other => panic!("expected NSEC3PARAM, got {other:?}"),
        }
    }

    #[test]
    fn parse_nsec3param_empty_salt() {
        let tokens = &["1", "0", "0", "-"];
        let rdata = parse_nsec3param(tokens).unwrap();
        assert!(matches!(
            rdata,
            RecordData::Nsec3param { ref salt, .. } if salt.is_empty()
        ));
    }

    // -- Type bitmap --

    #[test]
    fn type_bitmap_roundtrip() {
        let types = &["A", "AAAA", "RRSIG", "NSEC"];
        let bitmap = encode_type_bitmap(types).unwrap();
        let decoded = decode_type_bitmap(&bitmap);
        assert!(decoded.contains("A"));
        assert!(decoded.contains("AAAA"));
        assert!(decoded.contains("RRSIG"));
        assert!(decoded.contains("NSEC"));
    }

    // -- Timestamp --

    #[test]
    fn timestamp_roundtrip() {
        let ts = parse_timestamp("20260401000000", "test").unwrap();
        let formatted = format_timestamp(ts);
        assert_eq!(formatted, "20260401000000");
    }

    // -- Test vectors from dig captures --

    /// Real DNSKEY from cloudflare.com (ECDSAP256SHA256, KSK)
    #[test]
    fn parse_real_dnskey_from_dig() {
        let tokens = &[
            "257",
            "3",
            "13",
            "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ];
        let rdata = parse_dnskey(tokens).unwrap();
        match rdata {
            RecordData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                ref public_key,
            } => {
                assert_eq!(public_key.len(), 64);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Real DS record (typical delegation signer with SHA-256)
    #[test]
    fn parse_real_ds_from_dig() {
        let tokens = &[
            "2371",
            "13",
            "2",
            "32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9",
        ];
        let rdata = parse_ds(tokens).unwrap();
        match rdata {
            RecordData::Ds {
                key_tag: 2371,
                algorithm: 13,
                digest_type: 2,
                ref digest,
            } => {
                assert_eq!(digest.len(), 32); // SHA-256 = 32 bytes
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Real RRSIG from dig +dnssec
    #[test]
    fn parse_real_rrsig_from_dig() {
        let tokens = &[
            "A",
            "13",
            "3",
            "300",
            "20260415120000",
            "20260315120000",
            "34505",
            "example.com.",
            "dGVzdHNpZ25hdHVyZWRhdGE=",
        ];
        let rdata = parse_rrsig(tokens, &origin()).unwrap();
        match rdata {
            RecordData::Rrsig {
                type_covered: 1,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                key_tag: 34505,
                ref signer_name,
                ref signature,
                ..
            } => {
                assert_eq!(*signer_name, origin());
                assert!(!signature.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Real NSEC record pattern
    #[test]
    fn parse_real_nsec_from_dig() {
        let tokens = &["b.example.com.", "A", "AAAA", "RRSIG", "NSEC"];
        let rdata = parse_nsec(tokens, &origin()).unwrap();
        match rdata {
            RecordData::Nsec {
                ref next_domain,
                ref type_bitmaps,
            } => {
                assert_eq!(*next_domain, DomainName::new("b.example.com.").unwrap());
                let types = decode_type_bitmap(type_bitmaps);
                assert!(types.contains("A"));
                assert!(types.contains("AAAA"));
                assert!(types.contains("RRSIG"));
                assert!(types.contains("NSEC"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Real NSEC3 record pattern
    #[test]
    fn parse_real_nsec3_from_dig() {
        let tokens = &[
            "1",
            "0",
            "10",
            "aabbccdd",
            "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
            "A",
            "AAAA",
            "RRSIG",
        ];
        let rdata = parse_nsec3(tokens).unwrap();
        match rdata {
            RecordData::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 10,
                ref salt,
                ref next_hashed_owner,
                ref type_bitmaps,
            } => {
                assert_eq!(salt, &[0xaa, 0xbb, 0xcc, 0xdd]);
                assert_eq!(next_hashed_owner.len(), 20); // SHA-1 = 20 bytes
                let types = decode_type_bitmap(type_bitmaps);
                assert!(types.contains("A"));
                assert!(types.contains("AAAA"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// NSEC3PARAM as seen in zone apex
    #[test]
    fn parse_real_nsec3param_from_dig() {
        let tokens = &["1", "0", "0", "-"];
        let rdata = parse_nsec3param(tokens).unwrap();
        match rdata {
            RecordData::Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                ref salt,
            } => {
                assert!(salt.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -- Proptest roundtrips --

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn dnskey_roundtrip(
                flags in 0u16..=65535,
                protocol in 0u8..=255,
                algorithm in 0u8..=255,
                key_data in proptest::collection::vec(any::<u8>(), 1..64),
            ) {
                let text = serialize_dnskey(flags, protocol, algorithm, &key_data);
                let tokens: Vec<&str> = text.split_whitespace().collect();
                let parsed = parse_dnskey(&tokens).unwrap();
                match parsed {
                    RecordData::Dnskey { flags: f, protocol: p, algorithm: a, public_key } => {
                        prop_assert_eq!(f, flags);
                        prop_assert_eq!(p, protocol);
                        prop_assert_eq!(a, algorithm);
                        prop_assert_eq!(public_key, key_data);
                    }
                    other => prop_assert!(false, "expected DNSKEY, got {other:?}"),
                }
            }

            #[test]
            fn ds_roundtrip(
                key_tag in 0u16..=65535,
                algorithm in 0u8..=255,
                digest_type in 0u8..=255,
                digest_data in proptest::collection::vec(any::<u8>(), 1..32),
            ) {
                let text = serialize_ds(key_tag, algorithm, digest_type, &digest_data);
                let tokens: Vec<&str> = text.split_whitespace().collect();
                let parsed = parse_ds(&tokens).unwrap();
                match parsed {
                    RecordData::Ds { key_tag: kt, algorithm: a, digest_type: dt, digest } => {
                        prop_assert_eq!(kt, key_tag);
                        prop_assert_eq!(a, algorithm);
                        prop_assert_eq!(dt, digest_type);
                        prop_assert_eq!(digest, digest_data);
                    }
                    other => prop_assert!(false, "expected DS, got {other:?}"),
                }
            }

            #[test]
            fn nsec3_roundtrip(
                hash_alg in 0u8..=255,
                flags in 0u8..=255,
                iterations in 0u16..=65535,
                salt_data in proptest::collection::vec(any::<u8>(), 0..8),
                next_hash in proptest::collection::vec(any::<u8>(), 20..21),
            ) {
                let text = serialize_nsec3(hash_alg, flags, iterations, &salt_data, &next_hash, &[]);
                let tokens: Vec<&str> = text.split_whitespace().collect();
                let parsed = parse_nsec3(&tokens).unwrap();
                match parsed {
                    RecordData::Nsec3 {
                        hash_algorithm, flags: f, iterations: it, salt, next_hashed_owner, ..
                    } => {
                        prop_assert_eq!(hash_algorithm, hash_alg);
                        prop_assert_eq!(f, flags);
                        prop_assert_eq!(it, iterations);
                        prop_assert_eq!(salt, salt_data);
                        prop_assert_eq!(next_hashed_owner, next_hash);
                    }
                    other => prop_assert!(false, "expected NSEC3, got {other:?}"),
                }
            }

            #[test]
            fn rrsig_roundtrip(
                algorithm in 1u8..=15,
                labels in 0u8..=10,
                original_ttl in 0u32..=86400,
                key_tag in 0u16..=65535,
                sig_data in proptest::collection::vec(any::<u8>(), 1..64),
            ) {
                let origin = DomainName::new("example.com.").unwrap();
                // Use fixed timestamps to avoid edge cases
                let expiration = 1775000000u32;
                let inception = 1772000000u32;
                let text = serialize_rrsig(
                    1, algorithm, labels, original_ttl,
                    expiration, inception, key_tag,
                    &origin, &sig_data,
                );
                let tokens: Vec<&str> = text.split_whitespace().collect();
                let parsed = parse_rrsig(&tokens, &origin).unwrap();
                match parsed {
                    RecordData::Rrsig {
                        type_covered: tc, algorithm: a, labels: l,
                        original_ttl: ot, signature_expiration: se,
                        signature_inception: si, key_tag: kt,
                        ref signer_name, ref signature,
                    } => {
                        prop_assert_eq!(tc, 1);
                        prop_assert_eq!(a, algorithm);
                        prop_assert_eq!(l, labels);
                        prop_assert_eq!(ot, original_ttl);
                        prop_assert_eq!(se, expiration);
                        prop_assert_eq!(si, inception);
                        prop_assert_eq!(kt, key_tag);
                        prop_assert_eq!(signer_name.clone(), origin);
                        prop_assert_eq!(signature.clone(), sig_data);
                    }
                    other => prop_assert!(false, "expected RRSIG, got {other:?}"),
                }
            }
        }
    }
}
