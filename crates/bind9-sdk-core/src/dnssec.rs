// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! DNSSEC utilities: CDS/CDNSKEY generation and key tag computation.
//!
//! Provides helpers for generating CDS records from DNSKEY records
//! (RFC 4034 §5.1.4 digest computation), RFC 8078 DELETE sentinel
//! CDS/CDNSKEY records, and key tag computation per RFC 4034 Appendix B.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest, Sha256, Sha384};

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::rdata::RecordData;

/// Digest algorithm for DS/CDS record generation.
///
/// Maps to IANA "Delegation Signer (DS) RR Type Digest Algorithms" registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestType {
    /// SHA-256 (digest type 2, mandatory per RFC 4509).
    Sha256,
    /// SHA-384 (digest type 4, RFC 6605).
    Sha384,
}

impl DigestType {
    /// Return the IANA-assigned numeric value for this digest type.
    pub fn value(self) -> u8 {
        match self {
            Self::Sha256 => 2,
            Self::Sha384 => 4,
        }
    }
}

/// Namespace for CDS record construction helpers.
///
/// CDS records are used for automated DNSSEC delegation trust maintenance
/// (RFC 7344). They carry the same content as DS records but are published
/// in the child zone to signal the parent.
pub struct CdsRecord;

impl CdsRecord {
    /// Generate a CDS record from a DNSKEY record.
    ///
    /// Computes the DS digest per RFC 4034 §5.1.4:
    /// `digest = hash(owner_name_wire || dnskey_rdata_wire)`
    ///
    /// The owner name is written in DNS wire format (uncompressed, original case).
    /// The DNSKEY RDATA wire format is: `flags(2) || protocol(1) || algorithm(1) || public_key`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidRecord` if `dnskey` is not a `RecordData::Dnskey`.
    pub fn from_dnskey(
        owner: &DomainName,
        dnskey: &RecordData,
        digest_type: DigestType,
    ) -> Result<RecordData, CoreError> {
        let (flags, protocol, algorithm, public_key) = match dnskey {
            RecordData::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => (*flags, *protocol, *algorithm, public_key),
            _ => {
                return Err(CoreError::InvalidRecord(String::from(
                    "expected DNSKEY record",
                )));
            }
        };

        let key_tag = compute_key_tag(flags, protocol, algorithm, public_key);

        // Build digest input: owner wire format + DNSKEY RDATA wire format
        let mut input = Vec::new();
        owner.write_wire(&mut input);
        input.extend_from_slice(&flags.to_be_bytes());
        input.push(protocol);
        input.push(algorithm);
        input.extend_from_slice(public_key);

        let digest = match digest_type {
            DigestType::Sha256 => Sha256::digest(&input).to_vec(),
            DigestType::Sha384 => Sha384::digest(&input).to_vec(),
        };

        Ok(RecordData::Cds {
            key_tag,
            algorithm,
            digest_type: digest_type.value(),
            digest,
        })
    }

    /// Create an RFC 8078 §4 DELETE sentinel CDS record.
    ///
    /// This special CDS record signals the parent to remove the DS record,
    /// effectively disabling DNSSEC for the child zone.
    ///
    /// Fields: `key_tag=0, algorithm=0, digest_type=0, digest=[0x00]`
    pub fn delete_sentinel() -> RecordData {
        RecordData::Cds {
            key_tag: 0,
            algorithm: 0,
            digest_type: 0,
            digest: vec![0x00],
        }
    }
}

/// Compute a DNSKEY key tag per RFC 4034 Appendix B.
///
/// The key tag is a 16-bit value derived from the DNSKEY RDATA that provides
/// a quick way to identify which key was used to generate a signature.
///
/// Input is the DNSKEY RDATA fields: `flags || protocol || algorithm || public_key`.
pub fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += u32::from(byte) << 8;
        } else {
            ac += u32::from(byte);
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;

    use crate::domain::DomainName;
    use crate::rdata::RecordData;

    #[test]
    fn cds_from_dnskey_sha256() {
        let dnskey = RecordData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![0xAA; 64], // 64 bytes for P-256 test key
        };
        let owner = DomainName::new("example.com.").unwrap();
        let cds = CdsRecord::from_dnskey(&owner, &dnskey, DigestType::Sha256).unwrap();
        match cds {
            RecordData::Cds {
                algorithm,
                digest_type,
                ref digest,
                ..
            } => {
                assert_eq!(algorithm, 13);
                assert_eq!(digest_type, 2); // SHA-256 = 2
                assert_eq!(digest.len(), 32);
            }
            ref other => panic!("expected CDS, got {other:?}"),
        }
    }

    #[test]
    fn cds_from_dnskey_sha384() {
        let dnskey = RecordData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![0xBB; 64],
        };
        let owner = DomainName::new("example.com.").unwrap();
        let cds = CdsRecord::from_dnskey(&owner, &dnskey, DigestType::Sha384).unwrap();
        match cds {
            RecordData::Cds {
                digest_type,
                ref digest,
                ..
            } => {
                assert_eq!(digest_type, 4); // SHA-384 = 4
                assert_eq!(digest.len(), 48);
            }
            ref other => panic!("expected CDS, got {other:?}"),
        }
    }

    #[test]
    fn cds_from_non_dnskey_fails() {
        let not_dnskey = RecordData::A(core::net::Ipv4Addr::new(1, 2, 3, 4));
        let owner = DomainName::new("example.com.").unwrap();
        let err = CdsRecord::from_dnskey(&owner, &not_dnskey, DigestType::Sha256).unwrap_err();
        assert!(err.to_string().contains("expected DNSKEY"));
    }

    #[test]
    fn delete_sentinel_cds() {
        let cds = CdsRecord::delete_sentinel();
        match cds {
            RecordData::Cds {
                key_tag,
                algorithm,
                digest_type,
                ref digest,
            } => {
                assert_eq!(key_tag, 0);
                assert_eq!(algorithm, 0);
                assert_eq!(digest_type, 0);
                assert_eq!(digest, &[0x00]);
            }
            ref other => panic!("expected CDS, got {other:?}"),
        }
    }

    #[test]
    fn compute_key_tag_nonzero() {
        let tag = compute_key_tag(257, 3, 13, &[0xAA; 64]);
        assert_ne!(tag, 0, "key tag should be nonzero for non-trivial key");
    }

    #[test]
    fn compute_key_tag_deterministic() {
        let tag1 = compute_key_tag(257, 3, 13, &[0xAA; 64]);
        let tag2 = compute_key_tag(257, 3, 13, &[0xAA; 64]);
        assert_eq!(tag1, tag2, "key tag must be deterministic");
    }

    #[test]
    fn compute_key_tag_differs_for_different_keys() {
        let tag_a = compute_key_tag(257, 3, 13, &[0xAA; 64]);
        let tag_b = compute_key_tag(257, 3, 13, &[0xBB; 64]);
        assert_ne!(tag_a, tag_b, "different keys should produce different tags");
    }

    #[test]
    fn digest_type_values() {
        assert_eq!(DigestType::Sha256.value(), 2);
        assert_eq!(DigestType::Sha384.value(), 4);
    }

    #[test]
    fn cds_key_tag_matches_compute_key_tag() {
        let public_key = vec![0xCC; 64];
        let dnskey = RecordData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: public_key.clone(),
        };
        let owner = DomainName::new("test.example.").unwrap();
        let cds = CdsRecord::from_dnskey(&owner, &dnskey, DigestType::Sha256).unwrap();
        let expected_tag = compute_key_tag(257, 3, 13, &public_key);
        match cds {
            RecordData::Cds { key_tag, .. } => {
                assert_eq!(key_tag, expected_tag);
            }
            ref other => panic!("expected CDS, got {other:?}"),
        }
    }
}
