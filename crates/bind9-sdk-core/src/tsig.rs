// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

/// A TSIG key for DNS message authentication (RFC 8945).
///
/// Holds HMAC key material that is automatically zeroed on drop via
/// `zeroize::Zeroizing`. Does not implement `Clone` to prevent
/// accidental key duplication. The `Debug` impl redacts key material.
pub struct TsigKey {
    name: DomainName,
    algorithm: TsigAlgorithm,
    key_material: Zeroizing<Vec<u8>>,
}

impl TsigKey {
    /// Create a new TSIG key from raw key material bytes.
    ///
    /// Returns an error if `key_material` is empty.
    pub fn new(
        name: DomainName,
        algorithm: TsigAlgorithm,
        key_material: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if key_material.is_empty() {
            return Err(CoreError::Tsig("key material must not be empty".into()));
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
    fn material(&self) -> &[u8] {
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

/// A constructed TSIG pseudo-record for DNS message authentication (RFC 8945 §4.3).
///
/// This is not a real DNS resource record — it is appended to the additional
/// section of a DNS message to provide authentication.
pub struct TsigRecord {
    /// The TSIG key name.
    pub key_name: DomainName,
    /// The algorithm used.
    pub algorithm: TsigAlgorithm,
    /// The time the message was signed (seconds since Unix epoch).
    pub time_signed: u64,
    /// Clock skew tolerance in seconds (default: 300).
    pub fudge: u16,
    /// The computed HMAC (message authentication code).
    /// Wrapped in `Zeroizing` to clear on drop.
    pub mac: Zeroizing<Vec<u8>>,
    /// The original DNS message ID.
    pub original_id: u16,
    /// The complete TSIG record in wire format, ready to append to a DNS message.
    /// Wrapped in `Zeroizing` to clear on drop.
    pub wire_bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for TsigRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigRecord")
            .field("key_name", &self.key_name)
            .field("algorithm", &self.algorithm)
            .field("time_signed", &self.time_signed)
            .field("fudge", &self.fudge)
            .field("mac", &"[REDACTED]")
            .field("original_id", &self.original_id)
            .field("wire_bytes", &"[REDACTED]")
            .finish()
    }
}

impl TsigRecord {
    /// Construct a TSIG pseudo-record for a DNS message.
    ///
    /// Per RFC 8945 §4.3.3 (request MAC generation):
    /// MAC = HMAC(key, DNS message + TSIG Variables)
    ///
    /// The `message` parameter is the complete DNS message (header + sections)
    /// WITHOUT the TSIG record. The original message ID is extracted from
    /// bytes 0..2 of the message.
    ///
    /// For response or multi-message TSIG (RFC 8945 §4.5.3), pass the prior
    /// message's MAC as `request_mac`. This prepends the prior MAC
    /// (length-prefixed) to the MAC input for chaining.
    pub fn new(key: &TsigKey, message: &[u8], timestamp: u64, request_mac: Option<&[u8]>) -> Self {
        let fudge: u16 = 300;
        let error: u16 = 0;
        let other_len: u16 = 0;

        let original_id = if message.len() >= 2 {
            u16::from_be_bytes([message[0], message[1]])
        } else {
            0
        };

        // Build TSIG Variables for MAC computation (RFC 8945 §4.3.3)
        // All names MUST be in canonical wire format (lowercase, RFC 4034 §6.2)
        let mut tsig_vars = Vec::new();

        // Key name in canonical wire format
        key.name.write_wire_canonical(&mut tsig_vars);

        // Class: ANY (255)
        tsig_vars.extend_from_slice(&255u16.to_be_bytes());

        // TTL: 0
        tsig_vars.extend_from_slice(&0u32.to_be_bytes());

        // Algorithm name in canonical wire format
        let alg_name = key.algorithm.dns_name();
        let alg_domain = DomainName::new(alg_name).expect("algorithm DNS name is always valid");
        alg_domain.write_wire_canonical(&mut tsig_vars);

        // Time signed: 48-bit (6 bytes, big-endian)
        tsig_vars.extend_from_slice(&timestamp.to_be_bytes()[2..8]);

        // Fudge: 16-bit
        tsig_vars.extend_from_slice(&fudge.to_be_bytes());

        // Error: 16-bit (0 = NOERROR)
        tsig_vars.extend_from_slice(&error.to_be_bytes());

        // Other length: 16-bit (0)
        tsig_vars.extend_from_slice(&other_len.to_be_bytes());

        // MAC input = [prior MAC (length-prefixed)] + DNS message + TSIG variables
        // Prior MAC is included for response or multi-message TSIG (RFC 8945 §4.5.3)
        let mut mac_input = Vec::with_capacity(message.len() + tsig_vars.len());
        if let Some(prior) = request_mac {
            mac_input.extend_from_slice(&(prior.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(prior);
        }
        mac_input.extend_from_slice(message);
        mac_input.extend_from_slice(&tsig_vars);

        let mac = key.sign(&mac_input);

        // Build the complete TSIG record in wire format
        // Names in canonical form per RFC 8945 §4.2
        let mut wire = Vec::new();

        // Owner name: key name in canonical wire format
        key.name.write_wire_canonical(&mut wire);

        // TYPE: TSIG (250)
        wire.extend_from_slice(&250u16.to_be_bytes());

        // CLASS: ANY (255)
        wire.extend_from_slice(&255u16.to_be_bytes());

        // TTL: 0
        wire.extend_from_slice(&0u32.to_be_bytes());

        // RDATA length (placeholder)
        let rdata_start = wire.len();
        wire.extend_from_slice(&0u16.to_be_bytes());

        // RDATA: Algorithm name (canonical)
        alg_domain.write_wire_canonical(&mut wire);

        // RDATA: Time signed (48-bit)
        wire.extend_from_slice(&timestamp.to_be_bytes()[2..8]);

        // RDATA: Fudge
        wire.extend_from_slice(&fudge.to_be_bytes());

        // RDATA: MAC size
        let mac_len = mac.len() as u16;
        wire.extend_from_slice(&mac_len.to_be_bytes());

        // RDATA: MAC
        wire.extend_from_slice(&mac);

        // RDATA: Original ID
        wire.extend_from_slice(&original_id.to_be_bytes());

        // RDATA: Error
        wire.extend_from_slice(&error.to_be_bytes());

        // RDATA: Other length
        wire.extend_from_slice(&other_len.to_be_bytes());

        // Patch RDATA length
        let rdata_len = (wire.len() - rdata_start - 2) as u16;
        wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());

        TsigRecord {
            key_name: key.name.clone(),
            algorithm: key.algorithm,
            time_signed: timestamp,
            fudge,
            mac: Zeroizing::new(mac),
            original_id,
            wire_bytes: Zeroizing::new(wire),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;
    use super::*;
    use alloc::format;

    // --- TsigAlgorithm tests ---

    #[test]
    fn algorithm_dns_name_sha256() {
        assert_eq!(TsigAlgorithm::HmacSha256.dns_name(), "hmac-sha256.");
    }

    #[test]
    fn algorithm_dns_name_sha512() {
        assert_eq!(TsigAlgorithm::HmacSha512.dns_name(), "hmac-sha512.");
    }

    #[test]
    #[allow(deprecated)]
    fn algorithm_dns_name_sha1() {
        assert_eq!(TsigAlgorithm::HmacSha1.dns_name(), "hmac-sha1.");
    }

    #[test]
    fn algorithm_key_length_sha256() {
        assert_eq!(TsigAlgorithm::HmacSha256.key_length(), 32);
    }

    #[test]
    fn algorithm_key_length_sha512() {
        assert_eq!(TsigAlgorithm::HmacSha512.key_length(), 64);
    }

    #[test]
    #[allow(deprecated)]
    fn algorithm_key_length_sha1() {
        assert_eq!(TsigAlgorithm::HmacSha1.key_length(), 20);
    }

    #[test]
    fn algorithm_display_sha256() {
        assert_eq!(format!("{}", TsigAlgorithm::HmacSha256), "hmac-sha256");
    }

    #[test]
    fn algorithm_debug() {
        assert_eq!(format!("{:?}", TsigAlgorithm::HmacSha256), "HmacSha256");
    }

    #[test]
    fn algorithm_clone_eq() {
        let a = TsigAlgorithm::HmacSha256;
        let b = a;
        assert_eq!(a, b);
    }

    // --- TsigKey tests ---

    #[test]
    fn tsig_key_new_valid() {
        let key = TsigKey::new(
            DomainName::new("tsig-key.example.com.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0u8; 32],
        );
        assert!(key.is_ok());
    }

    #[test]
    fn tsig_key_new_empty_material_rejected() {
        let key = TsigKey::new(
            DomainName::new("tsig-key.example.com.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![],
        );
        assert!(key.is_err());
    }

    #[test]
    fn tsig_key_accessors() {
        let name = DomainName::new("my-key.").unwrap();
        let key = TsigKey::new(
            name.clone(),
            TsigAlgorithm::HmacSha512,
            alloc::vec![0xAB; 64],
        )
        .unwrap();
        assert_eq!(key.name(), &name);
        assert_eq!(key.algorithm(), TsigAlgorithm::HmacSha512);
    }

    #[test]
    fn tsig_key_debug_redacts_material() {
        let key = TsigKey::new(
            DomainName::new("secret-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xFF; 32],
        )
        .unwrap();
        let debug = format!("{:?}", key);
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must redact key material: {debug}"
        );
        assert!(
            !debug.contains("255"),
            "Debug must not leak key bytes: {debug}"
        );
        assert!(
            !debug.contains("0xff"),
            "Debug must not leak key bytes: {debug}"
        );
        assert!(
            debug.contains("secret-key."),
            "Debug should include key name: {debug}"
        );
        assert!(
            debug.contains("HmacSha256"),
            "Debug should include algorithm: {debug}"
        );
    }

    // --- from_base64 tests ---

    #[test]
    fn tsig_key_from_base64_valid() {
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = TsigKey::from_base64(
            DomainName::new("b64-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            b64,
        );
        assert!(key.is_ok());
    }

    #[test]
    fn tsig_key_from_base64_with_whitespace() {
        let b64 = "AAAAAAAAAAAAAAAA\n  AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = TsigKey::from_base64(
            DomainName::new("b64-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            b64,
        );
        assert!(key.is_ok(), "from_base64 should strip whitespace");
    }

    #[test]
    fn tsig_key_from_base64_invalid() {
        let key = TsigKey::from_base64(
            DomainName::new("bad-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            "not!valid!base64!!!",
        );
        assert!(key.is_err());
    }

    #[test]
    fn tsig_key_from_base64_empty() {
        let key = TsigKey::from_base64(
            DomainName::new("empty-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            "",
        );
        assert!(key.is_err());
    }

    #[test]
    fn tsig_key_from_base64_known_value() {
        let key = TsigKey::from_base64(
            DomainName::new("known-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            "aGVsbG8gd29ybGQ=",
        )
        .unwrap();
        assert_eq!(key.material(), b"hello world");
    }

    // --- generate tests (std-gated) ---

    #[cfg(feature = "std")]
    #[test]
    fn tsig_key_generate_sha256() {
        let key = TsigKey::generate(
            DomainName::new("gen-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
        )
        .unwrap();
        assert_eq!(key.algorithm(), TsigAlgorithm::HmacSha256);
        assert_eq!(key.material().len(), 32);
    }

    #[cfg(feature = "std")]
    #[test]
    fn tsig_key_generate_sha512() {
        let key = TsigKey::generate(
            DomainName::new("gen-key.").unwrap(),
            TsigAlgorithm::HmacSha512,
        )
        .unwrap();
        assert_eq!(key.material().len(), 64);
    }

    #[cfg(feature = "std")]
    #[test]
    fn tsig_key_generate_unique() {
        let key1 =
            TsigKey::generate(DomainName::new("k1.").unwrap(), TsigAlgorithm::HmacSha256).unwrap();
        let key2 =
            TsigKey::generate(DomainName::new("k2.").unwrap(), TsigAlgorithm::HmacSha256).unwrap();
        assert_ne!(key1.material(), key2.material());
    }

    // --- sign/verify tests ---

    #[test]
    fn sign_produces_correct_length_sha256() {
        let key = TsigKey::new(
            DomainName::new("sign-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xAA; 32],
        )
        .unwrap();
        let mac = key.sign(b"test message");
        assert_eq!(mac.len(), 32, "HMAC-SHA256 must produce 32-byte MAC");
    }

    #[test]
    fn sign_produces_correct_length_sha512() {
        let key = TsigKey::new(
            DomainName::new("sign-key.").unwrap(),
            TsigAlgorithm::HmacSha512,
            alloc::vec![0xBB; 64],
        )
        .unwrap();
        let mac = key.sign(b"test message");
        assert_eq!(mac.len(), 64, "HMAC-SHA512 must produce 64-byte MAC");
    }

    #[test]
    #[allow(deprecated)]
    fn sign_produces_correct_length_sha1() {
        let key = TsigKey::new(
            DomainName::new("sign-key.").unwrap(),
            TsigAlgorithm::HmacSha1,
            alloc::vec![0xCC; 20],
        )
        .unwrap();
        let mac = key.sign(b"test message");
        assert_eq!(mac.len(), 20, "HMAC-SHA1 must produce 20-byte MAC");
    }

    #[test]
    fn verify_valid_signature() {
        let key = TsigKey::new(
            DomainName::new("verify-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x42; 32],
        )
        .unwrap();
        let message = b"authenticate this message";
        let mac = key.sign(message);
        assert!(key.verify(message, &mac).is_ok());
    }

    #[test]
    fn verify_wrong_mac_rejected() {
        let key = TsigKey::new(
            DomainName::new("verify-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x42; 32],
        )
        .unwrap();
        let message = b"authenticate this message";
        let bad_mac = alloc::vec![0x00; 32];
        assert!(key.verify(message, &bad_mac).is_err());
    }

    #[test]
    fn verify_wrong_message_rejected() {
        let key = TsigKey::new(
            DomainName::new("verify-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x42; 32],
        )
        .unwrap();
        let mac = key.sign(b"original message");
        assert!(key.verify(b"tampered message", &mac).is_err());
    }

    #[test]
    fn verify_truncated_mac_rejected() {
        let key = TsigKey::new(
            DomainName::new("verify-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x42; 32],
        )
        .unwrap();
        let mac = key.sign(b"some message");
        let truncated = &mac[..16];
        assert!(key.verify(b"some message", truncated).is_err());
    }

    #[test]
    fn sign_deterministic_same_key_same_message() {
        let key = TsigKey::new(
            DomainName::new("det-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x01; 32],
        )
        .unwrap();
        let mac1 = key.sign(b"deterministic");
        let mac2 = key.sign(b"deterministic");
        assert_eq!(mac1, mac2, "Same key + same message must produce same MAC");
    }

    #[test]
    fn sign_different_keys_different_macs() {
        let key1 = TsigKey::new(
            DomainName::new("k1.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x01; 32],
        )
        .unwrap();
        let key2 = TsigKey::new(
            DomainName::new("k2.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x02; 32],
        )
        .unwrap();
        let mac1 = key1.sign(b"same message");
        let mac2 = key2.sign(b"same message");
        assert_ne!(mac1, mac2);
    }

    /// RFC 4231 Test Case 1 for HMAC-SHA256
    #[test]
    fn sign_rfc_test_vector_sha256() {
        let key = TsigKey::new(
            DomainName::new("test.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0x0b; 20],
        )
        .unwrap();
        let mac = key.sign(b"Hi There");
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(
            mac.as_slice(),
            &expected,
            "HMAC-SHA256 must match RFC 4231 test vector 1"
        );
    }

    // --- TsigRecord tests ---

    #[test]
    fn tsig_record_new_produces_valid_wire() {
        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xAA; 32],
        )
        .unwrap();
        let message = alloc::vec![0x00; 12];
        let timestamp = 1710000000u64;

        let record = TsigRecord::new(&key, &message, timestamp, None);

        assert!(!record.wire_bytes.is_empty());
        assert!(record.key_name == DomainName::new("test-key.").unwrap());
        assert_eq!(record.algorithm, TsigAlgorithm::HmacSha256);
        assert_eq!(record.mac.len(), 32);
        assert_eq!(record.time_signed, timestamp);
        assert_eq!(record.fudge, 300);
    }

    #[test]
    fn tsig_record_different_timestamps_different_macs() {
        let key = TsigKey::new(
            DomainName::new("ts-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xBB; 32],
        )
        .unwrap();
        let message = alloc::vec![0x00; 12];

        let r1 = TsigRecord::new(&key, &message, 1000, None);
        let r2 = TsigRecord::new(&key, &message, 2000, None);

        assert_ne!(
            r1.mac, r2.mac,
            "Different timestamps must produce different MACs"
        );
    }

    #[test]
    fn tsig_record_wire_bytes_contains_all_fields() {
        let key = TsigKey::new(
            DomainName::new("k.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xCC; 32],
        )
        .unwrap();
        let message =
            alloc::vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let record = TsigRecord::new(&key, &message, 1710000000, None);

        let wire = &record.wire_bytes;
        assert!(
            wire.len() > 20,
            "Wire bytes too short: {} bytes",
            wire.len()
        );
    }

    #[test]
    fn tsig_record_canonical_key_name_produces_same_mac() {
        // RFC 8945 §4.3.3: key names are canonicalized to lowercase for MAC.
        // Mixed-case and lowercase key names with identical material must
        // produce identical MACs for the same message and timestamp.
        let material = alloc::vec![0xDD; 32];
        let key_upper = TsigKey::new(
            DomainName::new("My-Key.Example.COM.").unwrap(),
            TsigAlgorithm::HmacSha256,
            material.clone(),
        )
        .unwrap();
        let key_lower = TsigKey::new(
            DomainName::new("my-key.example.com.").unwrap(),
            TsigAlgorithm::HmacSha256,
            material,
        )
        .unwrap();
        let message = alloc::vec![0x00; 12];
        let ts = 1710000000u64;

        let r1 = TsigRecord::new(&key_upper, &message, ts, None);
        let r2 = TsigRecord::new(&key_lower, &message, ts, None);

        assert_eq!(
            r1.mac, r2.mac,
            "Canonical (lowercase) key names must produce identical MACs"
        );
    }

    #[test]
    fn tsig_record_debug_redacts_mac() {
        let key = TsigKey::new(
            DomainName::new("dbg-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xEE; 32],
        )
        .unwrap();
        let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
        let debug = format!("{:?}", record);
        assert!(
            debug.contains("[REDACTED]"),
            "Debug must redact mac: {debug}"
        );
        assert!(
            !debug.contains("238"),
            "Debug must not leak mac bytes: {debug}"
        );
    }

    #[test]
    fn tsig_record_with_request_mac_differs() {
        let key = TsigKey::new(
            DomainName::new("chain-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xBB; 32],
        )
        .unwrap();
        let msg = alloc::vec![0u8; 12];
        let ts = 1710000000u64;

        let r1 = TsigRecord::new(&key, &msg, ts, None);
        let prior_mac = alloc::vec![0xCC; 32];
        let r2 = TsigRecord::new(&key, &msg, ts, Some(&prior_mac));

        assert_ne!(
            &*r1.mac, &*r2.mac,
            "Including request_mac must change the output MAC"
        );
    }

    // --- Proptests ---

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn sign_verify_roundtrip(
                key_bytes in proptest::collection::vec(any::<u8>(), 1..=64),
                message in proptest::collection::vec(any::<u8>(), 0..=512),
            ) {
                let key = TsigKey::new(
                    DomainName::new("prop-key.").unwrap(),
                    TsigAlgorithm::HmacSha256,
                    key_bytes,
                ).unwrap();
                let mac = key.sign(&message);
                prop_assert!(key.verify(&message, &mac).is_ok());
            }

            #[test]
            fn sign_verify_different_message_fails(
                key_bytes in proptest::collection::vec(any::<u8>(), 16..=32),
                msg1 in proptest::collection::vec(any::<u8>(), 1..=256),
                msg2 in proptest::collection::vec(any::<u8>(), 1..=256),
            ) {
                prop_assume!(msg1 != msg2);
                let key = TsigKey::new(
                    DomainName::new("prop-key.").unwrap(),
                    TsigAlgorithm::HmacSha256,
                    key_bytes,
                ).unwrap();
                let mac = key.sign(&msg1);
                prop_assert!(key.verify(&msg2, &mac).is_err());
            }
        }
    }
}
