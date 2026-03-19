// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use crate::domain::DomainName;
use crate::error::CoreError;

use super::TsigAlgorithm;
use super::key::TsigKey;
use super::wire::read_wire_name;

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
    /// TSIG error code (0 = NOERROR, 18 = BADTIME).
    pub error: u16,
    /// Additional data (used for BADTIME: server's current time as 48-bit).
    pub other_data: Vec<u8>,
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
            .field("error", &self.error)
            .field("other_data_len", &self.other_data.len())
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
        // Wrapped in Zeroizing to clear HMAC input (contains key-derived data) on drop
        let mut mac_input = Zeroizing::new(Vec::with_capacity(message.len() + tsig_vars.len()));
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
            error: 0,
            other_data: Vec::new(),
            wire_bytes: Zeroizing::new(wire),
        }
    }

    /// Parse a TSIG pseudo-record from wire format bytes.
    ///
    /// The input should be the complete TSIG record starting from the owner name
    /// (key name). Returns `Err` if the wire format is invalid or truncated.
    pub fn parse_from_wire(wire: &[u8]) -> Result<Self, CoreError> {
        let mut pos = 0;

        // Owner name (key name) in wire format
        let key_name_str = read_wire_name(wire, &mut pos)?;
        let key_name = DomainName::new(&key_name_str)
            .map_err(|e| CoreError::Tsig(alloc::format!("invalid TSIG key name: {e}")))?;

        // TYPE (must be 250 = TSIG)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG type".into()));
        }
        let rtype = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;
        if rtype != 250 {
            return Err(CoreError::Tsig(alloc::format!(
                "expected TSIG type 250, got {rtype}"
            )));
        }

        // CLASS (must be 255 = ANY)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG class".into()));
        }
        let rclass = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;
        if rclass != 255 {
            return Err(CoreError::Tsig(alloc::format!(
                "expected TSIG class ANY (255), got {rclass}"
            )));
        }

        // TTL (must be 0 per RFC 8945 §4.2)
        if pos + 4 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG TTL".into()));
        }
        let ttl = u32::from_be_bytes([wire[pos], wire[pos + 1], wire[pos + 2], wire[pos + 3]]);
        if ttl != 0 {
            return Err(CoreError::Tsig(alloc::format!(
                "TSIG TTL must be 0, got {ttl}"
            )));
        }
        pos += 4;

        // RDLENGTH
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG RDLENGTH".into()));
        }
        let rdlength = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlength > wire.len() {
            return Err(CoreError::Tsig("TSIG RDATA truncated".into()));
        }

        // RDATA: Algorithm name
        let alg_name_str = read_wire_name(wire, &mut pos)?;
        let algorithm = match alg_name_str.to_lowercase().as_str() {
            "hmac-sha256." => TsigAlgorithm::HmacSha256,
            "hmac-sha512." => TsigAlgorithm::HmacSha512,
            #[allow(deprecated)]
            "hmac-sha1." => TsigAlgorithm::HmacSha1,
            other => {
                return Err(CoreError::Tsig(alloc::format!(
                    "unsupported TSIG algorithm: {other}"
                )));
            }
        };

        // RDATA: Time signed (48-bit, 6 bytes)
        if pos + 6 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG time_signed".into()));
        }
        let mut time_bytes = [0u8; 8];
        time_bytes[2..8].copy_from_slice(&wire[pos..pos + 6]);
        let time_signed = u64::from_be_bytes(time_bytes);
        pos += 6;

        // RDATA: Fudge (16-bit)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG fudge".into()));
        }
        let fudge = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;

        // RDATA: MAC size (16-bit)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG MAC size".into()));
        }
        let mac_size = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
        pos += 2;

        // RDATA: MAC
        if pos + mac_size > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG MAC".into()));
        }
        let mac = wire[pos..pos + mac_size].to_vec();
        pos += mac_size;

        // RDATA: Original ID (16-bit)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG original ID".into()));
        }
        let original_id = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;

        // RDATA: Error (16-bit)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG error".into()));
        }
        let error = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;

        // RDATA: Other length (16-bit)
        if pos + 2 > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG other_len".into()));
        }
        let other_len = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
        pos += 2;

        // RDATA: Other data
        if pos + other_len > wire.len() {
            return Err(CoreError::Tsig("truncated TSIG other_data".into()));
        }
        let other_data = wire[pos..pos + other_len].to_vec();

        Ok(TsigRecord {
            key_name,
            algorithm,
            time_signed,
            fudge,
            mac: Zeroizing::new(mac),
            original_id,
            error,
            other_data,
            wire_bytes: Zeroizing::new(wire.to_vec()),
        })
    }

    /// Verify that the TSIG timestamp is within the fudge window of `now`.
    ///
    /// Per RFC 8945 §5.2.3, if |time_signed - now| > fudge, reject with BADTIME.
    pub fn verify_time(&self, now: u64) -> Result<(), CoreError> {
        let diff = now.abs_diff(self.time_signed);
        if diff > self.fudge as u64 {
            return Err(CoreError::Tsig(alloc::format!(
                "TSIG time outside fudge window: signed={}, now={}, fudge={}",
                self.time_signed,
                now,
                self.fudge
            )));
        }
        Ok(())
    }

    /// Verify a TSIG-signed DNS response.
    ///
    /// Per RFC 8945 §4.5: reconstruct MAC input from request MAC + response
    /// message + TSIG variables, then verify. Also checks fudge window.
    ///
    /// `response_message` is the DNS response WITHOUT the TSIG record.
    /// `request_mac` is the MAC from the original request's TSIG.
    pub fn verify_response(
        key: &TsigKey,
        response_message: &[u8],
        response_tsig: &TsigRecord,
        request_mac: &[u8],
        now: u64,
    ) -> Result<(), CoreError> {
        // Check fudge window
        response_tsig.verify_time(now)?;

        // Reconstruct TSIG variables (same layout as in new())
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

        // Time signed: 48-bit
        tsig_vars.extend_from_slice(&response_tsig.time_signed.to_be_bytes()[2..8]);

        // Fudge: 16-bit
        tsig_vars.extend_from_slice(&response_tsig.fudge.to_be_bytes());

        // Error: 16-bit (from parsed TSIG)
        tsig_vars.extend_from_slice(&response_tsig.error.to_be_bytes());

        // Other length + data (from parsed TSIG)
        tsig_vars.extend_from_slice(&(response_tsig.other_data.len() as u16).to_be_bytes());
        tsig_vars.extend_from_slice(&response_tsig.other_data);

        // Build MAC input: request_mac (length-prefixed) + response + tsig_vars
        // Wrapped in Zeroizing to clear HMAC input on drop
        let mut mac_input = Zeroizing::new(Vec::with_capacity(
            2 + request_mac.len() + response_message.len() + tsig_vars.len(),
        ));
        mac_input.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(request_mac);
        mac_input.extend_from_slice(response_message);
        mac_input.extend_from_slice(&tsig_vars);

        key.verify(&mac_input, &response_tsig.mac)
    }
}
