// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::record::RecordClass;

use super::{Prerequisite, UpdateEntry, UpdateMessage};

impl UpdateMessage {
    /// The raw wire bytes of the DNS update message.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// The DNS message ID.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The request TSIG MAC, if this message was signed.
    ///
    /// Returns `None` for unsigned messages. Used by the transport layer
    /// to verify response TSIG per RFC 8945 §4.5.
    pub fn request_mac(&self) -> Option<&[u8]> {
        self.request_mac.as_ref().map(|z| z.as_slice())
    }

    /// Whether this message was signed with TSIG.
    pub fn is_signed(&self) -> bool {
        self.request_mac.is_some()
    }
}

/// Encode a complete RFC 2136 UPDATE message in DNS wire format.
pub(super) fn encode_update_message(
    id: u16,
    zone: &DomainName,
    class: RecordClass,
    prerequisites: &[Prerequisite],
    updates: &[UpdateEntry],
) -> Result<UpdateMessage, CoreError> {
    let mut wire = Vec::new();

    // --- Header (12 bytes) ---

    // ID
    wire.extend_from_slice(&id.to_be_bytes());

    // Flags: QR=0, Opcode=UPDATE(5), AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    // Byte 2: 0_0101_0_0_0 = 0x28
    wire.push(0x28);
    // Byte 3: 0_000_0000 = 0x00
    wire.push(0x00);

    // ZOCOUNT: 1 (always one zone entry)
    wire.extend_from_slice(&1u16.to_be_bytes());

    // PRCOUNT: number of prerequisite RRs (RrsetExistsWithData expands to N RRs)
    let prcount = prerequisites
        .iter()
        .try_fold(0usize, |count, prerequisite| {
            count
                .checked_add(prerequisite.wire_rr_count())
                .ok_or_else(|| invalid_record("prerequisite count overflow"))
        })?;
    wire.extend_from_slice(
        &u16::try_from(prcount)
            .map_err(|_| invalid_record("prerequisite count exceeds 65535"))?
            .to_be_bytes(),
    );

    // UPCOUNT: number of updates
    wire.extend_from_slice(
        &u16::try_from(updates.len())
            .map_err(|_| invalid_record("update count exceeds 65535"))?
            .to_be_bytes(),
    );

    // ADCOUNT: 0 (TSIG added separately by sign())
    wire.extend_from_slice(&0u16.to_be_bytes());

    // --- Zone Section ---
    // ZNAME + ZTYPE(SOA=6) + ZCLASS
    zone.write_wire(&mut wire);
    wire.extend_from_slice(&6u16.to_be_bytes()); // SOA type
    wire.extend_from_slice(&class.value().to_be_bytes());

    // --- Prerequisite Section ---
    for prereq in prerequisites {
        encode_prerequisite(prereq, class, &mut wire)?;
    }

    // --- Update Section ---
    for update in updates {
        encode_update_entry(update, &mut wire)?;
    }

    if wire.len() > usize::from(u16::MAX) {
        return Err(invalid_record("DNS update message exceeds 65535 bytes"));
    }

    Ok(UpdateMessage {
        wire_bytes: wire,
        id,
        request_mac: None,
        pre_tsig_len: None,
    })
}

/// Encode a prerequisite as a DNS RR in wire format (RFC 2136 §2.4).
///
/// `zone_class` is needed for `RrsetExistsWithData` (§2.4.2) which uses the
/// zone's class rather than ANY or NONE.
fn encode_prerequisite(
    prereq: &Prerequisite,
    zone_class: RecordClass,
    wire: &mut Vec<u8>,
) -> Result<(), CoreError> {
    match prereq {
        Prerequisite::RrsetExists { name, rtype } => {
            // NAME + TYPE + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::RrsetNotExists { name, rtype } => {
            // NAME + TYPE + CLASS=NONE(254) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::NameExists { name } => {
            // NAME + TYPE=ANY(255) + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::NameNotExists { name } => {
            // NAME + TYPE=ANY(255) + CLASS=NONE(254) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::RrsetExistsWithData {
            name,
            rtype,
            records,
        } => {
            // Each record is a separate prerequisite RR (§2.4.2):
            // NAME + TYPE + CLASS=zone_class + TTL=0 + RDLENGTH + RDATA
            for rr in records {
                name.write_wire(wire);
                wire.extend_from_slice(&rtype.value().to_be_bytes());
                wire.extend_from_slice(&zone_class.value().to_be_bytes());
                wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
                encode_rdata_with_length(&rr.rdata, wire)?;
            }
        }
    }
    Ok(())
}

/// Encode an update entry as a DNS RR in wire format (RFC 2136 §2.5).
fn encode_update_entry(entry: &UpdateEntry, wire: &mut Vec<u8>) -> Result<(), CoreError> {
    match entry {
        UpdateEntry::AddRecord(rr) => {
            // NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
            rr.name.write_wire(wire);
            wire.extend_from_slice(&rdata_type_value(&rr.rdata).to_be_bytes());
            wire.extend_from_slice(&rr.class.value().to_be_bytes());
            wire.extend_from_slice(&rr.ttl.value().to_be_bytes());
            encode_rdata_with_length(&rr.rdata, wire)?;
        }
        UpdateEntry::DeleteRrset { name, rtype } => {
            // NAME + TYPE + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        UpdateEntry::DeleteRecord(rr) => {
            // NAME + TYPE + CLASS=NONE(254) + TTL=0 + RDLENGTH + RDATA
            rr.name.write_wire(wire);
            wire.extend_from_slice(&rdata_type_value(&rr.rdata).to_be_bytes());
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            encode_rdata_with_length(&rr.rdata, wire)?;
        }
        UpdateEntry::DeleteName { name } => {
            // NAME + TYPE=ANY(255) + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
    }
    Ok(())
}

/// Get the DNS type code for a `RecordData` variant.
fn rdata_type_value(rdata: &crate::rdata::RecordData) -> u16 {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(_) => 1,
        RecordData::Aaaa(_) => 28,
        RecordData::Cname(_) => 5,
        RecordData::Ns(_) => 2,
        RecordData::Ptr(_) => 12,
        RecordData::Soa { .. } => 6,
        RecordData::Mx { .. } => 15,
        RecordData::Txt(_) => 16,
        RecordData::Srv { .. } => 33,
        RecordData::Caa { .. } => 257,
        RecordData::Dnskey { .. } => 48,
        RecordData::Rrsig { .. } => 46,
        RecordData::Nsec { .. } => 47,
        RecordData::Nsec3 { .. } => 50,
        RecordData::Ds { .. } => 43,
        RecordData::Cds { .. } => 59,
        RecordData::Cdnskey { .. } => 60,
        RecordData::Tlsa { .. } => 52,
        RecordData::Sshfp { .. } => 44,
        RecordData::Csync { .. } => 62,
        RecordData::Rp { .. } => 17,
        RecordData::Nsec3param { .. } => 51,
        RecordData::Dlv { .. } => 32769,
        RecordData::Unknown { rtype, .. } => *rtype,
    }
}

/// Encode `RecordData` in DNS wire format.
fn encode_rdata_with_length(
    rdata: &crate::rdata::RecordData,
    wire: &mut Vec<u8>,
) -> Result<(), CoreError> {
    let rdata_start = wire.len();
    wire.extend_from_slice(&0u16.to_be_bytes());
    encode_rdata(rdata, wire)?;
    let rdata_len = wire.len() - rdata_start - 2;
    let rdata_len =
        u16::try_from(rdata_len).map_err(|_| invalid_record("RDATA length exceeds 65535 bytes"))?;
    wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
    Ok(())
}

fn encode_rdata(rdata: &crate::rdata::RecordData, wire: &mut Vec<u8>) -> Result<(), CoreError> {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(addr) => {
            wire.extend_from_slice(&addr.octets());
        }
        RecordData::Aaaa(addr) => {
            wire.extend_from_slice(&addr.octets());
        }
        RecordData::Cname(name) | RecordData::Ns(name) | RecordData::Ptr(name) => {
            name.write_wire(wire);
        }
        RecordData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            mname.write_wire(wire);
            rname.write_wire(wire);
            wire.extend_from_slice(&serial.value().to_be_bytes());
            wire.extend_from_slice(&refresh.value().to_be_bytes());
            wire.extend_from_slice(&retry.value().to_be_bytes());
            wire.extend_from_slice(&expire.value().to_be_bytes());
            wire.extend_from_slice(&minimum.value().to_be_bytes());
        }
        RecordData::Mx {
            preference,
            exchange,
        } => {
            wire.extend_from_slice(&preference.to_be_bytes());
            exchange.write_wire(wire);
        }
        RecordData::Txt(strings) => {
            for s in strings {
                let bytes = s.as_bytes();
                let length = u8::try_from(bytes.len())
                    .map_err(|_| invalid_record("TXT character-string exceeds 255 bytes"))?;
                wire.push(length);
                wire.extend_from_slice(bytes);
            }
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            wire.extend_from_slice(&priority.to_be_bytes());
            wire.extend_from_slice(&weight.to_be_bytes());
            wire.extend_from_slice(&port.to_be_bytes());
            target.write_wire(wire);
        }
        RecordData::Caa { flags, tag, value } => {
            wire.push(*flags);
            let tag_bytes = tag.as_bytes();
            wire.push(
                u8::try_from(tag_bytes.len())
                    .map_err(|_| invalid_record("CAA tag exceeds 255 bytes"))?,
            );
            wire.extend_from_slice(tag_bytes);
            wire.extend_from_slice(value.as_bytes());
        }
        RecordData::Unknown { rdata, .. } => {
            wire.extend_from_slice(rdata);
        }
        RecordData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.push(*protocol);
            wire.push(*algorithm);
            wire.extend_from_slice(public_key);
        }
        RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
        | RecordData::Cds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            wire.extend_from_slice(&key_tag.to_be_bytes());
            wire.push(*algorithm);
            wire.push(*digest_type);
            wire.extend_from_slice(digest);
        }
        RecordData::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => {
            wire.extend_from_slice(&type_covered.to_be_bytes());
            wire.push(*algorithm);
            wire.push(*labels);
            wire.extend_from_slice(&original_ttl.to_be_bytes());
            wire.extend_from_slice(&signature_expiration.to_be_bytes());
            wire.extend_from_slice(&signature_inception.to_be_bytes());
            wire.extend_from_slice(&key_tag.to_be_bytes());
            signer_name.write_wire(wire);
            wire.extend_from_slice(signature);
        }
        RecordData::Nsec {
            next_domain,
            type_bitmaps,
        } => {
            next_domain.write_wire(wire);
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmaps,
        } => {
            wire.push(*hash_algorithm);
            wire.push(*flags);
            wire.extend_from_slice(&iterations.to_be_bytes());
            wire.push(
                u8::try_from(salt.len())
                    .map_err(|_| invalid_record("NSEC3 salt exceeds 255 bytes"))?,
            );
            wire.extend_from_slice(salt);
            wire.push(
                u8::try_from(next_hashed_owner.len())
                    .map_err(|_| invalid_record("NSEC3 next hashed owner exceeds 255 bytes"))?,
            );
            wire.extend_from_slice(next_hashed_owner);
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Cdnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.push(*protocol);
            wire.push(*algorithm);
            wire.extend_from_slice(public_key);
        }
        RecordData::Tlsa {
            usage,
            selector,
            matching_type,
            certificate_data,
        } => {
            wire.push(*usage);
            wire.push(*selector);
            wire.push(*matching_type);
            wire.extend_from_slice(certificate_data);
        }
        RecordData::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        } => {
            wire.push(*algorithm);
            wire.push(*fp_type);
            wire.extend_from_slice(fingerprint);
        }
        RecordData::Csync {
            soa_serial,
            flags,
            type_bitmaps,
        } => {
            wire.extend_from_slice(&soa_serial.to_be_bytes());
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Rp { mbox, txt } => {
            mbox.write_wire(wire);
            txt.write_wire(wire);
        }
        RecordData::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        } => {
            wire.push(*hash_algorithm);
            wire.push(*flags);
            wire.extend_from_slice(&iterations.to_be_bytes());
            wire.push(
                u8::try_from(salt.len())
                    .map_err(|_| invalid_record("NSEC3PARAM salt exceeds 255 bytes"))?,
            );
            wire.extend_from_slice(salt);
        }
        RecordData::Dlv {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            wire.extend_from_slice(&key_tag.to_be_bytes());
            wire.push(*algorithm);
            wire.push(*digest_type);
            wire.extend_from_slice(digest);
        }
    }
    Ok(())
}

fn invalid_record(message: impl Into<alloc::string::String>) -> CoreError {
    CoreError::InvalidRecord(message.into())
}
