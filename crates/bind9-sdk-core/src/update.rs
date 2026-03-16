// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::protocol::{Rcode, RecordType};
use crate::record::{RecordClass, ResourceRecord};

/// A prerequisite condition for an RFC 2136 dynamic update (§2.4).
///
/// Prerequisites are checked by the server before any updates are applied.
/// If any prerequisite fails, the entire update is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// An RRset with this name and type must exist (any data).
    RrsetExists { name: DomainName, rtype: RecordType },
    /// An RRset with this name and type must NOT exist.
    RrsetNotExists { name: DomainName, rtype: RecordType },
    /// At least one RRset with this name must exist (any type).
    NameExists { name: DomainName },
    /// No RRsets with this name must exist (name is not in use).
    NameNotExists { name: DomainName },
    /// An RRset with this name, type, and specific data must exist (§2.4.2).
    RrsetExistsWithData {
        name: DomainName,
        rtype: RecordType,
        records: Vec<ResourceRecord>,
    },
}

impl Prerequisite {
    /// Number of wire-level RRs this prerequisite expands to.
    ///
    /// Most variants produce exactly one RR. `RrsetExistsWithData` produces
    /// one RR per record in the set (RFC 2136 §2.4.2).
    fn wire_rr_count(&self) -> usize {
        match self {
            Self::RrsetExistsWithData { records, .. } => records.len(),
            _ => 1,
        }
    }
}

/// An update operation for an RFC 2136 dynamic update (§2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateEntry {
    /// Add a resource record to the zone.
    AddRecord(ResourceRecord),
    /// Delete all records of a given type at a name.
    DeleteRrset { name: DomainName, rtype: RecordType },
    /// Delete a specific resource record.
    DeleteRecord(ResourceRecord),
    /// Delete all records at a name (any type).
    DeleteName { name: DomainName },
}

/// Typestate: the update message has not been signed.
pub struct Unsigned;

/// Typestate: the update message has been signed with TSIG.
pub struct Signed {
    message: UpdateMessage,
}

/// Builder for constructing RFC 2136 dynamic update messages.
///
/// Uses the typestate pattern to enforce signing discipline at compile time:
/// - `UpdateBuilder<Unsigned>`: can add prerequisites and updates, can sign or build unsigned
/// - `UpdateBuilder<Signed>`: can only call `build()` to extract the signed message
///
/// All builder methods consume `self` and return a new builder (move semantics).
pub struct UpdateBuilder<State = Unsigned> {
    id: u16,
    zone: DomainName,
    class: RecordClass,
    prerequisites: Vec<Prerequisite>,
    updates: Vec<UpdateEntry>,
    state: State,
}

impl UpdateBuilder<Unsigned> {
    /// Create a new update builder for the given zone.
    ///
    /// When the `std` feature is enabled, the message ID is randomly generated.
    /// In `no_std`/WASM, the ID defaults to 0; use [`with_id`](Self::with_id) instead.
    #[cfg(feature = "std")]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        let mut id_bytes = [0u8; 2];
        let _ = getrandom::fill(&mut id_bytes);
        let id = u16::from_be_bytes(id_bytes);
        Self::with_id(id, zone, class)
    }

    /// Create a new update builder for the given zone (`no_std` version).
    #[cfg(not(feature = "std"))]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        Self::with_id(0, zone, class)
    }

    /// Create a new update builder with an explicit message ID.
    ///
    /// Use this in `no_std`/WASM contexts or when a specific ID is needed for testing.
    pub fn with_id(id: u16, zone: DomainName, class: RecordClass) -> Self {
        Self {
            id,
            zone,
            class,
            prerequisites: Vec::new(),
            updates: Vec::new(),
            state: Unsigned,
        }
    }

    /// Require that an RRset with the given name and type exists (RFC 2136 §2.4.1).
    pub fn require_rrset_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that an RRset with the given name and type does NOT exist (RFC 2136 §2.4.2).
    pub fn require_rrset_not_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetNotExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that at least one record with the given name exists (RFC 2136 §2.4.4).
    pub fn require_name_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites
            .push(Prerequisite::NameExists { name: name.clone() });
        self
    }

    /// Require that no records with the given name exist (RFC 2136 §2.4.5).
    pub fn require_name_not_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites
            .push(Prerequisite::NameNotExists { name: name.clone() });
        self
    }

    /// Require that an RRset with the given name, type, and specific data
    /// exists (RFC 2136 §2.4.2).
    ///
    /// Each record in `records` becomes a separate prerequisite RR in the wire
    /// format. The CLASS in each wire RR is set to the zone class (not ANY).
    pub fn require_rrset_exists_with_data(
        mut self,
        name: &DomainName,
        rtype: RecordType,
        records: Vec<ResourceRecord>,
    ) -> Self {
        self.prerequisites.push(Prerequisite::RrsetExistsWithData {
            name: name.clone(),
            rtype,
            records,
        });
        self
    }

    /// Add a resource record to the zone (RFC 2136 §2.5.1).
    pub fn add_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::AddRecord(record));
        self
    }

    /// Delete all records of a given type at a name (RFC 2136 §2.5.2).
    pub fn delete_rrset(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.updates.push(UpdateEntry::DeleteRrset {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Delete a specific resource record (RFC 2136 §2.5.4).
    pub fn delete_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::DeleteRecord(record));
        self
    }

    /// Delete all records at a name (RFC 2136 §2.5.3).
    pub fn delete_name(mut self, name: &DomainName) -> Self {
        self.updates
            .push(UpdateEntry::DeleteName { name: name.clone() });
        self
    }

    /// Build the update message without TSIG signing.
    ///
    /// Use for testing or on trusted networks.
    pub fn build_unsigned(self) -> UpdateMessage {
        encode_update_message(
            self.id,
            &self.zone,
            self.class,
            &self.prerequisites,
            &self.updates,
        )
    }

    /// Sign the update with a TSIG key at the given timestamp.
    ///
    /// The `timestamp` is seconds since the Unix epoch, used in the TSIG
    /// record's Time Signed field. Servers reject timestamps outside their
    /// fudge window (RFC 8945 §5.2.3), so this must be the current time.
    ///
    /// Use [`sign_now`](Self::sign_now) (requires `std` feature) for automatic
    /// timestamping, or provide a timestamp from an external clock in `no_std`.
    pub fn sign(self, key: &crate::tsig::TsigKey, timestamp: u64) -> UpdateBuilder<Signed> {
        self.sign_inner(key, timestamp)
    }

    /// Sign the update with a TSIG key using the current system time.
    ///
    /// Convenience wrapper around [`sign`](Self::sign) that reads
    /// `SystemTime::now()` for the TSIG timestamp.
    #[cfg(feature = "std")]
    pub fn sign_now(self, key: &crate::tsig::TsigKey) -> UpdateBuilder<Signed> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_secs();
        self.sign_inner(key, timestamp)
    }

    fn sign_inner(self, key: &crate::tsig::TsigKey, timestamp: u64) -> UpdateBuilder<Signed> {
        let unsigned = encode_update_message(
            self.id,
            &self.zone,
            self.class,
            &self.prerequisites,
            &self.updates,
        );

        let tsig = crate::tsig::TsigRecord::new(key, unsigned.as_bytes(), timestamp, None);

        let pre_tsig_len = unsigned.wire_bytes.len();
        let request_mac = tsig.mac.to_vec();

        let mut wire = unsigned.wire_bytes;

        // Increment ARCOUNT in DNS header (bytes 10..12)
        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        wire[10..12].copy_from_slice(&(arcount + 1).to_be_bytes());

        // Append TSIG record
        wire.extend_from_slice(&tsig.wire_bytes);

        UpdateBuilder {
            id: self.id,
            zone: self.zone,
            class: self.class,
            prerequisites: self.prerequisites,
            updates: self.updates,
            state: Signed {
                message: UpdateMessage {
                    wire_bytes: wire,
                    id: self.id,
                    request_mac: Some(request_mac),
                    pre_tsig_len: Some(pre_tsig_len),
                },
            },
        }
    }
}

impl UpdateBuilder<Signed> {
    /// Build the signed update message.
    pub fn build(self) -> UpdateMessage {
        self.state.message
    }
}

/// A constructed RFC 2136 dynamic update message, ready to send on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
    /// The request TSIG MAC, if the message was signed.
    /// Used by the net crate for response TSIG verification (RFC 8945 §4.5).
    pub(crate) request_mac: Option<Vec<u8>>,
    /// Length of the message before the TSIG record was appended.
    /// The response verifier needs the pre-TSIG bytes to reconstruct the MAC input.
    pub(crate) pre_tsig_len: Option<usize>,
}

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
        self.request_mac.as_deref()
    }

    /// Whether this message was signed with TSIG.
    pub fn is_signed(&self) -> bool {
        self.request_mac.is_some()
    }
}

/// Result of sending an RFC 2136 update to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    pub rcode: Rcode,
    pub id: u16,
}

/// Encode a complete RFC 2136 UPDATE message in DNS wire format.
fn encode_update_message(
    id: u16,
    zone: &DomainName,
    class: RecordClass,
    prerequisites: &[Prerequisite],
    updates: &[UpdateEntry],
) -> UpdateMessage {
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
    let prcount: usize = prerequisites.iter().map(Prerequisite::wire_rr_count).sum();
    wire.extend_from_slice(&(prcount as u16).to_be_bytes());

    // UPCOUNT: number of updates
    wire.extend_from_slice(&(updates.len() as u16).to_be_bytes());

    // ADCOUNT: 0 (TSIG added separately by sign())
    wire.extend_from_slice(&0u16.to_be_bytes());

    // --- Zone Section ---
    // ZNAME + ZTYPE(SOA=6) + ZCLASS
    zone.write_wire(&mut wire);
    wire.extend_from_slice(&6u16.to_be_bytes()); // SOA type
    wire.extend_from_slice(&class.value().to_be_bytes());

    // --- Prerequisite Section ---
    for prereq in prerequisites {
        encode_prerequisite(prereq, class, &mut wire);
    }

    // --- Update Section ---
    for update in updates {
        encode_update_entry(update, &mut wire);
    }

    UpdateMessage {
        wire_bytes: wire,
        id,
        request_mac: None,
        pre_tsig_len: None,
    }
}

/// Encode a prerequisite as a DNS RR in wire format (RFC 2136 §2.4).
///
/// `zone_class` is needed for `RrsetExistsWithData` (§2.4.2) which uses the
/// zone's class rather than ANY or NONE.
fn encode_prerequisite(prereq: &Prerequisite, zone_class: RecordClass, wire: &mut Vec<u8>) {
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
                let rdata_start = wire.len();
                wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
                encode_rdata(&rr.rdata, wire);
                let rdata_len = (wire.len() - rdata_start - 2) as u16;
                wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
            }
        }
    }
}

/// Encode an update entry as a DNS RR in wire format (RFC 2136 §2.5).
fn encode_update_entry(entry: &UpdateEntry, wire: &mut Vec<u8>) {
    match entry {
        UpdateEntry::AddRecord(rr) => {
            // NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
            rr.name.write_wire(wire);
            wire.extend_from_slice(&rdata_type_value(&rr.rdata).to_be_bytes());
            wire.extend_from_slice(&rr.class.value().to_be_bytes());
            wire.extend_from_slice(&rr.ttl.value().to_be_bytes());
            let rdata_start = wire.len();
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
            encode_rdata(&rr.rdata, wire);
            let rdata_len = (wire.len() - rdata_start - 2) as u16;
            wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
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
            let rdata_start = wire.len();
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
            encode_rdata(&rr.rdata, wire);
            let rdata_len = (wire.len() - rdata_start - 2) as u16;
            wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
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
        RecordData::Unknown { rtype, .. } => *rtype,
    }
}

/// Encode `RecordData` in DNS wire format.
fn encode_rdata(rdata: &crate::rdata::RecordData, wire: &mut Vec<u8>) {
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
                wire.push(bytes.len().min(255) as u8);
                wire.extend_from_slice(&bytes[..bytes.len().min(255)]);
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
            wire.push(tag_bytes.len() as u8);
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
            wire.push(salt.len() as u8);
            wire.extend_from_slice(salt);
            wire.push(next_hashed_owner.len() as u8);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_message_accessors() {
        let msg = UpdateMessage {
            wire_bytes: alloc::vec![0x00, 0x01, 0x28, 0x00],
            id: 0x0001,
            request_mac: None,
            pre_tsig_len: None,
        };
        assert_eq!(msg.as_bytes(), &[0x00, 0x01, 0x28, 0x00]);
        assert_eq!(msg.id(), 0x0001);
        assert!(!msg.is_signed());
        assert!(msg.request_mac().is_none());
    }

    #[test]
    fn update_result_success() {
        let result = UpdateResult {
            rcode: Rcode::NoError,
            id: 42,
        };
        assert!(result.rcode.is_success());
    }

    use crate::domain::DomainName;
    use crate::protocol::RecordType;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, Ttl};

    #[test]
    fn prerequisite_rrset_exists() {
        let prereq = Prerequisite::RrsetExists {
            name: DomainName::new("example.com.").unwrap(),
            rtype: RecordType::A,
        };
        assert!(matches!(prereq, Prerequisite::RrsetExists { .. }));
    }

    #[test]
    fn prerequisite_name_not_exists() {
        let prereq = Prerequisite::NameNotExists {
            name: DomainName::new("missing.example.com.").unwrap(),
        };
        assert!(matches!(prereq, Prerequisite::NameNotExists { .. }));
    }

    #[test]
    fn update_entry_add_record() {
        let rr = ResourceRecord {
            name: DomainName::new("new.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let entry = UpdateEntry::AddRecord(rr);
        assert!(matches!(entry, UpdateEntry::AddRecord(_)));
    }

    #[test]
    fn update_entry_delete_rrset() {
        let entry = UpdateEntry::DeleteRrset {
            name: DomainName::new("old.example.com.").unwrap(),
            rtype: RecordType::A,
        };
        assert!(matches!(entry, UpdateEntry::DeleteRrset { .. }));
    }

    #[test]
    fn update_entry_delete_name() {
        let entry = UpdateEntry::DeleteName {
            name: DomainName::new("gone.example.com.").unwrap(),
        };
        assert!(matches!(entry, UpdateEntry::DeleteName { .. }));
    }

    // --- UpdateBuilder tests ---

    #[test]
    fn builder_new_creates_unsigned() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::new(zone, RecordClass::IN);
        let _msg = builder.build_unsigned();
    }

    #[test]
    fn builder_with_id() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN);
        let msg = builder.build_unsigned();
        assert_eq!(msg.id(), 0x1234);
    }

    #[test]
    fn builder_add_prerequisite() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
            .require_name_not_exists(&DomainName::new("new.example.com.").unwrap());
        let _msg = builder.build_unsigned();
    }

    #[test]
    fn builder_add_records() {
        let zone = DomainName::new("example.com.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("www.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN).add_record(rr);
        let _msg = builder.build_unsigned();
    }

    #[test]
    fn builder_delete_operations() {
        let zone = DomainName::new("example.com.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("old.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(0).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
        };
        let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .delete_rrset(
                &DomainName::new("del.example.com.").unwrap(),
                RecordType::Aaaa,
            )
            .delete_record(rr)
            .delete_name(&DomainName::new("gone.example.com.").unwrap());
        let _msg = builder.build_unsigned();
    }

    #[test]
    fn builder_chaining() {
        let zone = DomainName::new("example.com.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("www.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let msg = UpdateBuilder::with_id(42, zone, RecordClass::IN)
            .require_name_exists(&DomainName::new("www.example.com.").unwrap())
            .add_record(rr)
            .delete_rrset(&DomainName::new("old.example.com.").unwrap(), RecordType::A)
            .build_unsigned();
        assert_eq!(msg.id(), 42);
        assert!(!msg.as_bytes().is_empty());
    }

    // --- Wire format tests ---

    #[test]
    fn wire_header_opcode_is_update() {
        let zone = DomainName::new("example.com.").unwrap();
        let msg = UpdateBuilder::with_id(0xABCD, zone, RecordClass::IN).build_unsigned();
        let bytes = msg.as_bytes();

        // Bytes 0-1: ID
        assert_eq!(bytes[0], 0xAB);
        assert_eq!(bytes[1], 0xCD);

        // Byte 2: QR(0) + Opcode(5=UPDATE) + AA(0) + TC(0) + RD(0) = 0x28
        assert_eq!(bytes[2], 0x28);

        // Byte 3: RA(0) + Z(0) + RCODE(0) = 0x00
        assert_eq!(bytes[3], 0x00);
    }

    #[test]
    fn wire_section_counts() {
        let zone = DomainName::new("example.com.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("www.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
            .add_record(rr)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // ZOCOUNT (bytes 4-5): 1
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1);

        // PRCOUNT (bytes 6-7): 1
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);

        // UPCOUNT (bytes 8-9): 1
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 1);

        // ADCOUNT (bytes 10-11): 0
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 0);
    }

    #[test]
    fn wire_rrset_exists_with_data_prcount() {
        let zone = DomainName::new("example.com.").unwrap();
        let name = DomainName::new("www.example.com.").unwrap();
        let rr1 = ResourceRecord {
            name: name.clone(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let rr2 = ResourceRecord {
            name: name.clone(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
        };
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr1, rr2])
            .build_unsigned();
        let bytes = msg.as_bytes();

        // PRCOUNT should be 2 (one RR per record in the RRset)
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 2);
    }

    #[test]
    fn wire_rrset_exists_with_data_encoding() {
        let zone = DomainName::new("example.com.").unwrap();
        let name = DomainName::new("www.example.com.").unwrap();
        let rr = ResourceRecord {
            name: name.clone(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr])
            .build_unsigned();
        let bytes = msg.as_bytes();

        // After header (12) + zone section (13 name + 2 type + 2 class = 17), prerequisite starts at 29
        let prereq_start = 29;

        // Name: \x03www\x07example\x03com\x00 = 17 bytes
        assert_eq!(bytes[prereq_start], 3); // "www" label
        let after_name = prereq_start + 17;

        // TYPE: A (1)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
            1
        );
        // CLASS: IN (1) — zone class, NOT ANY
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
            1
        );
        // TTL: 0
        assert_eq!(
            u32::from_be_bytes([
                bytes[after_name + 4],
                bytes[after_name + 5],
                bytes[after_name + 6],
                bytes[after_name + 7]
            ]),
            0
        );
        // RDLENGTH: 4 (IPv4 address)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
            4
        );
        // RDATA: 10.0.0.1
        assert_eq!(&bytes[after_name + 10..after_name + 14], &[10, 0, 0, 1]);
    }

    #[test]
    fn wire_rrset_exists_with_data_mixed_prerequisites() {
        // Mix RrsetExistsWithData (2 records) + RrsetExists (1 RR) = PRCOUNT 3
        let zone = DomainName::new("example.com.").unwrap();
        let name = DomainName::new("www.example.com.").unwrap();
        let rr1 = ResourceRecord {
            name: name.clone(),
            class: RecordClass::IN,
            ttl: Ttl::new(0).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let rr2 = ResourceRecord {
            name: name.clone(),
            class: RecordClass::IN,
            ttl: Ttl::new(0).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
        };
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr1, rr2])
            .require_rrset_exists(&name, RecordType::Aaaa)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // PRCOUNT: 2 (from RrsetExistsWithData) + 1 (from RrsetExists) = 3
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 3);
    }

    #[test]
    fn wire_zone_section_present() {
        let zone = DomainName::new("example.com.").unwrap();
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN).build_unsigned();
        let bytes = msg.as_bytes();

        // After 12-byte header, zone section:
        // Name: \x07example\x03com\x00 (13 bytes)
        assert_eq!(bytes[12], 7); // label length "example"
        assert_eq!(&bytes[13..20], b"example");
        assert_eq!(bytes[20], 3); // label length "com"
        assert_eq!(&bytes[21..24], b"com");
        assert_eq!(bytes[24], 0); // root label

        // TYPE: SOA (6)
        assert_eq!(u16::from_be_bytes([bytes[25], bytes[26]]), 6);

        // CLASS: IN (1)
        assert_eq!(u16::from_be_bytes([bytes[27], bytes[28]]), 1);
    }

    #[test]
    fn wire_empty_update_just_header_and_zone() {
        let zone = DomainName::new("t.").unwrap();
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN).build_unsigned();
        let bytes = msg.as_bytes();
        // Header (12) + zone name (3: \x01t\x00) + type (2) + class (2) = 19
        assert_eq!(bytes.len(), 19);
    }

    #[test]
    fn wire_signed_message_has_tsig_in_additional() {
        let zone = DomainName::new("example.com.").unwrap();
        let key = crate::tsig::TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            crate::tsig::TsigAlgorithm::HmacSha256,
            alloc::vec![0xAA; 32],
        )
        .unwrap();
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .sign(&key, 0)
            .build();
        let bytes = msg.as_bytes();

        // ADCOUNT should be 1 (TSIG record in additional section)
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1);

        // Message should be longer than unsigned (TSIG adds significant bytes)
        assert!(bytes.len() > 19);
    }

    // --- Sign integration tests ---

    #[test]
    fn signed_build_produces_valid_message() {
        let zone = DomainName::new("example.com.").unwrap();
        let key = crate::tsig::TsigKey::new(
            DomainName::new("update-key.").unwrap(),
            crate::tsig::TsigAlgorithm::HmacSha256,
            alloc::vec![0x42; 32],
        )
        .unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("new.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };

        let msg = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN)
            .require_name_not_exists(&DomainName::new("new.example.com.").unwrap())
            .add_record(rr)
            .sign(&key, 1710000000)
            .build();

        let bytes = msg.as_bytes();
        assert_eq!(msg.id(), 0x1234);

        // Opcode must be UPDATE (5)
        assert_eq!(bytes[2] & 0x78, 0x28);

        // ZOCOUNT = 1
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1);

        // PRCOUNT = 1
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);

        // UPCOUNT = 1
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 1);

        // ADCOUNT = 1 (TSIG)
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1);
    }

    #[test]
    fn wire_multiple_prerequisites_counted() {
        let zone = DomainName::new("example.com.").unwrap();
        let name = DomainName::new("www.example.com.").unwrap();
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .require_rrset_exists(&name, RecordType::A)
            .require_rrset_not_exists(&name, RecordType::Aaaa)
            .require_name_exists(&name)
            .build_unsigned();
        let bytes = msg.as_bytes();
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 3);
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 0);
    }

    #[test]
    fn wire_multiple_updates_counted() {
        let zone = DomainName::new("example.com.").unwrap();
        let rr1 = ResourceRecord {
            name: DomainName::new("a.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
        };
        let rr2 = ResourceRecord {
            name: DomainName::new("b.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
        };
        let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .add_record(rr1)
            .add_record(rr2)
            .delete_name(&DomainName::new("c.example.com.").unwrap())
            .build_unsigned();
        let bytes = msg.as_bytes();
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0); // no prereqs
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 3); // 3 updates
    }

    #[test]
    fn wire_delete_record_has_rdata() {
        let zone = DomainName::new("t.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("t.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(0).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(1, 2, 3, 4)),
        };
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
            .delete_record(rr)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // After header (12) + zone (t. = 3 bytes name + 2 type + 2 class = 7), update starts at 19
        let upd_start = 19;
        // Name: \x01t\x00 = 3 bytes
        let after_name = upd_start + 3;

        // TYPE: A (1)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
            1
        );
        // CLASS: NONE (254)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
            254
        );
        // TTL: 0
        assert_eq!(
            u32::from_be_bytes([
                bytes[after_name + 4],
                bytes[after_name + 5],
                bytes[after_name + 6],
                bytes[after_name + 7]
            ]),
            0
        );
        // RDLENGTH: 4
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
            4
        );
        // RDATA: 1.2.3.4
        assert_eq!(&bytes[after_name + 10..after_name + 14], &[1, 2, 3, 4]);
    }

    #[test]
    fn wire_delete_rrset_has_no_rdata() {
        let zone = DomainName::new("t.").unwrap();
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
            .delete_rrset(&DomainName::new("t.").unwrap(), RecordType::Aaaa)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // After header (12) + zone (7), update at 19
        let upd_start = 19;
        let after_name = upd_start + 3; // \x01t\x00

        // TYPE: AAAA (28)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
            28
        );
        // CLASS: ANY (255)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
            255
        );
        // TTL: 0
        assert_eq!(
            u32::from_be_bytes([
                bytes[after_name + 4],
                bytes[after_name + 5],
                bytes[after_name + 6],
                bytes[after_name + 7]
            ]),
            0
        );
        // RDLENGTH: 0
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
            0
        );
        // Nothing after RDLENGTH
        assert_eq!(bytes.len(), after_name + 10);
    }

    #[test]
    fn wire_add_record_has_class_and_ttl() {
        let zone = DomainName::new("t.").unwrap();
        let rr = ResourceRecord {
            name: DomainName::new("t.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 168, 1, 1)),
        };
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
            .add_record(rr)
            .build_unsigned();
        let bytes = msg.as_bytes();

        let upd_start = 19;
        let after_name = upd_start + 3;

        // TYPE: A (1)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
            1
        );
        // CLASS: IN (1) — actual class, not ANY
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
            1
        );
        // TTL: 3600
        assert_eq!(
            u32::from_be_bytes([
                bytes[after_name + 4],
                bytes[after_name + 5],
                bytes[after_name + 6],
                bytes[after_name + 7]
            ]),
            3600
        );
        // RDLENGTH: 4
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
            4
        );
        // RDATA: 192.168.1.1
        assert_eq!(&bytes[after_name + 10..after_name + 14], &[192, 168, 1, 1]);
    }

    #[test]
    fn wire_prerequisite_rrset_not_exists_class_none() {
        let zone = DomainName::new("t.").unwrap();
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
            .require_rrset_not_exists(&DomainName::new("t.").unwrap(), RecordType::Mx)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // After header (12) + zone (7), prereq at 19
        let after_name = 19 + 3; // \x01t\x00

        // TYPE: MX (15)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
            15
        );
        // CLASS: NONE (254)
        assert_eq!(
            u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
            254
        );
    }

    #[test]
    fn unsigned_and_signed_produce_different_bytes() {
        let zone = DomainName::new("example.com.").unwrap();
        let key = crate::tsig::TsigKey::new(
            DomainName::new("k.").unwrap(),
            crate::tsig::TsigAlgorithm::HmacSha256,
            alloc::vec![0xFF; 32],
        )
        .unwrap();

        let unsigned = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN).build_unsigned();
        let signed = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .sign(&key, 0)
            .build();

        assert_ne!(unsigned.as_bytes(), signed.as_bytes());
        assert!(signed.as_bytes().len() > unsigned.as_bytes().len());
    }
}
