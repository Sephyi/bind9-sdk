// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::domain::DomainName;
use crate::protocol::RecordType;
use crate::record::{RecordClass, ResourceRecord};

use super::message::encode_update_message;
use super::{Prerequisite, Signed, Unsigned, UpdateBuilder, UpdateEntry, UpdateMessage};

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
    ) -> Result<Self, crate::error::CoreError> {
        if records.is_empty() {
            return Err(crate::error::CoreError::InvalidRecord(
                "RrsetExistsWithData requires non-empty records".into(),
            ));
        }
        self.prerequisites.push(Prerequisite::RrsetExistsWithData {
            name: name.clone(),
            rtype,
            records,
        });
        Ok(self)
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
    /// Use `sign_now` (requires `std` feature) for automatic timestamping,
    /// or provide a timestamp from an external clock in `no_std`.
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
                    request_mac: Some(Zeroizing::new(request_mac)),
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
