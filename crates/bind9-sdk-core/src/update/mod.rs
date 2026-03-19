// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC 2136 dynamic DNS update message construction.
//!
//! Provides a typestate builder ([`UpdateBuilder`]) that enforces signing
//! discipline at compile time, prerequisite conditions ([`Prerequisite`]),
//! update operations ([`UpdateEntry`]), and the wire-encoded message
//! ([`UpdateMessage`]).

mod builder;
mod message;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::domain::DomainName;
use crate::protocol::{Rcode, RecordType};
use crate::record::{RecordClass, ResourceRecord};

/// A prerequisite condition for an RFC 2136 dynamic update (§2.4).
///
/// Prerequisites are checked by the server before any updates are applied.
/// If any prerequisite fails, the entire update is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Prerequisite {
    /// An RRset with this name and type must exist (any data).
    RrsetExists {
        /// Owner name of the required RRset.
        name: DomainName,
        /// Record type of the required RRset.
        rtype: RecordType,
    },
    /// An RRset with this name and type must NOT exist.
    RrsetNotExists {
        /// Owner name of the forbidden RRset.
        name: DomainName,
        /// Record type of the forbidden RRset.
        rtype: RecordType,
    },
    /// At least one RRset with this name must exist (any type).
    NameExists {
        /// The domain name that must be in use.
        name: DomainName,
    },
    /// No RRsets with this name must exist (name is not in use).
    NameNotExists {
        /// The domain name that must not be in use.
        name: DomainName,
    },
    /// An RRset with this name, type, and specific data must exist (§2.4.2).
    RrsetExistsWithData {
        /// Owner name of the required RRset.
        name: DomainName,
        /// Record type of the required RRset.
        rtype: RecordType,
        /// The specific records that must be present.
        records: Vec<ResourceRecord>,
    },
}

impl Prerequisite {
    /// Number of wire-level RRs this prerequisite expands to.
    ///
    /// Most variants produce exactly one RR. `RrsetExistsWithData` produces
    /// one RR per record in the set (RFC 2136 §2.4.2).
    pub(super) fn wire_rr_count(&self) -> usize {
        match self {
            Self::RrsetExistsWithData { records, .. } => records.len(),
            _ => 1,
        }
    }
}

/// An update operation for an RFC 2136 dynamic update (§2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateEntry {
    /// Add a resource record to the zone.
    AddRecord(ResourceRecord),
    /// Delete all records of a given type at a name.
    DeleteRrset {
        /// Owner name of the RRset to delete.
        name: DomainName,
        /// Record type of the RRset to delete.
        rtype: RecordType,
    },
    /// Delete a specific resource record.
    DeleteRecord(ResourceRecord),
    /// Delete all records at a name (any type).
    DeleteName {
        /// The domain name whose records should all be deleted.
        name: DomainName,
    },
}

/// Typestate: the update message has not been signed.
pub struct Unsigned;

/// Typestate: the update message has been signed with TSIG.
pub struct Signed {
    pub(super) message: UpdateMessage,
}

/// Builder for constructing RFC 2136 dynamic update messages.
///
/// Uses the typestate pattern to enforce signing discipline at compile time:
/// - `UpdateBuilder<Unsigned>`: can add prerequisites and updates, can sign or build unsigned
/// - `UpdateBuilder<Signed>`: can only call `build()` to extract the signed message
///
/// All builder methods consume `self` and return a new builder (move semantics).
pub struct UpdateBuilder<State = Unsigned> {
    pub(super) id: u16,
    pub(super) zone: DomainName,
    pub(super) class: RecordClass,
    pub(super) prerequisites: Vec<Prerequisite>,
    pub(super) updates: Vec<UpdateEntry>,
    pub(super) state: State,
}

/// A constructed RFC 2136 dynamic update message, ready to send on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
    /// The request TSIG MAC, if the message was signed.
    /// Used by the net crate for response TSIG verification (RFC 8945 §4.5).
    /// Wrapped in `Zeroizing` so the MAC is wiped from memory on drop.
    pub(crate) request_mac: Option<Zeroizing<Vec<u8>>>,
    /// Length of the message before the TSIG record was appended.
    /// The response verifier needs the pre-TSIG bytes to reconstruct the MAC input.
    pub(crate) pre_tsig_len: Option<usize>,
}

/// Result of sending an RFC 2136 update to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    /// The DNS RCODE from the server response.
    pub rcode: Rcode,
    /// The DNS message ID echoed by the server.
    pub id: u16,
}
