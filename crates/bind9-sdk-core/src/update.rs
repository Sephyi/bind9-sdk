// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::protocol::{Rcode, RecordType};
use crate::record::ResourceRecord;

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

/// A constructed RFC 2136 dynamic update message, ready to send on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
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
}

/// Result of sending an RFC 2136 update to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    pub rcode: Rcode,
    pub id: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_message_accessors() {
        let msg = UpdateMessage {
            wire_bytes: alloc::vec![0x00, 0x01, 0x28, 0x00],
            id: 0x0001,
        };
        assert_eq!(msg.as_bytes(), &[0x00, 0x01, 0x28, 0x00]);
        assert_eq!(msg.id(), 0x0001);
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
}
