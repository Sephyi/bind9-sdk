// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Zone transfer types for AXFR and IXFR operations.
//!
//! Provides [`TransferSession`] (typestate: [`Pending`] / [`Active`]),
//! [`TransferKind`], and [`TransferRecord`] — core types consumed by
//! the net layer's `TransferClient`.

use crate::domain::DomainName;
use crate::record::{ResourceRecord, Serial};

/// Typestate: the transfer session has been created but not yet started.
pub struct Pending;

/// Typestate: the transfer session is actively receiving records.
pub struct Active;

/// The kind of zone transfer being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferKind {
    /// Full zone transfer (AXFR) — retrieves the entire zone.
    Axfr,
    /// Incremental zone transfer (IXFR) — retrieves only changes since a known serial.
    Ixfr,
}

/// A record received during a zone transfer.
///
/// The first and last records in a successful AXFR are always SOA records.
/// `BeginSoa` marks the opening SOA, `EndSoa` marks the closing SOA, and
/// `Record` covers everything in between.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferRecord {
    /// The opening SOA record that begins a zone transfer.
    BeginSoa(ResourceRecord),
    /// A regular record within the transfer stream.
    Record(ResourceRecord),
    /// The closing SOA record that ends a zone transfer.
    EndSoa(ResourceRecord),
}

/// A typed event from an RFC 1995 incremental zone transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IxfrEvent {
    /// The server is not newer than the requested serial.
    NoChange(ResourceRecord),
    /// The server's current SOA that brackets an incremental response.
    CurrentSoa(ResourceRecord),
    /// The older SOA that begins a delete sequence.
    DeleteSoa(ResourceRecord),
    /// A record to remove from the caller's current zone.
    Deleted(ResourceRecord),
    /// The newer SOA that begins an add sequence.
    AddSoa(ResourceRecord),
    /// A record to add to the caller's current zone.
    Added(ResourceRecord),
    /// The final copy of the server's current SOA.
    EndSoa(ResourceRecord),
    /// The server returned the complete zone instead of incremental differences.
    AxfrFallback(TransferRecord),
}

/// A zone transfer session tracking transfer state.
///
/// Uses the typestate pattern: `TransferSession<Pending>` is created via
/// [`axfr`](TransferSession::axfr) or [`ixfr`](TransferSession::ixfr),
/// then transitions to `TransferSession<Active>` when the transfer begins.
pub struct TransferSession<State> {
    zone: DomainName,
    kind: TransferKind,
    current_serial: Option<Serial>,
    _state: core::marker::PhantomData<State>,
}

impl TransferSession<Pending> {
    /// Create a new AXFR transfer session for the given zone.
    pub fn axfr(zone: DomainName) -> Self {
        Self {
            zone,
            kind: TransferKind::Axfr,
            current_serial: None,
            _state: core::marker::PhantomData,
        }
    }

    /// Create a new IXFR transfer session for the given zone.
    ///
    /// `current_serial` is the serial number of the zone data we already hold;
    /// the server will send only changes since that serial.
    pub fn ixfr(zone: DomainName, current_serial: Serial) -> Self {
        Self {
            zone,
            kind: TransferKind::Ixfr,
            current_serial: Some(current_serial),
            _state: core::marker::PhantomData,
        }
    }

    /// The zone being transferred.
    pub fn zone(&self) -> &DomainName {
        &self.zone
    }

    /// Whether this is a full zone transfer (AXFR).
    pub fn is_axfr(&self) -> bool {
        matches!(self.kind, TransferKind::Axfr)
    }

    /// Whether this is an incremental zone transfer (IXFR).
    pub fn is_ixfr(&self) -> bool {
        matches!(self.kind, TransferKind::Ixfr)
    }

    /// The transfer kind.
    pub fn kind(&self) -> TransferKind {
        self.kind
    }

    /// The current serial for IXFR, or `None` for AXFR.
    pub fn current_serial(&self) -> Option<Serial> {
        self.current_serial
    }

    /// Transition to the active state.
    pub fn start(self) -> TransferSession<Active> {
        TransferSession {
            zone: self.zone,
            kind: self.kind,
            current_serial: self.current_serial,
            _state: core::marker::PhantomData,
        }
    }
}

impl TransferSession<Active> {
    /// The zone being transferred.
    pub fn zone(&self) -> &DomainName {
        &self.zone
    }

    /// The transfer kind.
    pub fn kind(&self) -> TransferKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};

    #[test]
    fn transfer_session_axfr() {
        let zone = DomainName::new("example.com.").unwrap();
        let session = TransferSession::<Pending>::axfr(zone.clone());
        assert_eq!(session.zone(), &zone);
        assert!(session.is_axfr());
        assert!(!session.is_ixfr());
        assert!(session.current_serial().is_none());
    }

    #[test]
    fn transfer_session_ixfr() {
        let zone = DomainName::new("example.com.").unwrap();
        let serial = Serial::new(2024010101);
        let session = TransferSession::<Pending>::ixfr(zone.clone(), serial);
        assert_eq!(session.zone(), &zone);
        assert!(session.is_ixfr());
        assert!(!session.is_axfr());
        assert_eq!(session.current_serial(), Some(serial));
    }

    #[test]
    fn transfer_session_start_transitions() {
        let zone = DomainName::new("example.com.").unwrap();
        let session = TransferSession::<Pending>::axfr(zone.clone());
        let active = session.start();
        assert_eq!(active.zone(), &zone);
        assert_eq!(active.kind(), TransferKind::Axfr);
    }

    #[test]
    fn transfer_kind_equality() {
        assert_eq!(TransferKind::Axfr, TransferKind::Axfr);
        assert_eq!(TransferKind::Ixfr, TransferKind::Ixfr);
        assert_ne!(TransferKind::Axfr, TransferKind::Ixfr);
    }

    #[test]
    fn transfer_record_begin_soa() {
        let soa = ResourceRecord {
            name: DomainName::new("example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::Soa {
                mname: DomainName::new("ns1.example.com.").unwrap(),
                rname: DomainName::new("admin.example.com.").unwrap(),
                serial: Serial::new(2024010101),
                refresh: Ttl::new(3600).unwrap(),
                retry: Ttl::new(900).unwrap(),
                expire: Ttl::new(604800).unwrap(),
                minimum: Ttl::new(86400).unwrap(),
            },
        };
        let record = TransferRecord::BeginSoa(soa.clone());
        assert!(matches!(record, TransferRecord::BeginSoa(ref r) if r == &soa));
    }

    #[test]
    fn transfer_record_variants() {
        let rr = ResourceRecord {
            name: DomainName::new("host.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let record = TransferRecord::Record(rr.clone());
        assert!(matches!(record, TransferRecord::Record(ref r) if r == &rr));
    }

    #[test]
    fn ixfr_events_distinguish_deleted_and_added_records() {
        let rr = ResourceRecord {
            name: DomainName::new("host.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };

        let deleted = IxfrEvent::Deleted(rr.clone());
        let added = IxfrEvent::Added(rr.clone());

        assert!(matches!(deleted, IxfrEvent::Deleted(ref record) if record == &rr));
        assert!(matches!(added, IxfrEvent::Added(ref record) if record == &rr));
    }

    #[test]
    fn ixfr_event_can_report_axfr_fallback() {
        let rr = ResourceRecord {
            name: DomainName::new("host.example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(300).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };

        let event = IxfrEvent::AxfrFallback(TransferRecord::Record(rr.clone()));

        assert!(
            matches!(event, IxfrEvent::AxfrFallback(TransferRecord::Record(ref record)) if record == &rr)
        );
    }
}
