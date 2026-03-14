// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub(crate) mod parser;
pub(crate) mod rdata_text;

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::record::{RecordClass, ResourceRecord, Serial};

/// Summary of a zone (name, class, serial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    pub name: DomainName,
    pub class: RecordClass,
    pub serial: Serial,
}

/// Full zone data — a collection of resource records sharing a common origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub name: DomainName,
    pub class: RecordClass,
    pub records: Vec<ResourceRecord>,
}

impl Zone {
    /// Extract the SOA serial number, if the zone contains a SOA record.
    pub fn serial(&self) -> Option<Serial> {
        self.soa().map(|rr| match &rr.rdata {
            crate::rdata::RecordData::Soa { serial, .. } => *serial,
            _ => unreachable!("soa() only returns SOA records"),
        })
    }

    /// Find the SOA record in this zone.
    pub fn soa(&self) -> Option<&ResourceRecord> {
        self.records
            .iter()
            .find(|rr| matches!(rr.rdata, crate::rdata::RecordData::Soa { .. }))
    }

    /// Create a zone summary.
    pub fn summary(&self) -> ZoneSummary {
        ZoneSummary {
            name: self.name.clone(),
            class: self.class,
            serial: self.serial().unwrap_or(Serial::new(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, Ttl};

    fn example_zone() -> Zone {
        let name = DomainName::new("example.com.").unwrap();
        Zone {
            name: name.clone(),
            class: RecordClass::IN,
            records: alloc::vec![
                ResourceRecord {
                    name: name.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: RecordData::Soa {
                        mname: DomainName::new("ns1.example.com.").unwrap(),
                        rname: DomainName::new("admin.example.com.").unwrap(),
                        serial: Serial::new(2026031401),
                        refresh: Ttl::new(3600).unwrap(),
                        retry: Ttl::new(900).unwrap(),
                        expire: Ttl::new(604800).unwrap(),
                        minimum: Ttl::new(86400).unwrap(),
                    },
                },
                ResourceRecord {
                    name: name.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
                },
            ],
        }
    }

    #[test]
    fn zone_serial_from_soa() {
        let zone = example_zone();
        assert_eq!(zone.serial(), Some(Serial::new(2026031401)));
    }

    #[test]
    fn zone_soa_found() {
        let zone = example_zone();
        assert!(zone.soa().is_some());
    }

    #[test]
    fn zone_summary() {
        let zone = example_zone();
        let summary = zone.summary();
        assert_eq!(summary.name, DomainName::new("example.com.").unwrap());
        assert_eq!(summary.class, RecordClass::IN);
        assert_eq!(summary.serial, Serial::new(2026031401));
    }

    #[test]
    fn zone_no_soa_serial_is_none() {
        let zone = Zone {
            name: DomainName::new("empty.example.com.").unwrap(),
            class: RecordClass::IN,
            records: alloc::vec![],
        };
        assert_eq!(zone.serial(), None);
    }
}
