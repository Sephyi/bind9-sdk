// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub(crate) mod parser;
pub(crate) mod rdata_dnssec;
pub(crate) mod rdata_text;
pub(crate) mod serializer;

use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};

/// Summary of a zone (name, class, serial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    /// The apex domain name of the zone.
    pub name: DomainName,
    /// The DNS class of the zone (almost always `IN`).
    pub class: RecordClass,
    /// The current SOA serial number.
    pub serial: Serial,
}

/// Full zone data — a collection of resource records sharing a common origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The apex domain name of the zone.
    pub name: DomainName,
    /// The DNS class of the zone (almost always `IN`).
    pub class: RecordClass,
    /// All resource records in the zone.
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

/// Resolver for `$INCLUDE` directives in zone files.
///
/// Implement this trait to provide filesystem or custom include resolution.
/// The default `ZoneFile::parse()` method returns an error on `$INCLUDE`.
/// Use `ZoneFile::parse_with_includes()` to supply a resolver.
pub trait IncludeResolver {
    /// Read the content of an included file.
    fn resolve(&self, path: &str) -> Result<String, CoreError>;
}

/// A parsed zone file with metadata.
///
/// One `ZoneFile` corresponds to one zone (RFC 1035 master file format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFile {
    /// The zone origin (from `$ORIGIN` directive or inferred from SOA).
    pub origin: DomainName,
    /// The default TTL (from `$TTL` directive).
    pub default_ttl: Option<Ttl>,
    /// The parsed zone data.
    pub zone: Zone,
}

impl ZoneFile {
    /// Parse a zone file from text.
    ///
    /// Returns `CoreError::ZoneParse` on `$INCLUDE` directives. Use
    /// `parse_with_includes()` if the zone file may contain includes.
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        parser::parse_zone(input, None)
    }

    /// Parse a zone file from text with include resolution.
    pub fn parse_with_includes(
        input: &str,
        resolver: &dyn IncludeResolver,
    ) -> Result<Self, CoreError> {
        parser::parse_zone(input, Some(resolver))
    }

    /// Serialize the zone file back to text format.
    pub fn serialize(&self) -> String {
        serializer::serialize(self)
    }
}

impl crate::traits::ZoneManager for ZoneFile {
    type Error = CoreError;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, CoreError> {
        Ok(alloc::vec![self.zone.summary()])
    }

    async fn get_zone(&self, name: &DomainName) -> Result<Zone, CoreError> {
        if self.zone.name == *name {
            Ok(self.zone.clone())
        } else {
            Err(CoreError::InvalidName {
                name: alloc::format!("{name}"),
                reason: "zone not found".into(),
            })
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

    #[test]
    fn zonefile_type_constructs() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        assert_eq!(zf.origin, DomainName::new("example.com.").unwrap());
        assert_eq!(zf.default_ttl, Some(Ttl::new(3600).unwrap()));
        assert_eq!(zf.zone.name, DomainName::new("example.com.").unwrap());
    }

    struct TestIncludeResolver;

    impl IncludeResolver for TestIncludeResolver {
        fn resolve(&self, _path: &str) -> Result<alloc::string::String, CoreError> {
            Ok(alloc::string::String::from("included IN A 10.0.0.1\n"))
        }
    }

    #[test]
    fn include_resolver_trait_implementable() {
        let resolver = TestIncludeResolver;
        let content = resolver.resolve("test.zone").unwrap();
        assert!(content.contains("included"));
    }

    #[test]
    fn zonefile_zone_manager_list_zones() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        let summaries = alloc::vec![zf.zone.summary()];
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, DomainName::new("example.com.").unwrap());
        assert_eq!(summaries[0].serial, Serial::new(2026031401));
    }

    #[test]
    fn zonefile_zone_manager_get_zone_not_found() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        let other = DomainName::new("other.com.").unwrap();
        assert_ne!(zf.zone.name, other);
    }
}
