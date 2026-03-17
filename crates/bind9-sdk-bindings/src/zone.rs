// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use bind9_sdk_core::zone::ZoneFile;
use napi_derive::napi;

use crate::error::BindSdkError;
use crate::record::convert_resource_record;

/// A parsed DNS zone file (RFC 1035 master file format).
///
/// Use `JsZoneFile.parse()` to create from text, and `.serialize()` to
/// convert back. Records can be extracted via `records()`.
#[napi]
pub struct JsZoneFile {
    inner: ZoneFile,
}

#[napi]
impl JsZoneFile {
    /// Parse a zone file from text.
    ///
    /// Throws on `$INCLUDE` directives. Use a fully-resolved zone file.
    #[napi(factory)]
    pub fn parse(text: String) -> napi::Result<Self> {
        let inner = ZoneFile::parse(&text).map_err(BindSdkError::from_core)?;
        Ok(Self { inner })
    }

    /// Serialize the zone file back to canonical text format.
    #[napi]
    pub fn serialize(&self) -> String {
        self.inner.serialize()
    }

    /// Number of resource records in the zone.
    #[napi]
    pub fn record_count(&self) -> u32 {
        self.inner.zone.records.len() as u32
    }

    /// The zone origin as a fully-qualified domain name string.
    #[napi]
    pub fn origin(&self) -> String {
        self.inner.origin.to_string()
    }

    /// All resource records in the zone as plain JS objects.
    #[napi]
    pub fn records(&self) -> Vec<crate::record::JsResourceRecord> {
        self.inner
            .zone
            .records
            .iter()
            .map(convert_resource_record)
            .collect()
    }
}
