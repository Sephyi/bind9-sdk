// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use bind9_sdk_core::DomainName;
use napi_derive::napi;

use crate::error::BindSdkError;

/// A fully-qualified domain name (RFC 1035).
///
/// Validates label length (max 63 bytes), total name length (max 253
/// characters), and wire format length (max 255 octets) on construction.
#[napi]
pub struct JsDomainName {
    inner: DomainName,
}

#[napi]
impl JsDomainName {
    /// Create a new domain name from a string.
    ///
    /// Accepts both relative (`"example.com"`) and absolute (`"example.com."`)
    /// forms. Throws on invalid input.
    #[napi(constructor)]
    pub fn new(name: String) -> napi::Result<Self> {
        let inner = DomainName::new(&name).map_err(BindSdkError::from_core)?;
        Ok(Self { inner })
    }

    /// Returns the fully-qualified string representation (with trailing dot).
    #[napi(js_name = "toString")]
    pub fn as_fqdn(&self) -> String {
        self.inner.to_string()
    }

    /// Number of labels (excluding root).
    #[napi]
    pub fn label_count(&self) -> u32 {
        self.inner.label_count() as u32
    }
}
