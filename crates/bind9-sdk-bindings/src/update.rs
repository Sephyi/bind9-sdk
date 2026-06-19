// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::Arc;

use bind9_sdk_core::DomainName;
use bind9_sdk_core::record::{RecordClass, ResourceRecord, Ttl};
use bind9_sdk_core::update::{Unsigned, UpdateBuilder, UpdateMessage};
use bind9_sdk_core::zone::ZoneFile;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::error::BindSdkError;
use crate::tsig::JsTsigKey;

/// Builder for RFC 2136 dynamic DNS update messages.
///
/// Uses an internal `Option` wrapper around the consuming-self Rust builder.
/// Each method takes ownership of the inner builder, performs the operation,
/// and stores the result back.
#[napi]
pub struct JsUpdateBuilder {
    inner: Option<UpdateBuilder<Unsigned>>,
}

#[napi]
impl JsUpdateBuilder {
    /// Create a new update builder for the given zone name.
    ///
    /// The zone must be a valid fully-qualified domain name.
    #[napi(constructor)]
    pub fn new(zone: String) -> napi::Result<Self> {
        let domain = DomainName::new(&zone).map_err(BindSdkError::from_core)?;
        let builder = UpdateBuilder::new(domain, RecordClass::IN);
        Ok(Self {
            inner: Some(builder),
        })
    }

    /// Add a resource record to the update (RFC 2136 section 2.5.1).
    ///
    /// The record is parsed from zone-file-style arguments:
    /// `name` (FQDN), `ttl` (seconds), `rtype` (e.g., `"A"`), `rdata` (e.g., `"192.0.2.1"`).
    #[napi]
    pub fn add_record(
        &mut self,
        name: String,
        ttl: u32,
        rtype: String,
        rdata: String,
    ) -> napi::Result<()> {
        let rr = parse_record_from_strings(&name, ttl, &rtype, &rdata)?;
        let builder = self.take_builder()?;
        self.inner = Some(builder.add_record(rr));
        Ok(())
    }

    /// Delete a specific resource record (RFC 2136 section 2.5.4).
    ///
    /// Arguments are the same as `addRecord`. The server matches the exact
    /// record and removes it.
    #[napi]
    pub fn delete_record(
        &mut self,
        name: String,
        ttl: u32,
        rtype: String,
        rdata: String,
    ) -> napi::Result<()> {
        let rr = parse_record_from_strings(&name, ttl, &rtype, &rdata)?;
        let builder = self.take_builder()?;
        self.inner = Some(builder.delete_record(rr));
        Ok(())
    }

    /// Build the update without TSIG signing.
    ///
    /// Returns the raw DNS wire-format bytes. Use for testing or on trusted networks.
    #[napi]
    pub fn build_unsigned(&mut self) -> napi::Result<Buffer> {
        let builder = self.take_builder()?;
        let message = builder.build_unsigned().map_err(BindSdkError::from_core)?;
        Ok(Buffer::from(message.as_bytes().to_vec()))
    }

    /// Sign the update with a TSIG key and build the message.
    ///
    /// Returns the raw DNS wire-format bytes including the TSIG record.
    /// Uses the current system time for the TSIG timestamp.
    #[napi]
    pub fn sign(&mut self, key: &JsTsigKey) -> napi::Result<Buffer> {
        let builder = self.take_builder()?;
        let signed = builder
            .sign_now(key.inner_ref())
            .map_err(BindSdkError::from_core)?;
        let message = signed.build();
        Ok(Buffer::from(message.as_bytes().to_vec()))
    }

    /// Build an unsigned update and return an opaque message object.
    ///
    /// Use with `JsNsUpdateSender.sendMessage()` for proper response verification.
    #[napi]
    pub fn build_message_unsigned(&mut self) -> napi::Result<JsUpdateMessage> {
        let builder = self.take_builder()?;
        let message = builder.build_unsigned().map_err(BindSdkError::from_core)?;
        Ok(JsUpdateMessage {
            inner: Arc::new(message),
        })
    }

    /// Sign the update and return an opaque message object.
    ///
    /// Use with `JsNsUpdateSender.sendMessage()` for proper TSIG response verification.
    #[napi]
    pub fn sign_message(&mut self, key: &JsTsigKey) -> napi::Result<JsUpdateMessage> {
        let builder = self.take_builder()?;
        let signed = builder
            .sign_now(key.inner_ref())
            .map_err(BindSdkError::from_core)?;
        let message = signed.build();
        Ok(JsUpdateMessage {
            inner: Arc::new(message),
        })
    }
}

/// An opaque RFC 2136 update message, ready to be sent.
///
/// Created via `JsUpdateBuilder.buildMessageUnsigned()` or
/// `JsUpdateBuilder.signMessage()`. Pass to `JsNsUpdateSender.sendMessage()`.
#[napi]
pub struct JsUpdateMessage {
    pub(crate) inner: Arc<UpdateMessage>,
}

#[napi]
impl JsUpdateMessage {
    /// The raw DNS wire-format bytes.
    #[napi]
    pub fn as_bytes(&self) -> Buffer {
        Buffer::from(self.inner.as_bytes().to_vec())
    }

    /// Whether this message is TSIG-signed.
    #[napi]
    pub fn is_signed(&self) -> bool {
        self.inner.is_signed()
    }
}

impl JsUpdateBuilder {
    /// Take the inner builder, returning an error if already consumed.
    fn take_builder(&mut self) -> napi::Result<UpdateBuilder<Unsigned>> {
        self.inner.take().ok_or_else(|| {
            napi::Error::from_reason(
                "UpdateBuilder has already been consumed (build or sign was called)",
            )
        })
    }
}

/// Parse a `ResourceRecord` from zone-file-style string arguments.
///
/// Constructs a minimal zone file snippet and uses the zone parser to
/// produce a properly typed `ResourceRecord`.
fn parse_record_from_strings(
    name: &str,
    ttl: u32,
    rtype: &str,
    rdata: &str,
) -> napi::Result<ResourceRecord> {
    // Ensure the name is absolute for the zone parser
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };

    let snippet = format!("$ORIGIN {fqdn}\n{fqdn} {ttl} IN {rtype} {rdata}\n");
    let zone_file = ZoneFile::parse(&snippet).map_err(BindSdkError::from_core)?;

    let mut records = zone_file.zone.records;
    if records.is_empty() {
        return Err(napi::Error::from_reason(
            "failed to parse record from the provided arguments",
        ));
    }

    let mut rr = records.remove(0);
    // Override TTL with the explicit value (the parser may have used $TTL default)
    rr.ttl = Ttl::new(ttl).map_err(BindSdkError::from_core)?;
    Ok(rr)
}
