// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! JavaScript bindings for AXFR/IXFR zone transfer client.

use std::pin::pin;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::transfer::TransferRecord;
use bind9_sdk_net::TransferClient;
use napi_derive::napi;
use tokio_stream::StreamExt;

use crate::error::BindSdkError;
use crate::record::{JsResourceRecord, convert_resource_record};

/// A zone transfer client for AXFR and IXFR operations.
///
/// Connects over plain TCP to a DNS server and retrieves zone data.
/// Currently limited to localhost connections (TLS required for remote).
#[napi]
pub struct JsTransferClient {
    host: String,
    port: u16,
}

#[napi]
impl JsTransferClient {
    /// Create a new transfer client.
    ///
    /// The client connects on each transfer operation. Plain TCP is only
    /// allowed for localhost; remote connections require TLS (not yet implemented).
    #[napi(constructor)]
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Perform a full zone transfer (AXFR).
    ///
    /// Connects to the server, sends an AXFR query, and collects all records.
    /// Returns an array of resource record objects.
    #[napi]
    pub async fn axfr(&self, zone: String) -> napi::Result<Vec<JsResourceRecord>> {
        let domain = DomainName::new(&zone).map_err(BindSdkError::from_core)?;
        let addr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;

        let client = TransferClient::connect(addr, None)
            .await
            .map_err(BindSdkError::from_net)?;

        let stream = client
            .axfr(domain, None)
            .await
            .map_err(BindSdkError::from_net)?;
        let mut stream = pin!(stream);

        let mut records = Vec::new();
        while let Some(result) = stream.next().await {
            let transfer_record = result.map_err(BindSdkError::from_net)?;
            let rr = match transfer_record {
                TransferRecord::BeginSoa(rr)
                | TransferRecord::Record(rr)
                | TransferRecord::EndSoa(rr) => rr,
                _ => continue,
            };
            records.push(convert_resource_record(&rr));
        }

        Ok(records)
    }
}
