// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! JavaScript bindings for RFC 2136 dynamic DNS update sender.

use std::sync::Arc;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_net::NsUpdateSender;
use napi_derive::napi;

use crate::error::BindSdkError;
use crate::update::JsUpdateMessage;

/// Sends RFC 2136 dynamic update messages to a DNS server.
///
/// Uses UDP with automatic TCP fallback when the response is truncated.
/// Supports optional TSIG response verification when the message was signed.
#[napi]
pub struct JsNsUpdateSender {
    server: String,
    port: u16,
    key: Option<Arc<TsigKey>>,
}

#[napi]
impl JsNsUpdateSender {
    /// Create a new nsupdate sender.
    ///
    /// If TSIG key parameters are provided, the sender will verify
    /// response TSIG signatures for signed messages.
    #[napi(constructor)]
    pub fn new(
        server: String,
        port: u16,
        key_name: Option<String>,
        algorithm: Option<String>,
        key_secret_base64: Option<String>,
    ) -> napi::Result<Self> {
        let key = match (key_name, algorithm, key_secret_base64) {
            (Some(name), Some(algo_str), Some(secret)) => {
                let algo = parse_algorithm(&algo_str)?;
                let domain = DomainName::new(&name).map_err(BindSdkError::from_core)?;
                let key =
                    TsigKey::from_base64(domain, algo, &secret).map_err(BindSdkError::from_core)?;
                Some(Arc::new(key))
            }
            (None, None, None) => None,
            _ => {
                return Err(napi::Error::from_reason(
                    "key_name, algorithm, and key_secret_base64 must all be provided or all omitted",
                ));
            }
        };
        Ok(Self { server, port, key })
    }

    /// Send a dynamic update message and return the response RCODE.
    ///
    /// `message` should be created via `JsUpdateBuilder.buildMessageUnsigned()`
    /// or `JsUpdateBuilder.signMessage()`.
    ///
    /// Returns the response RCODE as a string (e.g., `"NOERROR"`, `"REFUSED"`).
    #[napi]
    pub async fn send_message(&self, message: &JsUpdateMessage) -> napi::Result<String> {
        let addr = format!("{}:{}", self.server, self.port)
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;

        let sender = NsUpdateSender::new(addr);

        let tsig_key_ref = self.key.as_deref();
        let result = sender
            .send(&message.inner, tsig_key_ref)
            .await
            .map_err(BindSdkError::from_net)?;

        Ok(result.rcode.to_string())
    }
}

/// Parse an algorithm string into a `TsigAlgorithm`.
fn parse_algorithm(algorithm: &str) -> napi::Result<TsigAlgorithm> {
    match algorithm {
        "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
        "hmac-sha1" => {
            #[allow(deprecated)]
            Ok(TsigAlgorithm::HmacSha1)
        }
        other => Err(napi::Error::from_reason(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}
