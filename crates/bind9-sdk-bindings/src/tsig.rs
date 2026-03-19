// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::Arc;

use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_core::DomainName;
use napi_derive::napi;

use crate::error::BindSdkError;

/// A TSIG key for DNS message authentication (RFC 8945).
///
/// Holds HMAC key material that is securely managed (zeroized on drop,
/// not cloneable). Use `Arc` internally for safe sharing.
#[napi]
pub struct JsTsigKey {
    inner: Arc<TsigKey>,
}

#[napi]
impl JsTsigKey {
    /// Create a TSIG key from a name, algorithm string, and base64-encoded secret.
    ///
    /// Supported algorithms: `"hmac-sha256"`, `"hmac-sha512"`, `"hmac-sha1"` (legacy).
    /// Throws on invalid name, unsupported algorithm, or bad base64.
    #[napi(constructor)]
    pub fn new(name: String, algorithm: String, secret_base64: String) -> napi::Result<Self> {
        let algo = match algorithm.as_str() {
            "hmac-sha256" => TsigAlgorithm::HmacSha256,
            "hmac-sha512" => TsigAlgorithm::HmacSha512,
            "hmac-sha1" =>
            {
                #[allow(deprecated)]
                TsigAlgorithm::HmacSha1
            }
            other => {
                return Err(napi::Error::from_reason(format!(
                    "unsupported algorithm: {other}"
                )));
            }
        };
        let domain = DomainName::new(&name).map_err(BindSdkError::from_core)?;
        let key =
            TsigKey::from_base64(domain, algo, &secret_base64).map_err(BindSdkError::from_core)?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// The key name as a fully-qualified domain name string.
    #[napi]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    /// The algorithm name (e.g., `"hmac-sha256"`).
    #[napi]
    pub fn algorithm(&self) -> String {
        format!("{}", self.inner.algorithm())
    }
}

impl JsTsigKey {
    /// Access the inner `TsigKey` reference (crate-internal).
    pub(crate) fn inner_ref(&self) -> &TsigKey {
        &self.inner
    }
}
