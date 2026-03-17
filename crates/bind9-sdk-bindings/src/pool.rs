// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! JavaScript bindings for the rndc connection pool.

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};
use bind9_sdk_net::config::ClientConfig;
use bind9_sdk_net::pool::RndcPool;
use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::rndc::RndcConnection;
use napi_derive::napi;

use crate::error::BindSdkError;

/// A concurrency-limited pool for rndc operations.
///
/// Limits the number of concurrent rndc connections to prevent
/// overwhelming the BIND9 control channel. Each operation acquires
/// a slot, executes, and releases the slot.
#[napi]
pub struct JsRndcPool {
    inner: RndcPool,
}

#[napi]
impl JsRndcPool {
    /// Create a new rndc connection pool.
    ///
    /// `maxConcurrent` limits the number of simultaneous rndc connections.
    /// Set to 0 to use the default (4).
    #[napi(constructor)]
    pub fn new(
        host: String,
        port: u16,
        key_name: String,
        algorithm: String,
        key_secret_base64: String,
        max_concurrent: u32,
    ) -> napi::Result<Self> {
        let algo = parse_algorithm(&algorithm)?;
        let domain = DomainName::new(&key_name).map_err(BindSdkError::from_core)?;
        let key = TsigKey::from_base64(domain, algo, &key_secret_base64)
            .map_err(BindSdkError::from_core)?;

        let addr = format!("{host}:{port}")
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;

        let config = ClientConfig::new(addr, key);
        let pool = RndcPool::new(config, max_concurrent as usize);

        Ok(Self { inner: pool })
    }

    /// The number of currently available (unacquired) connection slots.
    #[napi]
    pub fn available(&self) -> u32 {
        self.inner.available() as u32
    }

    /// Execute an rndc command through the pool.
    ///
    /// Acquires a connection slot, connects, authenticates, sends the command,
    /// closes the connection, and releases the slot.
    #[napi]
    pub async fn execute(&self, command: String) -> napi::Result<String> {
        let guard = self.inner.acquire().await.map_err(BindSdkError::from_net)?;
        let config = guard.config();

        let conn = RndcConnection::connect(config.rndc_addr)
            .await
            .map_err(BindSdkError::from_net)?;
        let mut conn = conn
            .authenticate(&config.rndc_key)
            .await
            .map_err(BindSdkError::from_net)?;
        let resp = conn
            .command(RndcCommand::Raw(command))
            .await
            .map_err(BindSdkError::from_net)?;
        conn.close().await.map_err(BindSdkError::from_net)?;

        Ok(resp.text)
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
