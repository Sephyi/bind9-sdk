// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

/// Error mapping for JS bindings.
///
/// Converts internal SDK error types into [`napi::Error`] for propagation
/// to JavaScript callers.
pub struct BindSdkError;

impl BindSdkError {
    /// Convert a [`bind9_sdk_core::CoreError`] into a [`napi::Error`].
    pub fn from_core(err: bind9_sdk_core::CoreError) -> napi::Error {
        napi::Error::from_reason(err.to_string())
    }

    /// Convert a [`bind9_sdk_net::NetError`] into a [`napi::Error`].
    #[cfg(feature = "nodejs")]
    #[allow(dead_code)] // used by future net-layer bindings
    pub fn from_net(err: bind9_sdk_net::NetError) -> napi::Error {
        napi::Error::from_reason(err.to_string())
    }
}
