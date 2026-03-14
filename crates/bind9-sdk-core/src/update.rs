// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use crate::protocol::Rcode;

/// A constructed RFC 2136 dynamic update message, ready to send on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
}

impl UpdateMessage {
    /// The raw wire bytes of the DNS update message.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// The DNS message ID.
    pub fn id(&self) -> u16 {
        self.id
    }
}

/// Result of sending an RFC 2136 update to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    pub rcode: Rcode,
    pub id: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_message_accessors() {
        let msg = UpdateMessage {
            wire_bytes: alloc::vec![0x00, 0x01, 0x28, 0x00],
            id: 0x0001,
        };
        assert_eq!(msg.as_bytes(), &[0x00, 0x01, 0x28, 0x00]);
        assert_eq!(msg.id(), 0x0001);
    }

    #[test]
    fn update_result_success() {
        let result = UpdateResult {
            rcode: Rcode::NoError,
            id: 42,
        };
        assert!(result.rcode.is_success());
    }
}
