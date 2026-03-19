// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CoreError;

/// Read an uncompressed wire-format domain name from `data` at `pos`.
/// Returns the parsed name string (with trailing dot) and advances `pos`.
pub(super) fn read_wire_name(data: &[u8], pos: &mut usize) -> Result<String, CoreError> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        if *pos >= data.len() {
            return Err(CoreError::Tsig("truncated wire name".into()));
        }
        let len = data[*pos] as usize;
        *pos += 1;
        if len == 0 {
            break;
        }
        // Reject compression pointers (top 2 bits set)
        if len & 0xC0 != 0 {
            return Err(CoreError::Tsig(
                "compressed names not supported in TSIG".into(),
            ));
        }
        if *pos + len > data.len() {
            return Err(CoreError::Tsig("truncated wire name label".into()));
        }
        let label = core::str::from_utf8(&data[*pos..*pos + len])
            .map_err(|_| CoreError::Tsig("invalid UTF-8 in wire name".into()))?;
        labels.push(String::from(label));
        *pos += len;
    }
    let mut name = labels.join(".");
    name.push('.');
    Ok(name)
}
