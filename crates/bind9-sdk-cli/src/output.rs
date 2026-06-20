// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Output formatting for CLI commands.
//!
//! Supports both human-readable text and JSON output modes.

use serde::Serialize;

use crate::commands::OutputFormat;

/// Print a serializable value in the requested output format.
///
/// For `Text` format, uses the `Display` implementation.
/// For `Json` format, serializes to JSON.
pub fn print_output<T: Serialize + std::fmt::Display>(format: OutputFormat, value: &T) {
    match format {
        OutputFormat::Text => {
            println!("{value}");
        }
        OutputFormat::Json => match serde_json::to_string_pretty(value) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error: failed to serialize JSON: {e}"),
        },
    }
}

/// Print a plain string message respecting the output format.
pub fn print_message(format: OutputFormat, message: &str) {
    match format {
        OutputFormat::Text => {
            println!("{message}");
        }
        OutputFormat::Json => {
            let wrapper = serde_json::json!({ "message": message });
            match serde_json::to_string_pretty(&wrapper) {
                Ok(json) => println!("{json}"),
                Err(error) => eprintln!("error: failed to serialize JSON: {error}"),
            }
        }
    }
}

/// Print a success message respecting the output format.
pub fn print_success(format: OutputFormat, message: &str) {
    match format {
        OutputFormat::Text => {
            println!("{message}");
        }
        OutputFormat::Json => {
            let wrapper = serde_json::json!({ "status": "ok", "message": message });
            match serde_json::to_string_pretty(&wrapper) {
                Ok(json) => println!("{json}"),
                Err(error) => eprintln!("error: failed to serialize JSON: {error}"),
            }
        }
    }
}
