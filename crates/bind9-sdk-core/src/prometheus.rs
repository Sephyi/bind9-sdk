// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Prometheus text exposition for BIND statistics (FR-072).
//!
//! Renders a [`ServerStats`] snapshot into the Prometheus text exposition
//! format (version 0.0.4) so the SDK can feed a scrape endpoint without a
//! separate `bind_exporter` process. Metric names are prefixed `bind_` and
//! label values are escaped per the exposition spec.

use alloc::format;
use alloc::string::String;

use crate::traits::{CounterSet, ServerStats};

/// Escape a Prometheus label value: backslash, double-quote, and newline.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render one labelled counter family from a [`CounterSet`].
fn render_counter_set(out: &mut String, metric: &str, help: &str, label: &str, set: &CounterSet) {
    if set.is_empty() {
        return;
    }
    out.push_str(&format!("# HELP {metric} {help}\n"));
    out.push_str(&format!("# TYPE {metric} counter\n"));
    for counter in set.iter() {
        out.push_str(&format!(
            "{metric}{{{label}=\"{}\"}} {}\n",
            escape_label(&counter.name),
            counter.value
        ));
    }
}

/// Render a [`ServerStats`] snapshot as Prometheus text exposition format.
///
/// The output is suitable for serving directly from an HTTP `/metrics`
/// endpoint. Only populated sections are emitted, so an empty snapshot yields
/// an empty string.
pub fn server_stats_to_prometheus(stats: &ServerStats) -> String {
    let mut out = String::new();

    render_counter_set(
        &mut out,
        "bind_incoming_queries_total",
        "Incoming requests by DNS opcode.",
        "opcode",
        &stats.opcodes,
    );
    render_counter_set(
        &mut out,
        "bind_responses_total",
        "Responses by DNS RCODE.",
        "rcode",
        &stats.rcodes,
    );
    render_counter_set(
        &mut out,
        "bind_socket_total",
        "Socket I/O counters.",
        "operation",
        &stats.socket,
    );

    if let Some(memory) = &stats.memory {
        out.push_str("# HELP bind_memory_in_use_bytes Memory currently in use.\n");
        out.push_str("# TYPE bind_memory_in_use_bytes gauge\n");
        out.push_str(&format!("bind_memory_in_use_bytes {}\n", memory.in_use));
        out.push_str("# HELP bind_memory_malloced_bytes Total memory allocated.\n");
        out.push_str("# TYPE bind_memory_malloced_bytes gauge\n");
        out.push_str(&format!("bind_memory_malloced_bytes {}\n", memory.malloced));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{CounterSet, MemoryStats, NamedCounter, ServerStats};

    fn stats() -> ServerStats {
        ServerStats {
            json_stats_version: None,
            boot_time: None,
            config_time: None,
            current_time: None,
            version: None,
            opcodes: CounterSet::new(alloc::vec![
                NamedCounter::new("QUERY", 42),
                NamedCounter::new("UPDATE", 3),
            ]),
            rcodes: CounterSet::new(alloc::vec![NamedCounter::new("NOERROR", 40)]),
            views: alloc::vec![],
            socket: CounterSet::new(alloc::vec![]),
            memory: Some(MemoryStats {
                in_use: 1024,
                malloced: 2048,
                contexts: alloc::vec![],
            }),
            traffic: alloc::vec![],
        }
    }

    #[test]
    fn renders_counters_and_memory() {
        let text = server_stats_to_prometheus(&stats());
        assert!(text.contains("# TYPE bind_incoming_queries_total counter"));
        assert!(text.contains("bind_incoming_queries_total{opcode=\"QUERY\"} 42"));
        assert!(text.contains("bind_responses_total{rcode=\"NOERROR\"} 40"));
        assert!(text.contains("bind_memory_in_use_bytes 1024"));
        assert!(text.contains("bind_memory_malloced_bytes 2048"));
    }

    #[test]
    fn empty_sections_are_omitted() {
        let text = server_stats_to_prometheus(&stats());
        // socket set is empty -> no socket family emitted.
        assert!(!text.contains("bind_socket_total"));
    }

    #[test]
    fn label_values_are_escaped() {
        let s = ServerStats {
            opcodes: CounterSet::new(alloc::vec![NamedCounter::new("a\"b\\c", 1)]),
            ..stats()
        };
        let text = server_stats_to_prometheus(&s);
        assert!(text.contains("opcode=\"a\\\"b\\\\c\""));
    }
}
