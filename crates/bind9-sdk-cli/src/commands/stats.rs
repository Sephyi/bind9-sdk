// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Server statistics CLI command.

use std::collections::BTreeMap;

use serde::Serialize;

use bind9_sdk::net::{Bind9Client, ClientConfig};
use bind9_sdk::{
    CounterSet, MemoryContextStats, MemoryStats, ServerStats, StatsClient, TrafficHistogram,
    ViewStats,
};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::print_output;

#[derive(Debug, Serialize)]
struct StatsOutput {
    json_stats_version: Option<String>,
    version: Option<String>,
    boot_time: Option<String>,
    config_time: Option<String>,
    current_time: Option<String>,
    queries: Option<u64>,
    servfail: Option<u64>,
    opcodes: BTreeMap<String, u64>,
    rcodes: BTreeMap<String, u64>,
    views: Vec<ViewStatsOutput>,
    socket: BTreeMap<String, u64>,
    memory: Option<MemoryStatsOutput>,
    traffic: BTreeMap<String, BTreeMap<String, u64>>,
}

#[derive(Debug, Serialize)]
struct ViewStatsOutput {
    name: String,
    resolver_stats: BTreeMap<String, u64>,
    query_types: BTreeMap<String, u64>,
    cache: BTreeMap<String, u64>,
    cache_stats: BTreeMap<String, u64>,
    adb: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct MemoryStatsOutput {
    in_use: u64,
    malloced: u64,
    contexts: Vec<MemoryContextStatsOutput>,
}

#[derive(Debug, Serialize)]
struct MemoryContextStatsOutput {
    id: String,
    name: String,
    references: u64,
    malloced: u64,
    in_use: u64,
    pools: u64,
    high_water: u64,
    low_water: u64,
}

impl From<ServerStats> for StatsOutput {
    fn from(stats: ServerStats) -> Self {
        Self {
            queries: stats.opcodes.get("QUERY"),
            servfail: stats.rcodes.get("SERVFAIL"),
            json_stats_version: stats.json_stats_version,
            version: stats.version,
            boot_time: stats.boot_time,
            config_time: stats.config_time,
            current_time: stats.current_time,
            opcodes: counters_to_map(&stats.opcodes),
            rcodes: counters_to_map(&stats.rcodes),
            views: stats.views.into_iter().map(ViewStatsOutput::from).collect(),
            socket: counters_to_map(&stats.socket),
            memory: stats.memory.map(MemoryStatsOutput::from),
            traffic: stats
                .traffic
                .into_iter()
                .map(|histogram| (histogram.name.clone(), traffic_histogram_to_map(&histogram)))
                .collect(),
        }
    }
}

impl From<ViewStats> for ViewStatsOutput {
    fn from(stats: ViewStats) -> Self {
        Self {
            name: stats.name,
            resolver_stats: counters_to_map(&stats.resolver_stats),
            query_types: counters_to_map(&stats.query_types),
            cache: counters_to_map(&stats.cache),
            cache_stats: counters_to_map(&stats.cache_stats),
            adb: counters_to_map(&stats.adb),
        }
    }
}

impl From<MemoryStats> for MemoryStatsOutput {
    fn from(stats: MemoryStats) -> Self {
        Self {
            in_use: stats.in_use,
            malloced: stats.malloced,
            contexts: stats
                .contexts
                .into_iter()
                .map(MemoryContextStatsOutput::from)
                .collect(),
        }
    }
}

impl From<MemoryContextStats> for MemoryContextStatsOutput {
    fn from(stats: MemoryContextStats) -> Self {
        Self {
            id: stats.id,
            name: stats.name,
            references: stats.references,
            malloced: stats.malloced,
            in_use: stats.in_use,
            pools: stats.pools,
            high_water: stats.high_water,
            low_water: stats.low_water,
        }
    }
}

fn counters_to_map(counters: &CounterSet) -> BTreeMap<String, u64> {
    counters
        .iter()
        .map(|counter| (counter.name.clone(), counter.value))
        .collect()
}

fn traffic_histogram_to_map(histogram: &TrafficHistogram) -> BTreeMap<String, u64> {
    counters_to_map(&histogram.buckets)
}

impl std::fmt::Display for StatsOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(version) = &self.version {
            writeln!(f, "BIND version: {version}")?;
        }
        if let Some(boot_time) = &self.boot_time {
            writeln!(f, "Boot time: {boot_time}")?;
        }
        if let Some(current_time) = &self.current_time {
            writeln!(f, "Snapshot time: {current_time}")?;
        }
        if let Some(queries) = self.queries {
            writeln!(f, "Queries: {queries}")?;
        }
        if let Some(servfail) = self.servfail {
            writeln!(f, "SERVFAIL: {servfail}")?;
        }
        writeln!(f, "Views: {}", self.views.len())?;
        writeln!(f, "Socket counters: {}", self.socket.len())
    }
}

/// Execute the stats command.
pub async fn execute(format: OutputFormat, config: Option<ClientConfig>) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;

    let client = Bind9Client::new(config);
    let stats = client.server_stats().await.map_err(CliError::Net)?;
    print_output(format, &StatsOutput::from(stats));
    Ok(())
}

#[cfg(test)]
mod tests {
    use bind9_sdk::{CounterSet, NamedCounter, ServerStats};

    use super::*;

    #[test]
    fn stats_output_is_one_structured_json_document() {
        let mut stats = ServerStats::default();
        stats.version = Some("9.20.18".into());
        stats.opcodes = CounterSet::new(vec![NamedCounter::new("QUERY", 160)]);
        stats.rcodes = CounterSet::new(vec![NamedCounter::new("SERVFAIL", 5)]);
        stats.socket = CounterSet::new(vec![NamedCounter::new("UDP4Open", 6)]);

        let value = serde_json::to_value(StatsOutput::from(stats)).unwrap();
        assert_eq!(value["version"], "9.20.18");
        assert_eq!(value["queries"], 160);
        assert_eq!(value["servfail"], 5);
        assert_eq!(value["opcodes"]["QUERY"], 160);
        assert_eq!(value["socket"]["UDP4Open"], 6);
    }
}
