// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! rndc command types and response parsing.
//!
//! Each `RndcCommand` variant maps to a BIND9 `rndc` subcommand.
//! The `to_command_string()` method produces the command text sent
//! inside the ISC message `_data` field.

use std::fmt;
use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::record::RecordClass;
use bind9_sdk_core::traits::{FrozenZone, ServerStatus};

/// A zone plus optional DNS class and BIND view selector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneTarget {
    /// Absolute zone name.
    pub zone: DomainName,
    /// DNS class. BIND defaults this to IN.
    pub class: Option<RecordClass>,
    /// BIND view name.
    pub view: Option<String>,
}

impl ZoneTarget {
    /// Create a target for a zone in the default class and view.
    pub fn new(zone: DomainName) -> Self {
        Self {
            zone,
            class: None,
            view: None,
        }
    }

    /// Select an explicit DNS class.
    pub fn with_class(mut self, class: RecordClass) -> Self {
        self.class = Some(class);
        self
    }

    /// Select a BIND view.
    ///
    /// The command serializer inserts class `IN` when a view is provided
    /// without an explicit class because rndc's grammar requires the class
    /// position before the view.
    pub fn with_view(mut self, view: impl Into<String>) -> Self {
        self.view = Some(view.into());
        self
    }

    fn command_args(&self) -> String {
        let mut args = self.zone.to_string();
        if let Some(class) = self.class {
            args.push(' ');
            args.push_str(&class.to_string());
        } else if self.view.is_some() {
            args.push_str(" IN");
        }
        if let Some(view) = &self.view {
            args.push(' ');
            args.push_str(view);
        }
        args
    }
}

/// A section accepted by `rndc dumpdb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpDbCategory {
    /// All database sections.
    All,
    /// Cache database.
    Cache,
    /// Authoritative zones.
    Zones,
    /// Address database.
    Adb,
    /// Bad-cache entries.
    Bad,
    /// Expired cache entries.
    Expired,
    /// Failed-fetch cache entries.
    Fail,
}

impl fmt::Display for DumpDbCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::All => "-all",
            Self::Cache => "-cache",
            Self::Zones => "-zones",
            Self::Adb => "-adb",
            Self::Bad => "-bad",
            Self::Expired => "-expired",
            Self::Fail => "-fail",
        })
    }
}

/// Options for `rndc dumpdb`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DumpDbOptions {
    /// Database categories to dump.
    pub categories: Vec<DumpDbCategory>,
    /// Views to include.
    pub views: Vec<String>,
}

/// On/off switch used by rndc logging commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    On,
    Off,
}

impl fmt::Display for Toggle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::On => "on",
            Self::Off => "off",
        })
    }
}

/// DNSSEC validation control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationAction {
    On,
    Off,
    Status,
}

impl fmt::Display for ValidationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Status => "status",
        })
    }
}

/// RFC 5011 managed-key operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedKeysAction {
    Refresh,
    Status,
    Sync,
}

impl fmt::Display for ManagedKeysAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refresh => "refresh",
            Self::Status => "status",
            Self::Sync => "sync",
        })
    }
}

/// Memory-profiler operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemProfAction {
    On,
    Off,
    Dump,
}

impl fmt::Display for MemProfAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Dump => "dump",
        })
    }
}

/// `serve-stale` control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeStaleAction {
    On,
    Off,
    Reset,
    Status,
}

impl fmt::Display for ServeStaleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Reset => "reset",
            Self::Status => "status",
        })
    }
}

/// DNSSEC signing maintenance operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningAction {
    ClearAll,
    ClearKey {
        key: String,
    },
    List,
    Nsec3Param {
        hash: u8,
        flags: u8,
        iterations: u16,
        salt: String,
    },
    Nsec3ParamNone,
    Serial(u32),
}

/// Values accepted by `rndc tcp-timeouts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpTimeoutValues {
    pub initial: u32,
    pub idle: u32,
    pub keepalive: u32,
    pub advertised: u32,
}

/// DNSSEC policy key selector used by `dnssec -checkds` and `-rollover`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnssecKeySelector {
    /// DNSSEC key tag.
    pub key_tag: u16,
    /// Optional DNSSEC algorithm identifier.
    pub algorithm: Option<String>,
}

impl DnssecKeySelector {
    /// Select a DNSSEC key by key tag.
    pub fn new(key_tag: u16) -> Self {
        Self {
            key_tag,
            algorithm: None,
        }
    }

    /// Disambiguate the key with its DNSSEC algorithm identifier.
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = Some(algorithm.into());
        self
    }
}

/// An rndc command to send to a BIND9 server.
///
/// Covers all rndc commands available in BIND9 9.20.
/// Use `Raw` for commands not yet represented by a named variant.
///
/// # Examples
///
/// ```ignore
/// let cmd = RndcCommand::Status;
/// assert_eq!(cmd.to_command_string(), "status");
///
/// let target = ZoneTarget::new(DomainName::new("example.com.").unwrap());
/// let cmd = RndcCommand::Reload { target: Some(target) };
/// assert_eq!(cmd.to_command_string(), "reload example.com.");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RndcCommand {
    /// Query server status.
    Status,
    /// Reload configuration and either all zones or one selected zone.
    Reload { target: Option<ZoneTarget> },
    /// Refresh a secondary zone from its primary.
    Refresh { target: ZoneTarget },
    /// Force a zone retransfer from primary.
    Retransfer { target: ZoneTarget },
    /// Freeze all dynamic zones or one selected zone.
    Freeze { target: Option<ZoneTarget> },
    /// Thaw all dynamic zones or one selected zone.
    Thaw { target: Option<ZoneTarget> },
    /// Synchronize zone journal to zone file.
    /// If `zone` is `None`, syncs all zones.
    Sync {
        /// Remove journal files after synchronizing.
        clean: bool,
        /// Optional zone target; `None` synchronizes all dynamic zones.
        target: Option<ZoneTarget>,
    },
    /// Flush all caches or one view's cache.
    Flush { view: Option<String> },
    /// Flush a specific name from cache.
    FlushName {
        name: DomainName,
        view: Option<String>,
    },
    /// Flush a name and all names below it from cache.
    FlushTree {
        name: DomainName,
        view: Option<String>,
    },
    /// Dump statistics to the statistics file.
    Stats,
    /// Dump the database to the dump file.
    DumpDb { options: DumpDbOptions },
    /// Send NOTIFY for a zone.
    Notify { target: ZoneTarget },
    /// Set debug trace level.
    /// If `level` is `None`, increments by 1.
    Trace { level: Option<u32> },
    /// Disable debug tracing.
    NoTrace,
    /// Reload configuration and add/remove zones.
    Reconfig,
    /// Sign a zone with DNSSEC keys.
    Sign { target: ZoneTarget },
    /// Maintain DNSSEC signing state.
    Signing {
        action: SigningAction,
        target: ZoneTarget,
    },
    /// Control DNSSEC validation.
    Validation {
        action: ValidationAction,
        view: Option<String>,
    },
    /// Add a zone at runtime.
    AddZone { target: ZoneTarget, config: String },
    /// Modify a zone's configuration at runtime.
    ModZone { target: ZoneTarget, config: String },
    /// Delete a zone at runtime.
    DelZone { target: ZoneTarget, clean: bool },
    /// Show a zone's runtime configuration.
    ShowZone { target: ZoneTarget },
    /// RFC 5011 managed-key operation.
    ManagedKeys {
        action: ManagedKeysAction,
        class: Option<RecordClass>,
        view: Option<String>,
    },
    /// Query zone status.
    ZoneStatus { target: ZoneTarget },
    /// List all negative trust anchors.
    NtaList,
    /// Add a negative trust anchor.
    NtaAdd {
        domain: DomainName,
        lifetime: Option<Duration>,
        force: bool,
        view: Option<String>,
    },
    /// Remove a negative trust anchor.
    NtaRemove {
        domain: DomainName,
        view: Option<String>,
    },
    /// Query DNSSEC status for a zone.
    DnssecStatus { target: ZoneTarget },
    /// Mark DS publication state for a zone key.
    DnssecCheckDs {
        target: ZoneTarget,
        state: DsState,
        key: Option<DnssecKeySelector>,
        when: Option<String>,
    },
    /// Update DNSSEC keys without signing immediately.
    LoadKeys { target: ZoneTarget },
    /// Manually roll a DNSSEC policy key.
    DnssecRollover {
        target: ZoneTarget,
        key: DnssecKeySelector,
        when: Option<String>,
    },
    /// Reopen the DNSTAP output file.
    DnstapReopen,
    /// Roll DNSTAP output files, optionally retaining `count` files.
    DnstapRoll { count: Option<u32> },
    /// Show fetch-limit throttling state.
    FetchLimit { view: Option<String> },
    /// Save pending updates and stop named.
    Stop { report_pid: bool },
    /// Stop named without saving pending updates.
    Halt { report_pid: bool },
    /// Import a signed-key-response file for offline KSK signing.
    SkrImport { file: String, target: ZoneTarget },
    /// Control or dump memory profiling.
    MemProf { action: Option<MemProfAction> },
    /// Toggle or explicitly set query logging.
    QueryLog { action: Option<Toggle> },
    /// Dump currently recursing queries.
    Recursing,
    /// Reset selected statistics counters.
    ResetStats { counters: Vec<String> },
    /// Toggle or explicitly set response logging.
    ResponseLog { action: Option<Toggle> },
    /// Rescan network interfaces.
    Scan,
    /// Write security roots for the selected views.
    SecRoots { views: Vec<String> },
    /// Control stale-answer serving.
    ServeStale {
        action: Option<ServeStaleAction>,
        class: Option<RecordClass>,
        view: Option<String>,
    },
    /// Display or update TCP timeout values.
    TcpTimeouts { values: Option<TcpTimeoutValues> },
    /// Raw command string -- escape hatch for commands not yet in the enum.
    Raw(String),
}

impl RndcCommand {
    /// Convert to the command string sent in the rndc wire protocol.
    ///
    /// This is the text placed in the `_data` map's `type` field of the
    /// ISC binary message.
    pub fn to_command_string(&self) -> String {
        match self {
            Self::Status => "status".to_string(),
            Self::Reload { target } => command_with_target("reload", target.as_ref()),
            Self::Refresh { target } => command_with_target("refresh", Some(target)),
            Self::Retransfer { target } => command_with_target("retransfer", Some(target)),
            Self::Freeze { target } => command_with_target("freeze", target.as_ref()),
            Self::Thaw { target } => command_with_target("thaw", target.as_ref()),
            Self::Sync { clean, target } => {
                let mut command = String::from("sync");
                if *clean {
                    command.push_str(" -clean");
                }
                if let Some(target) = target {
                    command.push(' ');
                    command.push_str(&target.command_args());
                }
                command
            }
            Self::Flush { view } => command_with_optional_token("flush", view.as_deref()),
            Self::FlushName { name, view } => {
                command_with_name_and_view("flushname", name, view.as_deref())
            }
            Self::FlushTree { name, view } => {
                command_with_name_and_view("flushtree", name, view.as_deref())
            }
            Self::Stats => "stats".to_string(),
            Self::DumpDb { options } => {
                let mut command = String::from("dumpdb");
                for category in &options.categories {
                    command.push(' ');
                    command.push_str(&category.to_string());
                }
                for view in &options.views {
                    command.push(' ');
                    command.push_str(view);
                }
                command
            }
            Self::Notify { target } => command_with_target("notify", Some(target)),
            Self::Trace { level: Some(l) } => format!("trace {l}"),
            Self::Trace { level: None } => "trace".to_string(),
            Self::NoTrace => "notrace".to_string(),
            Self::Reconfig => "reconfig".to_string(),
            Self::Sign { target } => command_with_target("sign", Some(target)),
            Self::Signing { action, target } => signing_command(action, target),
            Self::Validation { action, view } => {
                command_with_optional_token(&format!("validation {action}"), view.as_deref())
            }
            Self::AddZone { target, config } => {
                format!("addzone {} {config}", target.command_args())
            }
            Self::ModZone { target, config } => {
                format!("modzone {} {config}", target.command_args())
            }
            Self::DelZone { target, clean } => {
                let command = if *clean { "delzone -clean" } else { "delzone" };
                command_with_target(command, Some(target))
            }
            Self::ShowZone { target } => command_with_target("showzone", Some(target)),
            Self::ManagedKeys {
                action,
                class,
                view,
            } => command_with_class_and_view(
                &format!("managed-keys {action}"),
                *class,
                view.as_deref(),
            ),
            Self::ZoneStatus { target } => command_with_target("zonestatus", Some(target)),
            Self::NtaList => "nta -dump".to_string(),
            Self::NtaAdd {
                domain,
                lifetime,
                force,
                view,
            } => {
                let mut command = String::from("nta");
                if let Some(lifetime) = lifetime {
                    command.push_str(" -lifetime ");
                    command.push_str(&lifetime.as_secs().to_string());
                }
                if *force {
                    command.push_str(" -force");
                }
                command.push(' ');
                command.push_str(&domain.to_string());
                if let Some(view) = view {
                    command.push(' ');
                    command.push_str(view);
                }
                command
            }
            Self::NtaRemove { domain, view } => {
                let mut command = format!("nta -remove {domain}");
                if let Some(view) = view {
                    command.push(' ');
                    command.push_str(view);
                }
                command
            }
            Self::DnssecStatus { target } => command_with_target("dnssec -status", Some(target)),
            Self::DnssecCheckDs {
                target,
                state,
                key,
                when,
            } => {
                let mut command = String::from("dnssec -checkds");
                append_key_options(&mut command, key.as_ref(), when.as_deref());
                command.push(' ');
                command.push_str(&state.to_string());
                command.push(' ');
                command.push_str(&target.command_args());
                command
            }
            Self::LoadKeys { target } => format!("loadkeys {}", target.command_args()),
            Self::DnssecRollover { target, key, when } => {
                let mut command = format!("dnssec -rollover -key {}", key.key_tag);
                if let Some(algorithm) = &key.algorithm {
                    command.push_str(" -alg ");
                    command.push_str(algorithm);
                }
                if let Some(when) = when {
                    command.push_str(" -when ");
                    command.push_str(when);
                }
                command.push(' ');
                command.push_str(&target.command_args());
                command
            }
            Self::DnstapReopen => "dnstap -reopen".into(),
            Self::DnstapRoll { count } => command_with_optional_value("dnstap -roll", *count),
            Self::FetchLimit { view } => command_with_optional_token("fetchlimit", view.as_deref()),
            Self::Stop { report_pid } => {
                if *report_pid {
                    "stop -p".into()
                } else {
                    "stop".into()
                }
            }
            Self::Halt { report_pid } => {
                if *report_pid {
                    "halt -p".into()
                } else {
                    "halt".into()
                }
            }
            Self::SkrImport { file, target } => {
                format!("skr -import {file} {}", target.command_args())
            }
            Self::MemProf { action } => match action {
                Some(action) => format!("memprof {action}"),
                None => "memprof".into(),
            },
            Self::QueryLog { action } => match action {
                Some(action) => format!("querylog {action}"),
                None => "querylog".into(),
            },
            Self::Recursing => "recursing".into(),
            Self::ResetStats { counters } => {
                let mut command = String::from("reset-stats");
                for counter in counters {
                    command.push(' ');
                    command.push_str(counter);
                }
                command
            }
            Self::ResponseLog { action } => match action {
                Some(action) => format!("responselog {action}"),
                None => "responselog".into(),
            },
            Self::Scan => "scan".into(),
            Self::SecRoots { views } => {
                let mut command = String::from("secroots");
                for view in views {
                    command.push(' ');
                    command.push_str(view);
                }
                command
            }
            Self::ServeStale {
                action,
                class,
                view,
            } => {
                let base = action
                    .map(|action| format!("serve-stale {action}"))
                    .unwrap_or_else(|| "serve-stale".into());
                command_with_class_and_view(&base, *class, view.as_deref())
            }
            Self::TcpTimeouts { values } => match values {
                Some(values) => format!(
                    "tcp-timeouts {} {} {} {}",
                    values.initial, values.idle, values.keepalive, values.advertised
                ),
                None => "tcp-timeouts".into(),
            },
            Self::Raw(cmd) => cmd.clone(),
        }
    }
}

fn command_with_target(command: &str, target: Option<&ZoneTarget>) -> String {
    match target {
        Some(target) => format!("{command} {}", target.command_args()),
        None => command.into(),
    }
}

fn command_with_optional_token(command: &str, token: Option<&str>) -> String {
    match token {
        Some(token) => format!("{command} {token}"),
        None => command.into(),
    }
}

fn command_with_optional_value(command: &str, value: Option<u32>) -> String {
    match value {
        Some(value) => format!("{command} {value}"),
        None => command.into(),
    }
}

fn command_with_name_and_view(command: &str, name: &DomainName, view: Option<&str>) -> String {
    command_with_optional_token(&format!("{command} {name}"), view)
}

fn command_with_class_and_view(
    command: &str,
    class: Option<RecordClass>,
    view: Option<&str>,
) -> String {
    let mut output = String::from(command);
    if let Some(class) = class {
        output.push(' ');
        output.push_str(&class.to_string());
    } else if view.is_some() {
        output.push_str(" IN");
    }
    if let Some(view) = view {
        output.push(' ');
        output.push_str(view);
    }
    output
}

fn append_key_options(command: &mut String, key: Option<&DnssecKeySelector>, when: Option<&str>) {
    if let Some(key) = key {
        command.push_str(" -key ");
        command.push_str(&key.key_tag.to_string());
        if let Some(algorithm) = &key.algorithm {
            command.push_str(" -alg ");
            command.push_str(algorithm);
        }
    }
    if let Some(when) = when {
        command.push_str(" -when ");
        command.push_str(when);
    }
}

fn signing_command(action: &SigningAction, target: &ZoneTarget) -> String {
    let operation = match action {
        SigningAction::ClearAll => "-clear all".into(),
        SigningAction::ClearKey { key } => format!("-clear {key}"),
        SigningAction::List => "-list".into(),
        SigningAction::Nsec3Param {
            hash,
            flags,
            iterations,
            salt,
        } => format!("-nsec3param {hash} {flags} {iterations} {salt}"),
        SigningAction::Nsec3ParamNone => "-nsec3param none".into(),
        SigningAction::Serial(serial) => format!("-serial {serial}"),
    };
    format!("signing {operation} {}", target.command_args())
}

/// Parent DS state reported to BIND's DNSSEC policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsState {
    /// The DS record has been published in the parent zone.
    Published,
    /// The DS record has been withdrawn from the parent zone.
    Withdrawn,
}

impl fmt::Display for DsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Published => f.write_str("published"),
            Self::Withdrawn => f.write_str("withdrawn"),
        }
    }
}

impl fmt::Display for RndcCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_command_string())
    }
}

/// Response from an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RndcResponse {
    /// The text output from the server (may be multi-line).
    pub text: String,
    /// Parsed result status.
    pub result: RndcResult,
}

/// Result status of an rndc command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RndcResult {
    /// Command succeeded.
    Success,
    /// Command failed with an error.
    Error {
        /// Numeric error code from the server (if provided).
        code: u32,
        /// Human-readable error message.
        message: String,
    },
}

impl RndcResponse {
    /// Whether the command succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self.result, RndcResult::Success)
    }

    /// Parse a response from the raw text returned by BIND9.
    ///
    /// BIND9 rndc responses typically start with "rndc: " for errors,
    /// or contain the result text directly for successful commands.
    ///
    /// TODO: Verify response format against BIND9 source / wire captures.
    pub(crate) fn from_text(text: &str) -> Self {
        let is_error = text.starts_with("rndc: ")
            || text.starts_with("unknown command")
            || text.starts_with("not found");

        if is_error {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Error {
                    code: 1,
                    message: text.to_string(),
                },
            }
        } else {
            RndcResponse {
                text: text.to_string(),
                result: RndcResult::Success,
            }
        }
    }
}

/// Parse the output of `rndc status` into a `ServerStatus` struct.
///
/// # Expected format (BIND9 9.20)
///
/// ```text
/// version: BIND 9.20.0 (Stable Release) <id:abc123>
/// running on myhost: Linux x86_64
/// boot time: Mon, 01 Jan 2026 00:00:00 GMT
/// last configured: Mon, 01 Jan 2026 00:00:00 GMT
/// configuration file: /etc/named.conf
/// CPUs found: 4
/// worker threads: 4
/// number of zones: 42 (0 automatic)
/// debug level: 0
/// server is up and running
/// ```
///
/// TODO: Verify format against BIND9 9.20 output. The format may vary
/// slightly between BIND9 minor versions.
pub(crate) fn parse_server_status(text: &str) -> ServerStatus {
    let version = extract_field(text, "version:").unwrap_or_else(|| "unknown".to_string());

    let running_since = extract_field(text, "boot time:");

    let zone_count = extract_field(text, "number of zones:")
        .and_then(|s| {
            // "42 (0 automatic)" -> try to parse the first number
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let server_up = text.contains("server is up and running");

    ServerStatus::new(
        version,
        running_since,
        zone_count,
        server_up,
        text.to_string(),
    )
}

/// Extract the value after a field label from multi-line text.
///
/// Given text like "version: BIND 9.20.0\nboot time: Mon..." and
/// label "version:", returns Some("BIND 9.20.0").
fn extract_field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(label) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Construct a `FrozenZone` from the zone name used in a freeze command.
///
/// The rndc `freeze` command response does not contain structured data --
/// it just confirms success. The `FrozenZone` is constructed from the
/// command parameters.
pub(crate) fn make_frozen_zone(zone_name: &DomainName) -> FrozenZone {
    FrozenZone::new(zone_name.clone(), RecordClass::IN)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- RndcCommand serialization tests --

    fn target(name: &str) -> ZoneTarget {
        ZoneTarget::new(DomainName::new(name).unwrap())
    }

    #[test]
    fn command_status() {
        assert_eq!(RndcCommand::Status.to_command_string(), "status");
    }

    #[test]
    fn command_reload() {
        assert_eq!(
            RndcCommand::Reload { target: None }.to_command_string(),
            "reload"
        );
    }

    #[test]
    fn command_reload_zone() {
        let cmd = RndcCommand::Reload {
            target: Some(target("example.com.")),
        };
        assert_eq!(cmd.to_command_string(), "reload example.com.");
    }

    #[test]
    fn command_refresh() {
        let cmd = RndcCommand::Refresh {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "refresh example.com.");
    }

    #[test]
    fn command_retransfer() {
        let cmd = RndcCommand::Retransfer {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "retransfer example.com.");
    }

    #[test]
    fn command_freeze() {
        let cmd = RndcCommand::Freeze {
            target: Some(target("example.com.")),
        };
        assert_eq!(cmd.to_command_string(), "freeze example.com.");
    }

    #[test]
    fn command_thaw() {
        let cmd = RndcCommand::Thaw {
            target: Some(target("example.com.")),
        };
        assert_eq!(cmd.to_command_string(), "thaw example.com.");
    }

    #[test]
    fn command_sync_all() {
        let cmd = RndcCommand::Sync {
            clean: false,
            target: None,
        };
        assert_eq!(cmd.to_command_string(), "sync");
    }

    #[test]
    fn command_sync_zone() {
        let cmd = RndcCommand::Sync {
            clean: false,
            target: Some(ZoneTarget::new(DomainName::new("example.com.").unwrap())),
        };
        assert_eq!(cmd.to_command_string(), "sync example.com.");
    }

    #[test]
    fn command_flush() {
        assert_eq!(
            RndcCommand::Flush { view: None }.to_command_string(),
            "flush"
        );
    }

    #[test]
    fn command_flush_name() {
        let cmd = RndcCommand::FlushName {
            name: DomainName::new("stale.example.com.").unwrap(),
            view: None,
        };
        assert_eq!(cmd.to_command_string(), "flushname stale.example.com.");
    }

    #[test]
    fn command_stats() {
        assert_eq!(RndcCommand::Stats.to_command_string(), "stats");
    }

    #[test]
    fn command_dumpdb() {
        assert_eq!(
            RndcCommand::DumpDb {
                options: DumpDbOptions::default()
            }
            .to_command_string(),
            "dumpdb"
        );
    }

    #[test]
    fn command_notify() {
        let cmd = RndcCommand::Notify {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "notify example.com.");
    }

    #[test]
    fn command_trace_increment() {
        let cmd = RndcCommand::Trace { level: None };
        assert_eq!(cmd.to_command_string(), "trace");
    }

    #[test]
    fn command_trace_level() {
        let cmd = RndcCommand::Trace { level: Some(3) };
        assert_eq!(cmd.to_command_string(), "trace 3");
    }

    #[test]
    fn command_notrace() {
        assert_eq!(RndcCommand::NoTrace.to_command_string(), "notrace");
    }

    #[test]
    fn command_reconfig() {
        assert_eq!(RndcCommand::Reconfig.to_command_string(), "reconfig");
    }

    #[test]
    fn command_sign() {
        let cmd = RndcCommand::Sign {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "sign example.com.");
    }

    #[test]
    fn command_validation_on() {
        let cmd = RndcCommand::Validation {
            action: ValidationAction::On,
            view: None,
        };
        assert_eq!(cmd.to_command_string(), "validation on");
    }

    #[test]
    fn command_validation_off() {
        let cmd = RndcCommand::Validation {
            action: ValidationAction::Off,
            view: None,
        };
        assert_eq!(cmd.to_command_string(), "validation off");
    }

    #[test]
    fn command_addzone() {
        let cmd = RndcCommand::AddZone {
            target: target("new.example.com."),
            config: "{ type primary; file \"new.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "addzone new.example.com. { type primary; file \"new.zone\"; };"
        );
    }

    #[test]
    fn command_modzone() {
        let cmd = RndcCommand::ModZone {
            target: target("example.com."),
            config: "{ type primary; file \"updated.zone\"; };".into(),
        };
        assert_eq!(
            cmd.to_command_string(),
            "modzone example.com. { type primary; file \"updated.zone\"; };"
        );
    }

    #[test]
    fn command_delzone() {
        let cmd = RndcCommand::DelZone {
            target: target("old.example.com."),
            clean: false,
        };
        assert_eq!(cmd.to_command_string(), "delzone old.example.com.");
    }

    #[test]
    fn command_showzone() {
        let cmd = RndcCommand::ShowZone {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "showzone example.com.");
    }

    #[test]
    fn command_managed_keys() {
        let cmd = RndcCommand::ManagedKeys {
            action: ManagedKeysAction::Status,
            class: None,
            view: None,
        };
        assert_eq!(cmd.to_command_string(), "managed-keys status");
    }

    #[test]
    fn command_zonestatus() {
        let cmd = RndcCommand::ZoneStatus {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "zonestatus example.com.");
    }

    #[test]
    fn command_nta_list() {
        let cmd = RndcCommand::NtaList;
        assert_eq!(cmd.to_command_string(), "nta -dump");
    }

    #[test]
    fn command_nta_add() {
        let cmd = RndcCommand::NtaAdd {
            domain: DomainName::new("bad.example.com.").unwrap(),
            lifetime: Some(Duration::from_secs(3600)),
            force: false,
            view: None,
        };
        assert_eq!(
            cmd.to_command_string(),
            "nta -lifetime 3600 bad.example.com."
        );
    }

    #[test]
    fn command_nta_remove() {
        let cmd = RndcCommand::NtaRemove {
            domain: DomainName::new("bad.example.com.").unwrap(),
            view: None,
        };
        assert_eq!(cmd.to_command_string(), "nta -remove bad.example.com.");
    }

    #[test]
    fn command_dnssec_status() {
        let cmd = RndcCommand::DnssecStatus {
            target: target("example.com."),
        };
        assert_eq!(cmd.to_command_string(), "dnssec -status example.com.");
    }

    #[test]
    fn command_dnssec_checkds() {
        let published = RndcCommand::DnssecCheckDs {
            target: target("example.com."),
            state: DsState::Published,
            key: None,
            when: None,
        };
        assert_eq!(
            published.to_command_string(),
            "dnssec -checkds published example.com."
        );

        let withdrawn = RndcCommand::DnssecCheckDs {
            target: target("example.com."),
            state: DsState::Withdrawn,
            key: None,
            when: None,
        };
        assert_eq!(
            withdrawn.to_command_string(),
            "dnssec -checkds withdrawn example.com."
        );
    }

    #[test]
    fn command_raw() {
        let cmd = RndcCommand::Raw("custom-command arg1 arg2".into());
        assert_eq!(cmd.to_command_string(), "custom-command arg1 arg2");
    }

    #[test]
    fn command_display_matches_command_string() {
        let cmd = RndcCommand::Status;
        assert_eq!(format!("{cmd}"), cmd.to_command_string());
    }

    #[test]
    fn command_loadkeys_uses_typed_zone_target() {
        let target = ZoneTarget::new(DomainName::new("example.com.").unwrap())
            .with_class(RecordClass::IN)
            .with_view("external");
        assert_eq!(
            RndcCommand::LoadKeys { target }.to_command_string(),
            "loadkeys example.com. IN external"
        );
    }

    #[test]
    fn command_dnssec_rollover_includes_key_algorithm_and_time() {
        let command = RndcCommand::DnssecRollover {
            target: ZoneTarget::new(DomainName::new("example.com.").unwrap()),
            key: DnssecKeySelector::new(12345).with_algorithm("13"),
            when: Some("20260620010000".into()),
        };
        assert_eq!(
            command.to_command_string(),
            "dnssec -rollover -key 12345 -alg 13 -when 20260620010000 example.com."
        );
    }

    #[test]
    fn command_shutdown_variants_preserve_save_semantics() {
        assert_eq!(
            RndcCommand::Stop { report_pid: false }.to_command_string(),
            "stop"
        );
        assert_eq!(
            RndcCommand::Stop { report_pid: true }.to_command_string(),
            "stop -p"
        );
        assert_eq!(
            RndcCommand::Halt { report_pid: false }.to_command_string(),
            "halt"
        );
        assert_eq!(
            RndcCommand::Halt { report_pid: true }.to_command_string(),
            "halt -p"
        );
    }

    #[test]
    fn command_querylog_supports_toggle_and_explicit_state() {
        assert_eq!(
            RndcCommand::QueryLog { action: None }.to_command_string(),
            "querylog"
        );
        assert_eq!(
            RndcCommand::QueryLog {
                action: Some(Toggle::On)
            }
            .to_command_string(),
            "querylog on"
        );
        assert_eq!(
            RndcCommand::QueryLog {
                action: Some(Toggle::Off)
            }
            .to_command_string(),
            "querylog off"
        );
    }

    #[test]
    fn command_recursing_and_secroots() {
        assert_eq!(RndcCommand::Recursing.to_command_string(), "recursing");
        assert_eq!(
            RndcCommand::SecRoots {
                views: vec!["_default".into(), "internal".into()]
            }
            .to_command_string(),
            "secroots _default internal"
        );
    }

    #[test]
    fn command_dumpdb_has_typed_categories_and_views() {
        let command = RndcCommand::DumpDb {
            options: DumpDbOptions {
                categories: vec![DumpDbCategory::Cache, DumpDbCategory::Expired],
                views: vec!["internal".into()],
            },
        };
        assert_eq!(
            command.to_command_string(),
            "dumpdb -cache -expired internal"
        );
    }

    #[test]
    fn command_sync_clean_all_and_targeted_zone() {
        assert_eq!(
            RndcCommand::Sync {
                clean: true,
                target: None
            }
            .to_command_string(),
            "sync -clean"
        );
        assert_eq!(
            RndcCommand::Sync {
                clean: false,
                target: Some(ZoneTarget::new(DomainName::new("example.com.").unwrap()))
            }
            .to_command_string(),
            "sync example.com."
        );
    }

    #[test]
    fn command_remaining_bind_9_20_surface_serializes_exactly() {
        let zone = || target("example.com.");

        assert_eq!(
            RndcCommand::DnstapReopen.to_command_string(),
            "dnstap -reopen"
        );
        assert_eq!(
            RndcCommand::DnstapRoll { count: Some(4) }.to_command_string(),
            "dnstap -roll 4"
        );
        assert_eq!(
            RndcCommand::FetchLimit {
                view: Some("internal".into())
            }
            .to_command_string(),
            "fetchlimit internal"
        );
        assert_eq!(
            RndcCommand::FlushTree {
                name: DomainName::new("example.com.").unwrap(),
                view: Some("internal".into())
            }
            .to_command_string(),
            "flushtree example.com. internal"
        );
        assert_eq!(
            RndcCommand::Freeze { target: None }.to_command_string(),
            "freeze"
        );
        assert_eq!(
            RndcCommand::Thaw { target: None }.to_command_string(),
            "thaw"
        );
        assert_eq!(
            RndcCommand::SkrImport {
                file: "/var/lib/bind/offline.skr".into(),
                target: zone()
            }
            .to_command_string(),
            "skr -import /var/lib/bind/offline.skr example.com."
        );
        assert_eq!(
            RndcCommand::ManagedKeys {
                action: ManagedKeysAction::Refresh,
                class: None,
                view: Some("internal".into())
            }
            .to_command_string(),
            "managed-keys refresh IN internal"
        );
        assert_eq!(
            RndcCommand::MemProf {
                action: Some(MemProfAction::Dump)
            }
            .to_command_string(),
            "memprof dump"
        );
        assert_eq!(
            RndcCommand::ResetStats {
                counters: vec!["QrySuccess".into(), "QryFailure".into()]
            }
            .to_command_string(),
            "reset-stats QrySuccess QryFailure"
        );
        assert_eq!(
            RndcCommand::ResponseLog {
                action: Some(Toggle::On)
            }
            .to_command_string(),
            "responselog on"
        );
        assert_eq!(RndcCommand::Scan.to_command_string(), "scan");
        assert_eq!(
            RndcCommand::ServeStale {
                action: Some(ServeStaleAction::Status),
                class: None,
                view: Some("internal".into())
            }
            .to_command_string(),
            "serve-stale status IN internal"
        );
        assert_eq!(
            RndcCommand::Signing {
                action: SigningAction::Nsec3Param {
                    hash: 1,
                    flags: 0,
                    iterations: 10,
                    salt: "A1B2".into()
                },
                target: zone()
            }
            .to_command_string(),
            "signing -nsec3param 1 0 10 A1B2 example.com."
        );
        assert_eq!(
            RndcCommand::TcpTimeouts {
                values: Some(TcpTimeoutValues {
                    initial: 30,
                    idle: 300,
                    keepalive: 30,
                    advertised: 30
                })
            }
            .to_command_string(),
            "tcp-timeouts 30 300 30 30"
        );
        assert_eq!(
            RndcCommand::Validation {
                action: ValidationAction::Status,
                view: Some("internal".into())
            }
            .to_command_string(),
            "validation status internal"
        );
        assert_eq!(
            RndcCommand::DelZone {
                target: zone(),
                clean: true
            }
            .to_command_string(),
            "delzone -clean example.com."
        );
        assert_eq!(
            RndcCommand::DnssecCheckDs {
                target: zone(),
                state: DsState::Published,
                key: Some(DnssecKeySelector::new(12345).with_algorithm("13")),
                when: Some("20260620010000".into())
            }
            .to_command_string(),
            "dnssec -checkds -key 12345 -alg 13 -when 20260620010000 published example.com."
        );
        assert_eq!(
            RndcCommand::NtaAdd {
                domain: DomainName::new("broken.example.").unwrap(),
                lifetime: Some(Duration::from_secs(900)),
                force: true,
                view: Some("internal".into())
            }
            .to_command_string(),
            "nta -lifetime 900 -force broken.example. internal"
        );
    }

    // -- RndcResponse tests --

    #[test]
    fn response_success() {
        let resp = RndcResponse::from_text("version: BIND 9.20.0\nserver is up and running");
        assert!(resp.is_success());
        assert!(resp.text.contains("BIND 9.20.0"));
    }

    #[test]
    fn response_error_rndc_prefix() {
        let resp = RndcResponse::from_text("rndc: connect failed: connection refused");
        assert!(!resp.is_success());
        if let RndcResult::Error { message, .. } = &resp.result {
            assert!(message.contains("connect failed"));
        } else {
            panic!("expected error result");
        }
    }

    #[test]
    fn response_is_success_returns_false_for_error() {
        let resp = RndcResponse {
            text: "failed".into(),
            result: RndcResult::Error {
                code: 1,
                message: "failed".into(),
            },
        };
        assert!(!resp.is_success());
    }

    #[test]
    fn response_unknown_command() {
        let resp = RndcResponse::from_text("unknown command");
        assert!(!resp.is_success());
    }

    #[test]
    fn response_not_found() {
        let resp = RndcResponse::from_text("not found");
        assert!(!resp.is_success());
    }

    #[test]
    fn response_zone_name_with_error_is_not_false_positive() {
        // Zone names containing "error" should NOT be treated as errors (F-015)
        let resp = RndcResponse::from_text("zone error.example.com/IN: loaded serial 2024010101");
        assert!(
            resp.is_success(),
            "zone name containing 'error' must not trigger false positive"
        );
    }

    // -- ServerStatus parsing tests --

    #[test]
    fn parse_status_full_output() {
        let text = "\
version: BIND 9.20.0 (Stable Release) <id:abc123>
running on myhost: Linux x86_64
boot time: Mon, 01 Jan 2026 00:00:00 GMT
last configured: Mon, 01 Jan 2026 00:00:00 GMT
configuration file: /etc/named.conf
CPUs found: 4
worker threads: 4
number of zones: 42 (0 automatic)
debug level: 0
xfers running: 0
server is up and running";

        let status = parse_server_status(text);
        assert!(status.version.contains("BIND 9.20.0"));
        assert_eq!(
            status.running_since,
            Some("Mon, 01 Jan 2026 00:00:00 GMT".into())
        );
        assert_eq!(status.zone_count, 42);
        assert!(status.server_up);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn parse_status_missing_version() {
        let text = "server is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.version, "unknown");
        assert!(status.server_up);
    }

    #[test]
    fn parse_status_server_down() {
        let text = "version: BIND 9.20.0\nserver is shutting down";
        let status = parse_server_status(text);
        assert!(!status.server_up);
    }

    #[test]
    fn parse_status_no_boot_time() {
        let text = "version: BIND 9.20.0\nserver is up and running";
        let status = parse_server_status(text);
        assert_eq!(status.running_since, None);
    }

    #[test]
    fn parse_status_preserves_raw_text() {
        let text = "version: BIND 9.20.0\nsome custom output";
        let status = parse_server_status(text);
        assert_eq!(status.raw_text, text);
    }

    #[test]
    fn extract_field_finds_label() {
        let text = "version: BIND 9.20.0\nboot time: Monday";
        assert_eq!(extract_field(text, "version:"), Some("BIND 9.20.0".into()));
        assert_eq!(extract_field(text, "boot time:"), Some("Monday".into()));
    }

    #[test]
    fn extract_field_returns_none_for_missing() {
        let text = "version: BIND 9.20.0";
        assert_eq!(extract_field(text, "missing:"), None);
    }

    #[test]
    fn extract_field_handles_leading_whitespace() {
        let text = "  version: BIND 9.20.0";
        assert_eq!(extract_field(text, "version:"), Some("BIND 9.20.0".into()));
    }

    // -- FrozenZone construction tests --

    #[test]
    fn make_frozen_zone_from_domain_name() {
        let name = DomainName::new("example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
        assert_eq!(frozen.class, RecordClass::IN);
    }

    #[test]
    fn make_frozen_zone_preserves_name() {
        let name = DomainName::new("sub.domain.example.com.").unwrap();
        let frozen = make_frozen_zone(&name);
        assert_eq!(frozen.name, name);
    }
}
