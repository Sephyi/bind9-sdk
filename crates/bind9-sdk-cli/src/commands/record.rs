// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! DNS record management CLI commands.

use clap::Subcommand;

use bind9_sdk::core::protocol::{Rcode, RecordType};
use bind9_sdk::core::update::UpdateBuilder;
use bind9_sdk::core::zone::ZoneFile;
use bind9_sdk::net::{ClientConfig, NsUpdateSender};
use bind9_sdk::{DomainName, RecordClass};

use crate::commands::OutputFormat;
use crate::error::CliError;
use crate::output::{print_message, print_success};

/// Record management subcommands.
#[derive(Subcommand, Debug)]
pub enum RecordCommand {
    /// Add a DNS record via RFC 2136 dynamic update.
    Add {
        /// Zone name (e.g., `example.com`).
        zone: String,
        /// Record name (e.g., `www.example.com`).
        name: String,
        /// Record type (e.g., `A`, `AAAA`, `CNAME`).
        #[arg(name = "type")]
        rtype: String,
        /// Record data (e.g., `192.0.2.1`).
        data: String,
        /// TTL in seconds (default: 3600).
        #[arg(long, default_value = "3600")]
        ttl: u32,
    },

    /// Delete a DNS record via RFC 2136 dynamic update.
    Delete {
        /// Zone name (e.g., `example.com`).
        zone: String,
        /// Record name (e.g., `www.example.com`).
        name: String,
        /// Record type (e.g., `A`, `AAAA`, `CNAME`).
        #[arg(name = "type")]
        rtype: String,
        /// Record data (optional — if omitted, deletes all records of the given type).
        data: Option<String>,
    },
}

/// Execute a record subcommand.
pub async fn execute(
    cmd: &RecordCommand,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    match cmd {
        RecordCommand::Add {
            zone,
            name,
            rtype,
            data,
            ttl,
        } => execute_add(zone, name, rtype, data, *ttl, format, config).await,
        RecordCommand::Delete {
            zone,
            name,
            rtype,
            data,
        } => execute_delete(zone, name, rtype, data.as_deref(), format, config).await,
    }
}

async fn execute_add(
    zone: &str,
    name: &str,
    rtype: &str,
    data: &str,
    ttl: u32,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let dns_addr = config.dns_addr.ok_or_else(|| {
        CliError::Config("dns_port must be configured for record operations".into())
    })?;
    let zone_name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;

    // Parse the record by constructing a minimal zone file string and parsing it.
    // This reuses the zone parser to handle any record type string.
    let zone_line = format!("$ORIGIN {zone}\n$TTL {ttl}\n{name} {ttl} IN {rtype} {data}\n");
    let zone_file = ZoneFile::parse(&zone_line).map_err(CliError::Core)?;
    let record = zone_file
        .zone
        .records
        .first()
        .ok_or_else(|| CliError::Config("failed to parse record from input".into()))?
        .clone();

    // Build the RFC 2136 dynamic update message.
    let update = UpdateBuilder::new(zone_name.clone(), RecordClass::IN)
        .add_record(record.clone())
        .sign_now(&config.rndc_key)
        .build();

    // Send the update via DNS.
    let sender = NsUpdateSender::new(dns_addr);
    let result = sender
        .send(&update, Some(&config.rndc_key))
        .await
        .map_err(CliError::Net)?;

    if result.rcode == Rcode::NoError {
        print_success(
            format,
            &format!(
                "added: {} {} IN {} {} (zone: {zone_name})",
                record.name, record.ttl, rtype, data
            ),
        );
    } else {
        print_message(
            format,
            &format!(
                "server rejected update with RCODE: {} (zone: {zone_name})",
                result.rcode
            ),
        );
    }
    Ok(())
}

async fn execute_delete(
    zone: &str,
    name: &str,
    rtype: &str,
    data: Option<&str>,
    format: OutputFormat,
    config: Option<ClientConfig>,
) -> Result<(), CliError> {
    let config = config.ok_or_else(|| {
        CliError::Config(
            "server connection required — provide --server and --key-* flags or a config file"
                .into(),
        )
    })?;
    let dns_addr = config.dns_addr.ok_or_else(|| {
        CliError::Config("dns_port must be configured for record operations".into())
    })?;
    let zone_name =
        DomainName::new(zone).map_err(|e| CliError::Config(format!("invalid zone name: {e}")))?;
    let record_name =
        DomainName::new(name).map_err(|e| CliError::Config(format!("invalid record name: {e}")))?;

    let builder = UpdateBuilder::new(zone_name.clone(), RecordClass::IN);

    let builder = if let Some(data) = data {
        // Delete a specific record: parse the full record via zone parser.
        let zone_line = format!("$ORIGIN {zone}\n$TTL 0\n{name} 0 IN {rtype} {data}\n");
        let zone_file = ZoneFile::parse(&zone_line).map_err(CliError::Core)?;
        let record = zone_file
            .zone
            .records
            .first()
            .ok_or_else(|| CliError::Config("failed to parse record from input".into()))?
            .clone();
        builder.delete_record(record)
    } else {
        // Delete all records of the given type.
        let record_type = parse_record_type(rtype)?;
        builder.delete_rrset(&record_name, record_type)
    };

    let update = builder.sign_now(&config.rndc_key).build();

    let sender = NsUpdateSender::new(dns_addr);
    let result = sender
        .send(&update, Some(&config.rndc_key))
        .await
        .map_err(CliError::Net)?;

    let data_str = data.unwrap_or("*");
    if result.rcode == Rcode::NoError {
        print_success(
            format,
            &format!("deleted: {record_name} IN {rtype} {data_str} (zone: {zone_name})"),
        );
    } else {
        print_message(
            format,
            &format!(
                "server rejected delete with RCODE: {} (zone: {zone_name})",
                result.rcode
            ),
        );
    }
    Ok(())
}

/// Parse a record type string into a `RecordType`.
///
/// Supports common DNS record type mnemonics and the RFC 3597 `TYPEn` syntax
/// for unknown types.
fn parse_record_type(s: &str) -> Result<RecordType, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::Aaaa),
        "CNAME" => Ok(RecordType::Cname),
        "NS" => Ok(RecordType::Ns),
        "PTR" => Ok(RecordType::Ptr),
        "SOA" => Ok(RecordType::Soa),
        "MX" => Ok(RecordType::Mx),
        "TXT" => Ok(RecordType::Txt),
        "SRV" => Ok(RecordType::Srv),
        "CAA" => Ok(RecordType::Caa),
        "DNSKEY" => Ok(RecordType::Dnskey),
        "RRSIG" => Ok(RecordType::Rrsig),
        "NSEC" => Ok(RecordType::Nsec),
        "NSEC3" => Ok(RecordType::Nsec3),
        "NSEC3PARAM" => Ok(RecordType::Nsec3param),
        "DS" => Ok(RecordType::Ds),
        "CDS" => Ok(RecordType::Cds),
        "CDNSKEY" => Ok(RecordType::Cdnskey),
        "TLSA" => Ok(RecordType::Tlsa),
        "SSHFP" => Ok(RecordType::Sshfp),
        "CSYNC" => Ok(RecordType::Csync),
        "RP" => Ok(RecordType::Rp),
        "DLV" => Ok(RecordType::Dlv),
        other => {
            // RFC 3597 TYPEn syntax
            if let Some(num_str) = other.strip_prefix("TYPE") {
                let value: u16 = num_str
                    .parse()
                    .map_err(|_| CliError::Config(format!("invalid TYPE number: {other}")))?;
                Ok(RecordType::from_value(value))
            } else {
                Err(CliError::Config(format!("unsupported record type: {s}")))
            }
        }
    }
}
