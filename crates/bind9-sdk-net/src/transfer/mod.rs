// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AXFR/IXFR zone transfer client.
//!
//! Provides [`TransferClient`] for performing zone transfers over DNS-over-TCP.
//! The client returns an async [`Stream`] of [`TransferRecord`]s, allowing
//! incremental processing of large zones.
//!
//! Supports optional TSIG authentication (RFC 8945) for signed transfers.

pub mod wire;

#[cfg(test)]
mod tests;

use std::time::Duration;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::record::Serial;
use bind9_sdk_core::transfer::{IxfrEvent, TransferRecord};
use bind9_sdk_core::tsig::TsigKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

use crate::error::NetError;
use crate::tls::{TlsConfig, is_localhost};

use self::wire::{
    DnsHeader, encode_axfr_query_with_metadata, encode_ixfr_query_with_metadata,
    parse_resource_record, read_tcp_dns_message, split_final_tsig, write_tcp_dns_message,
};

/// Default per-message read timeout for zone transfers (60 seconds).
const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum number of records before aborting transfer (10 million).
const DEFAULT_MAX_RECORDS: usize = 10_000_000;

const QTYPE_IXFR: u16 = 251;
const QTYPE_AXFR: u16 = 252;

enum IxfrPhase {
    AwaitFirst,
    AwaitSecond {
        current_soa: bind9_sdk_core::record::ResourceRecord,
        current_serial: Serial,
    },
    Axfr {
        current_serial: Serial,
    },
    Delete {
        current_serial: Serial,
        from_serial: Serial,
    },
    Add {
        current_serial: Serial,
        to_serial: Serial,
    },
    Complete,
}

struct IxfrState {
    zone: DomainName,
    requested_serial: Serial,
    phase: IxfrPhase,
}

impl IxfrState {
    fn new(zone: DomainName, requested_serial: Serial) -> Self {
        Self {
            zone,
            requested_serial,
            phase: IxfrPhase::AwaitFirst,
        }
    }

    fn push(
        &mut self,
        record: bind9_sdk_core::record::ResourceRecord,
    ) -> Result<Vec<IxfrEvent>, NetError> {
        let phase = std::mem::replace(&mut self.phase, IxfrPhase::Complete);
        let mut events = Vec::new();

        self.phase = match phase {
            IxfrPhase::AwaitFirst => {
                let current_serial = apex_soa_serial(&record, &self.zone).ok_or_else(|| {
                    NetError::XfrProtocolError(
                        "first record in IXFR response must be the zone SOA".into(),
                    )
                })?;
                IxfrPhase::AwaitSecond {
                    current_soa: record,
                    current_serial,
                }
            }
            IxfrPhase::AwaitSecond {
                current_soa,
                current_serial,
            } => {
                if let Some(base_serial) = apex_soa_serial(&record, &self.zone) {
                    if base_serial == current_serial {
                        events.push(IxfrEvent::AxfrFallback(TransferRecord::BeginSoa(
                            current_soa,
                        )));
                        events.push(IxfrEvent::AxfrFallback(TransferRecord::EndSoa(record)));
                        IxfrPhase::Complete
                    } else {
                        if base_serial != self.requested_serial {
                            return Err(NetError::SerialMismatch {
                                expected: self.requested_serial.value(),
                                actual: base_serial.value(),
                            });
                        }
                        match current_serial.partial_cmp(&base_serial) {
                            Some(std::cmp::Ordering::Greater) => {}
                            Some(_) => {
                                return Err(NetError::XfrProtocolError(format!(
                                    "IXFR current serial {current_serial} is not newer than base serial {base_serial}"
                                )));
                            }
                            None => {
                                return Err(NetError::XfrProtocolError(format!(
                                    "IXFR serial ordering is undefined by RFC 1982: \
                                     current serial {current_serial}, base serial {base_serial}"
                                )));
                            }
                        }
                        events.push(IxfrEvent::CurrentSoa(current_soa));
                        events.push(IxfrEvent::DeleteSoa(record));
                        IxfrPhase::Delete {
                            current_serial,
                            from_serial: base_serial,
                        }
                    }
                } else {
                    events.push(IxfrEvent::AxfrFallback(TransferRecord::BeginSoa(
                        current_soa,
                    )));
                    events.push(IxfrEvent::AxfrFallback(TransferRecord::Record(record)));
                    IxfrPhase::Axfr { current_serial }
                }
            }
            IxfrPhase::Axfr { current_serial } => {
                if let Some(serial) = apex_soa_serial(&record, &self.zone) {
                    if serial != current_serial {
                        return Err(NetError::SerialMismatch {
                            expected: current_serial.value(),
                            actual: serial.value(),
                        });
                    }
                    events.push(IxfrEvent::AxfrFallback(TransferRecord::EndSoa(record)));
                    IxfrPhase::Complete
                } else {
                    events.push(IxfrEvent::AxfrFallback(TransferRecord::Record(record)));
                    IxfrPhase::Axfr { current_serial }
                }
            }
            IxfrPhase::Delete {
                current_serial,
                from_serial,
            } => {
                if let Some(to_serial) = apex_soa_serial(&record, &self.zone) {
                    let after_from = to_serial.partial_cmp(&from_serial);
                    let at_or_before_current = to_serial.partial_cmp(&current_serial);
                    if after_from.is_none() || at_or_before_current.is_none() {
                        return Err(NetError::XfrProtocolError(format!(
                            "IXFR serial ordering is undefined by RFC 1982: \
                             {from_serial} -> {to_serial} with current serial {current_serial}"
                        )));
                    }
                    if after_from != Some(std::cmp::Ordering::Greater)
                        || at_or_before_current == Some(std::cmp::Ordering::Greater)
                    {
                        return Err(NetError::XfrProtocolError(format!(
                            "invalid IXFR serial transition {from_serial} -> {to_serial} \
                             with current serial {current_serial}"
                        )));
                    }
                    events.push(IxfrEvent::AddSoa(record));
                    IxfrPhase::Add {
                        current_serial,
                        to_serial,
                    }
                } else {
                    events.push(IxfrEvent::Deleted(record));
                    IxfrPhase::Delete {
                        current_serial,
                        from_serial,
                    }
                }
            }
            IxfrPhase::Add {
                current_serial,
                to_serial,
            } => {
                if let Some(serial) = apex_soa_serial(&record, &self.zone) {
                    if serial == current_serial {
                        events.push(IxfrEvent::EndSoa(record));
                        IxfrPhase::Complete
                    } else if serial == to_serial {
                        events.push(IxfrEvent::DeleteSoa(record));
                        IxfrPhase::Delete {
                            current_serial,
                            from_serial: to_serial,
                        }
                    } else {
                        return Err(NetError::SerialMismatch {
                            expected: to_serial.value(),
                            actual: serial.value(),
                        });
                    }
                } else {
                    events.push(IxfrEvent::Added(record));
                    IxfrPhase::Add {
                        current_serial,
                        to_serial,
                    }
                }
            }
            IxfrPhase::Complete => {
                return Err(NetError::XfrProtocolError(
                    "received records after IXFR completion".into(),
                ));
            }
        };

        Ok(events)
    }

    fn finish(&mut self) -> Result<Vec<IxfrEvent>, NetError> {
        let phase = std::mem::replace(&mut self.phase, IxfrPhase::Complete);
        match phase {
            IxfrPhase::AwaitSecond { current_soa, .. } => {
                Ok(vec![IxfrEvent::NoChange(current_soa)])
            }
            IxfrPhase::Complete => Ok(Vec::new()),
            _ => Err(NetError::IncompleteTransfer {
                reason: "IXFR response ended before a complete delta or AXFR fallback".into(),
            }),
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.phase, IxfrPhase::Complete)
    }
}

fn apex_soa_serial(
    record: &bind9_sdk_core::record::ResourceRecord,
    zone: &DomainName,
) -> Option<Serial> {
    if record.name != *zone {
        return None;
    }
    match &record.rdata {
        RecordData::Soa { serial, .. } => Some(*serial),
        _ => None,
    }
}

/// Stateful RFC 8945 verifier for a DNS zone-transfer response stream.
struct XfrTsigVerifier<'a> {
    expected_id: u16,
    key: Option<&'a TsigKey>,
    prior_mac: Option<Vec<u8>>,
    first_message: bool,
    unsigned_messages: Vec<u8>,
    unsigned_message_count: u8,
    last_message_signed: bool,
}

struct TransferStreamContext<'a> {
    zone: DomainName,
    timeout: Duration,
    max_records: usize,
    verifier: XfrTsigVerifier<'a>,
    expected_qtype: u16,
}

impl<'a> TransferStreamContext<'a> {
    fn new(
        zone: DomainName,
        timeout: Duration,
        max_records: usize,
        query_id: u16,
        tsig_key: Option<&'a TsigKey>,
        request_mac: Option<Vec<u8>>,
        expected_qtype: u16,
    ) -> Self {
        Self {
            zone,
            timeout,
            max_records,
            verifier: XfrTsigVerifier::new(query_id, tsig_key, request_mac),
            expected_qtype,
        }
    }
}

impl<'a> XfrTsigVerifier<'a> {
    fn new(expected_id: u16, key: Option<&'a TsigKey>, request_mac: Option<Vec<u8>>) -> Self {
        Self {
            expected_id,
            key,
            prior_mac: request_mac,
            first_message: true,
            unsigned_messages: Vec::new(),
            unsigned_message_count: 0,
            last_message_signed: false,
        }
    }

    fn verify_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NetError> {
        let header = DnsHeader::parse(message)?;
        if header.id != self.expected_id {
            return Err(NetError::XfrProtocolError(format!(
                "response ID mismatch: expected {}, got {}",
                self.expected_id, header.id
            )));
        }

        let Some(key) = self.key else {
            self.first_message = false;
            return Ok(message.to_vec());
        };

        let split = split_final_tsig(message)?;
        let Some(tsig) = split.tsig else {
            if self.first_message {
                return Err(NetError::XfrProtocolError(
                    "first response in a signed transfer must contain TSIG".into(),
                ));
            }
            if self.unsigned_message_count >= 99 {
                return Err(NetError::XfrProtocolError(
                    "signed transfer exceeded 99 unsigned intermediary messages".into(),
                ));
            }
            self.unsigned_messages
                .extend_from_slice(&split.unsigned_message);
            self.unsigned_message_count += 1;
            self.last_message_signed = false;
            return Ok(split.unsigned_message);
        };

        if tsig.key_name != *key.name() {
            return Err(NetError::XfrProtocolError(format!(
                "TSIG key mismatch: expected {}, got {}",
                key.name(),
                tsig.key_name
            )));
        }
        if tsig.algorithm != key.algorithm() {
            return Err(NetError::XfrProtocolError(format!(
                "TSIG algorithm mismatch: expected {}, got {}",
                key.algorithm(),
                tsig.algorithm
            )));
        }
        if tsig.original_id != self.expected_id {
            return Err(NetError::XfrProtocolError(format!(
                "TSIG original ID mismatch: expected {}, got {}",
                self.expected_id, tsig.original_id
            )));
        }
        if tsig.error != 0 {
            return Err(NetError::TsigRejected {
                code: tsig.error,
                message: "zone-transfer TSIG response reported an error".into(),
            });
        }

        let prior_mac = self.prior_mac.as_deref().ok_or_else(|| {
            NetError::XfrProtocolError("signed transfer is missing the request MAC".into())
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                NetError::XfrProtocolError(format!("system clock before Unix epoch: {error}"))
            })?
            .as_secs();
        if self.first_message {
            bind9_sdk_core::tsig::TsigRecord::verify_response(
                key,
                &split.unsigned_message,
                &tsig,
                prior_mac,
                now,
            )?;
        } else {
            tsig.verify_time(now)?;
            let mut mac_input = Vec::with_capacity(
                2 + prior_mac.len()
                    + self.unsigned_messages.len()
                    + split.unsigned_message.len()
                    + 8,
            );
            mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(prior_mac);
            mac_input.extend_from_slice(&self.unsigned_messages);
            mac_input.extend_from_slice(&split.unsigned_message);
            mac_input.extend_from_slice(&tsig.time_signed.to_be_bytes()[2..]);
            mac_input.extend_from_slice(&tsig.fudge.to_be_bytes());
            key.verify(&mac_input, &tsig.mac)?;
        }

        self.prior_mac = Some(tsig.mac.to_vec());
        self.first_message = false;
        self.unsigned_messages.clear();
        self.unsigned_message_count = 0;
        self.last_message_signed = true;
        Ok(split.unsigned_message)
    }

    fn finish(&self) -> Result<(), NetError> {
        if self.key.is_some() && !self.last_message_signed {
            return Err(NetError::XfrProtocolError(
                "final response in a signed transfer must contain TSIG".into(),
            ));
        }
        Ok(())
    }
}

/// A zone transfer client that operates over any async TCP-like stream.
///
/// Generic over the transport `S` to allow testing with mock streams.
/// In production, `S` is typically `tokio::net::TcpStream`.
pub struct TransferClient<S> {
    stream: S,
    /// Per-message read timeout. Defaults to 60 seconds.
    timeout: Duration,
    /// Maximum number of records before aborting. Defaults to 10 million.
    max_records: usize,
}

impl TransferClient<tokio::net::TcpStream> {
    /// Connect to a DNS server for zone transfer over plain TCP.
    ///
    /// For non-localhost addresses, TLS is required (XoT per REQ-TLS-1).
    /// Localhost connections are exempt from the TLS requirement.
    ///
    /// When `tls` is `Some`, the connection should use a TLS transport
    /// (not yet implemented). Passing `Some` currently returns a
    /// [`NetError::Tls`] error.
    pub async fn connect(
        addr: std::net::SocketAddr,
        tls: Option<&TlsConfig>,
    ) -> Result<Self, NetError> {
        if !is_localhost(&addr) && tls.is_none() {
            return Err(NetError::TlsRequired {
                remote: addr.to_string(),
            });
        }
        if tls.is_some() {
            return Err(NetError::Tls(
                "use connect_tls() for TLS connections".into(),
            ));
        }
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| NetError::Connection(format!("failed to connect to {addr}: {e}")))?;
        Ok(TransferClient::new(stream))
    }
}

impl TransferClient<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    /// Connect to a DNS server using DNS-over-TLS (XoT, RFC 9103).
    ///
    /// `server_name` is authenticated against the certificate presented by
    /// the server. The supplied [`TlsConfig`] controls trust roots and TLS
    /// policy.
    pub async fn connect_tls(
        addr: std::net::SocketAddr,
        server_name: &str,
        tls: &TlsConfig,
    ) -> Result<Self, NetError> {
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .map_err(|error| NetError::Tls(format!("invalid TLS server name: {error}")))?;
        let tcp_stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|error| {
                NetError::Connection(format!("failed to connect to {addr}: {error}"))
            })?;
        let connector = tokio_rustls::TlsConnector::from(tls.client_config_arc());
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|error| NetError::Tls(format!("TLS handshake with {addr} failed: {error}")))?;
        Ok(Self::new(tls_stream))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TransferClient<S> {
    /// Create a new transfer client wrapping the given stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            timeout: DEFAULT_TRANSFER_TIMEOUT,
            max_records: DEFAULT_MAX_RECORDS,
        }
    }

    /// Set the per-message read timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum number of records before aborting the transfer.
    pub fn with_max_records(mut self, max_records: usize) -> Self {
        self.max_records = max_records;
        self
    }

    /// Perform an AXFR (full zone transfer).
    ///
    /// Sends an AXFR query for `zone` and returns a stream of records.
    /// The stream yields `BeginSoa` for the first SOA, `Record` for
    /// intermediate records, and `EndSoa` for the closing SOA.
    ///
    /// If `tsig_key` is provided, the query is signed with TSIG.
    #[tracing::instrument(skip(self, tsig_key), fields(zone = %zone, kind = "AXFR"))]
    pub async fn axfr<'a>(
        mut self,
        zone: DomainName,
        tsig_key: Option<&'a TsigKey>,
    ) -> Result<impl Stream<Item = Result<TransferRecord, NetError>> + 'a, NetError>
    where
        S: 'a,
    {
        let query = encode_axfr_query_with_metadata(&zone, tsig_key)?;
        write_tcp_dns_message(&mut self.stream, &query.message).await?;

        tracing::debug!("AXFR query sent");

        Ok(transfer_record_stream(
            self.stream,
            TransferStreamContext::new(
                zone,
                self.timeout,
                self.max_records,
                query.id,
                tsig_key,
                query.request_mac,
                QTYPE_AXFR,
            ),
        ))
    }

    /// Perform an IXFR (incremental zone transfer).
    ///
    /// Sends an IXFR query for `zone` starting from `current_serial`.
    /// If the server responds with an AXFR-style response (single SOA pair),
    /// the stream transparently handles it.
    #[tracing::instrument(skip(self, tsig_key), fields(zone = %zone, kind = "IXFR", serial = current_serial.value()))]
    pub async fn ixfr<'a>(
        mut self,
        zone: DomainName,
        current_serial: Serial,
        tsig_key: Option<&'a TsigKey>,
    ) -> Result<impl Stream<Item = Result<IxfrEvent, NetError>> + 'a, NetError>
    where
        S: 'a,
    {
        let query = encode_ixfr_query_with_metadata(&zone, current_serial, tsig_key)?;
        write_tcp_dns_message(&mut self.stream, &query.message).await?;

        tracing::debug!("IXFR query sent");

        Ok(ixfr_record_stream(
            self.stream,
            TransferStreamContext::new(
                zone,
                self.timeout,
                self.max_records,
                query.id,
                tsig_key,
                query.request_mac,
                QTYPE_IXFR,
            ),
            current_serial,
        ))
    }
}

fn ixfr_record_stream<'a, S: AsyncRead + AsyncWrite + Unpin + 'a>(
    mut stream: S,
    mut context: TransferStreamContext<'a>,
    current_serial: Serial,
) -> impl Stream<Item = Result<IxfrEvent, NetError>> + 'a {
    async_stream::try_stream! {
        let mut state = IxfrState::new(context.zone.clone(), current_serial);
        let mut record_count = 0usize;

        loop {
            let read_result = tokio::time::timeout(context.timeout, read_tcp_dns_message(&mut stream))
                .await
                .map_err(|_| NetError::TransferFailed {
                    reason: format!(
                        "transfer read timed out after {}s",
                        context.timeout.as_secs()
                    ),
                })?;
            let wire_message = match read_result {
                Ok(message) => message,
                Err(NetError::IncompleteTransfer { reason })
                    if reason == "connection closed before message length" =>
                {
                    for event in state.finish()? {
                        yield event;
                    }
                    context.verifier.finish()?;
                    break;
                }
                Err(error) => Err(error)?,
            };
            let message = context.verifier.verify_message(&wire_message)?;
            let header = DnsHeader::parse(&message)?;
            let mut offset = validate_transfer_response(
                &message,
                &header,
                &context.zone,
                context.expected_qtype,
            )?;

            for answer_index in 0..header.answer_count {
                let (record, consumed) = parse_resource_record(&message, offset)?;
                offset += consumed;
                record_count += 1;
                if record_count > context.max_records {
                    Err(NetError::TransferFailed {
                        reason: format!(
                            "transfer exceeded maximum record count ({})",
                            context.max_records
                        ),
                    })?;
                }

                let events = state.push(record)?;
                if state.is_complete() && answer_index + 1 != header.answer_count {
                    Err(NetError::XfrProtocolError(
                        "zone transfer response contains answers after IXFR completion".into(),
                    ))?;
                }
                for event in events {
                    yield event;
                }
                if state.is_complete() {
                    context.verifier.finish()?;
                    break;
                }
            }

            // RFC 1995 defines a one-RR response containing only the current
            // SOA when the server has no newer version than the client.
            if header.answer_count == 1 && !state.is_complete() {
                for event in state.finish()? {
                    yield event;
                }
                context.verifier.finish()?;
                break;
            }

            if state.is_complete() {
                break;
            }
        }
    }
}

/// Create an async stream that reads DNS messages from `stream` and yields
/// `TransferRecord`s until the closing SOA is received.
///
/// Each `read_tcp_dns_message` call is wrapped in a timeout to prevent
/// a malicious or slow server from holding the client indefinitely.
/// Total record count is capped at `max_records` to prevent memory exhaustion.
fn transfer_record_stream<'a, S: AsyncRead + AsyncWrite + Unpin + 'a>(
    mut stream: S,
    mut context: TransferStreamContext<'a>,
) -> impl Stream<Item = Result<TransferRecord, NetError>> + 'a {
    async_stream::try_stream! {
        let mut awaiting_first_soa = true;
        let mut opening_serial: Option<Serial> = None;
        let mut soa_count: u32 = 0;
        let mut record_count: usize = 0;
        'outer: loop {
            // F-003: wrap each read in a timeout to prevent indefinite blocking
            let wire_message = tokio::time::timeout(
                context.timeout,
                read_tcp_dns_message(&mut stream),
            )
                .await
                .map_err(|_| NetError::TransferFailed {
                    reason: format!(
                        "transfer read timed out after {}s",
                        context.timeout.as_secs()
                    ),
                })??;
            let msg = context.verifier.verify_message(&wire_message)?;
            let header = DnsHeader::parse(&msg)?;
            let mut offset =
                validate_transfer_response(
                    &msg,
                    &header,
                    &context.zone,
                    context.expected_qtype,
                )?;

            // Parse answer section records
            for answer_index in 0..header.answer_count {
                let (rr, consumed) = parse_resource_record(&msg, offset)?;
                offset += consumed;

                // F-007: limit total records to prevent resource exhaustion
                record_count += 1;
                if record_count > context.max_records {
                    Err(NetError::TransferFailed {
                        reason: format!(
                            "transfer exceeded maximum record count ({})",
                            context.max_records
                        ),
                    })?;
                }

                let is_soa =
                    matches!(rr.rdata, RecordData::Soa { .. }) && rr.name == context.zone;

                if awaiting_first_soa {
                    if is_soa {
                        opening_serial = apex_soa_serial(&rr, &context.zone);
                        soa_count += 1;
                        awaiting_first_soa = false;
                        yield TransferRecord::BeginSoa(rr);
                    } else {
                        Err(NetError::XfrProtocolError(
                            "first record in zone transfer must be SOA".into(),
                        ))?;
                    }
                } else if is_soa {
                    let closing_serial = apex_soa_serial(&rr, &context.zone).ok_or_else(|| {
                        NetError::XfrProtocolError(
                            "closing AXFR SOA did not contain a serial".into(),
                        )
                    })?;
                    if Some(closing_serial) != opening_serial {
                        let opening_serial =
                            opening_serial.map_or(0, |serial| serial.value());
                        Err(NetError::XfrProtocolError(format!(
                            "closing SOA serial {closing_serial} does not match opening SOA serial \
                             {opening_serial}"
                        )))?;
                    }
                    soa_count += 1;
                    if soa_count >= 2 {
                        if answer_index + 1 != header.answer_count {
                            Err(NetError::XfrProtocolError(
                                "zone transfer response contains answers after closing SOA".into(),
                            ))?;
                        }
                        context.verifier.finish()?;
                        yield TransferRecord::EndSoa(rr);
                        break 'outer;
                    } else {
                        yield TransferRecord::Record(rr);
                    }
                } else {
                    yield TransferRecord::Record(rr);
                }
            }
        }
    }
}

fn validate_transfer_response(
    message: &[u8],
    header: &DnsHeader,
    zone: &DomainName,
    expected_qtype: u16,
) -> Result<usize, NetError> {
    if !header.is_response {
        return Err(NetError::XfrProtocolError(
            "expected response, got query".into(),
        ));
    }
    if header.opcode != 0 {
        return Err(NetError::XfrProtocolError(format!(
            "expected standard QUERY opcode, got {}",
            header.opcode
        )));
    }
    if !header.authoritative {
        return Err(NetError::XfrProtocolError(
            "zone transfer response must be authoritative".into(),
        ));
    }
    if header.truncated {
        return Err(NetError::XfrProtocolError(
            "zone transfer response must not be truncated".into(),
        ));
    }
    if header.rcode != 0 {
        return Err(NetError::TransferFailed {
            reason: format!("server returned RCODE {}", header.rcode),
        });
    }
    if header.question_count > 1 {
        return Err(NetError::XfrProtocolError(format!(
            "zone transfer response has {} questions, expected at most one",
            header.question_count
        )));
    }

    let mut offset = 12;
    for _ in 0..header.question_count {
        let (question_name, name_len) = wire::parse_name(message, offset)?;
        let fixed_offset = offset + name_len;
        if fixed_offset + 4 > message.len() {
            return Err(NetError::XfrProtocolError(
                "truncated zone transfer question".into(),
            ));
        }
        let question_type = u16::from_be_bytes([message[fixed_offset], message[fixed_offset + 1]]);
        let question_class =
            u16::from_be_bytes([message[fixed_offset + 2], message[fixed_offset + 3]]);
        if question_name != *zone || question_type != expected_qtype || question_class != 1 {
            return Err(NetError::XfrProtocolError(format!(
                "zone transfer response question mismatch: name={question_name}, \
                 type={question_type}, class={question_class}"
            )));
        }
        offset = fixed_offset + 4;
    }
    Ok(offset)
}
