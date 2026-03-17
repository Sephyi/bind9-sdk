// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! AXFR/IXFR zone transfer client.
//!
//! Provides [`TransferClient`] for performing zone transfers over DNS-over-TCP.
//! The client returns an async [`Stream`](tokio_stream::Stream) of
//! [`TransferRecord`]s, allowing incremental processing of large zones.
//!
//! Supports optional TSIG authentication (RFC 8945) for signed transfers.

pub mod wire;

#[cfg(test)]
mod tests;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::record::Serial;
use bind9_sdk_core::transfer::TransferRecord;
use bind9_sdk_core::tsig::TsigKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

use crate::error::NetError;
use crate::tls::{TlsConfig, is_localhost};

use self::wire::{
    DnsHeader, encode_axfr_query, encode_ixfr_query, parse_resource_record, read_tcp_dns_message,
    write_tcp_dns_message,
};

/// A zone transfer client that operates over any async TCP-like stream.
///
/// Generic over the transport `S` to allow testing with mock streams.
/// In production, `S` is typically `tokio::net::TcpStream`.
pub struct TransferClient<S> {
    stream: S,
}

impl TransferClient<tokio::net::TcpStream> {
    /// Connect to a DNS server for zone transfer over plain TCP.
    ///
    /// For non-localhost addresses, TLS is required (XoT per REQ-TLS-1).
    /// Localhost connections are exempt from the TLS requirement.
    ///
    /// When `tls` is `Some`, the connection should use
    /// [`TransferClient::connect_tls`] (not yet implemented). Passing
    /// `Some` currently returns a [`NetError::Tls`] error.
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

impl<S: AsyncRead + AsyncWrite + Unpin> TransferClient<S> {
    /// Create a new transfer client wrapping the given stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Perform an AXFR (full zone transfer).
    ///
    /// Sends an AXFR query for `zone` and returns a stream of records.
    /// The stream yields `BeginSoa` for the first SOA, `Record` for
    /// intermediate records, and `EndSoa` for the closing SOA.
    ///
    /// If `tsig_key` is provided, the query is signed with TSIG.
    #[tracing::instrument(skip(self, tsig_key), fields(zone = %zone, kind = "AXFR"))]
    pub async fn axfr(
        mut self,
        zone: DomainName,
        tsig_key: Option<&TsigKey>,
    ) -> Result<impl Stream<Item = Result<TransferRecord, NetError>>, NetError> {
        let query = encode_axfr_query(&zone, tsig_key);
        write_tcp_dns_message(&mut self.stream, &query).await?;

        tracing::debug!("AXFR query sent");

        Ok(transfer_record_stream(self.stream, zone))
    }

    /// Perform an IXFR (incremental zone transfer).
    ///
    /// Sends an IXFR query for `zone` starting from `current_serial`.
    /// If the server responds with an AXFR-style response (single SOA pair),
    /// the stream transparently handles it.
    #[tracing::instrument(skip(self, tsig_key), fields(zone = %zone, kind = "IXFR", serial = current_serial.value()))]
    pub async fn ixfr(
        mut self,
        zone: DomainName,
        current_serial: Serial,
        tsig_key: Option<&TsigKey>,
    ) -> Result<impl Stream<Item = Result<TransferRecord, NetError>>, NetError> {
        let query = encode_ixfr_query(&zone, current_serial, tsig_key);
        write_tcp_dns_message(&mut self.stream, &query).await?;

        tracing::debug!("IXFR query sent");

        Ok(transfer_record_stream(self.stream, zone))
    }
}

/// Create an async stream that reads DNS messages from `stream` and yields
/// `TransferRecord`s until the closing SOA is received.
fn transfer_record_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    zone: DomainName,
) -> impl Stream<Item = Result<TransferRecord, NetError>> {
    async_stream::try_stream! {
        let mut awaiting_first_soa = true;
        let mut soa_count: u32 = 0;

        'outer: loop {
            let msg = read_tcp_dns_message(&mut stream).await?;
            let header = DnsHeader::parse(&msg)?;

            if !header.is_response {
                Err(NetError::XfrProtocolError("expected response, got query".into()))?;
            }

            if header.rcode != 0 {
                Err(NetError::TransferFailed {
                    reason: format!("server returned RCODE {}", header.rcode),
                })?;
            }

            // Skip the question section
            let mut offset = 12;
            for _ in 0..header.question_count {
                let (_, name_len) = wire::parse_name(&msg, offset)?;
                offset += name_len + 4; // name + QTYPE + QCLASS
            }

            // Parse answer section records
            for _ in 0..header.answer_count {
                let (rr, consumed) = parse_resource_record(&msg, offset)?;
                offset += consumed;

                let is_soa = matches!(rr.rdata, RecordData::Soa { .. }) && rr.name == zone;

                if awaiting_first_soa {
                    if is_soa {
                        soa_count += 1;
                        awaiting_first_soa = false;
                        yield TransferRecord::BeginSoa(rr);
                    } else {
                        Err(NetError::XfrProtocolError(
                            "first record in zone transfer must be SOA".into(),
                        ))?;
                    }
                } else if is_soa {
                    soa_count += 1;
                    if soa_count >= 2 {
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
