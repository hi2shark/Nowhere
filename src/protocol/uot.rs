// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Length-only UDP-over-stream packet framing after setup succeeds.

use anyhow::{Context, Result, bail};
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Fixed UoT packet header length.
pub const UOT_HEADER_LEN: usize = 2;
/// Largest packet representable by the UoT length prefix.
pub const UOT_PACKET_MAX: usize = u16::MAX as usize;

/// Encodes only the two-byte packet length header.
pub fn encode_udp_packet_header(payload_len: usize) -> Result<[u8; UOT_HEADER_LEN]> {
    if payload_len > UOT_PACKET_MAX {
        bail!("protocol::uot::encode_udp_packet_header: payload too large: {payload_len}");
    }
    Ok((payload_len as u16).to_be_bytes())
}

/// Encodes one complete UoT packet.
pub fn encode_udp_packet(payload: &[u8]) -> Result<Vec<u8>> {
    let header = encode_udp_packet_header(payload.len())?;
    let mut output = Vec::with_capacity(UOT_HEADER_LEN + payload.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(output)
}

/// Writes one UoT packet without concatenating its payload into another buffer.
pub async fn write_udp_packet<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let header = encode_udp_packet_header(payload.len())?;
    let mut frame = Buf::chain(&header[..], payload);
    writer
        .write_all_buf(&mut frame)
        .await
        .context("protocol::uot::write_udp_packet: failed to write packet")
}

/// Reads one UoT packet, returning `None` only for a clean EOF before a header.
pub async fn read_udp_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut payload = Vec::new();
    let Some(payload_len) = read_udp_packet_into(reader, &mut payload).await? else {
        return Ok(None);
    };
    debug_assert_eq!(payload_len, payload.len());
    Ok(Some(payload))
}

/// Reads into a reusable per-flow buffer and returns the complete packet length.
///
/// `Some(0)` is a legal zero-length UDP packet; only `None` means clean EOF.
pub async fn read_udp_packet_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload: &mut Vec<u8>,
) -> Result<Option<usize>> {
    let mut first = [0; 1];
    let count = reader
        .read(&mut first)
        .await
        .context("protocol::uot::read_udp_packet: failed to read packet length")?;
    if count == 0 {
        payload.clear();
        return Ok(None);
    }

    let mut second = [0; 1];
    reader
        .read_exact(&mut second)
        .await
        .context("protocol::uot::read_udp_packet: truncated packet length")?;
    let payload_len = u16::from_be_bytes([first[0], second[0]]) as usize;
    payload.resize(payload_len, 0);
    reader
        .read_exact(payload)
        .await
        .context("protocol::uot::read_udp_packet: truncated packet payload")?;
    Ok(Some(payload_len))
}

#[cfg(test)]
#[path = "../tests/protocol/uot.rs"]
mod tests;
