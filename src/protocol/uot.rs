// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP control and packet framing.

use anyhow::{Context, Result, bail};
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::FlowErrorCode;

/// UDP packet carried by a UoT stream.
pub const UDP_STREAM_DATA: u8 = 1;
/// Flow-open acknowledgement carried by a paired UoT downlink.
pub const UDP_STREAM_READY: u8 = 2;
/// Explicit paired-flow close notification.
pub const UDP_STREAM_CLOSE: u8 = 3;
/// Explicit flow rejection with one error-code byte.
pub const UDP_STREAM_REJECT: u8 = 4;

/// One typed frame carried after UoT setup.
#[derive(Debug, Eq, PartialEq)]
pub enum UdpStreamFrame {
    /// One complete UDP packet. The payload may be empty.
    Data(Vec<u8>),
    /// Flow-open acknowledgement.
    Ready,
    /// Flow-close notification.
    Close,
    /// Flow rejection.
    Reject(FlowErrorCode),
}

/// Reads one typed UoT frame, returning `None` on clean EOF.
pub async fn read_udp_stream_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<UdpStreamFrame>> {
    let context = "protocol::uot::read_udp_stream_frame";
    let mut frame_type = [0u8; 1];
    let n = reader
        .read(&mut frame_type)
        .await
        .with_context(|| format!("{context}: failed to read frame type"))?;
    if n == 0 {
        return Ok(None);
    }
    let length = read_u16_frame_len(context, reader)
        .await?
        .ok_or_else(|| anyhow::anyhow!("{context}: truncated frame length"))?;
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("protocol::uot::read_udp_stream_frame: failed to read payload")?;
    match frame_type[0] {
        UDP_STREAM_DATA => Ok(Some(UdpStreamFrame::Data(payload))),
        UDP_STREAM_READY if payload.is_empty() => Ok(Some(UdpStreamFrame::Ready)),
        UDP_STREAM_CLOSE if payload.is_empty() => Ok(Some(UdpStreamFrame::Close)),
        UDP_STREAM_REJECT if payload.len() == 1 => {
            Ok(Some(UdpStreamFrame::Reject(payload[0].try_into()?)))
        }
        UDP_STREAM_READY | UDP_STREAM_CLOSE | UDP_STREAM_REJECT => {
            bail!("{context}: control frame payload")
        }
        value => bail!("{context}: invalid frame type: {value}"),
    }
}

/// Encodes one typed UoT frame.
pub fn encode_udp_stream_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    check_udp_stream_frame(
        "protocol::uot::encode_udp_stream_frame",
        frame_type,
        payload,
    )?;
    let mut frame = Vec::with_capacity(3 + payload.len());
    frame.push(frame_type);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Writes one typed UoT frame without first concatenating it.
pub async fn write_udp_stream_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame_type: u8,
    payload: &[u8],
) -> Result<()> {
    check_udp_stream_frame("protocol::uot::write_udp_stream_frame", frame_type, payload)?;
    let kind = [frame_type];
    let length = (payload.len() as u16).to_be_bytes();
    let mut frame = Buf::chain(Buf::chain(&kind[..], &length[..]), payload);
    writer
        .write_all_buf(&mut frame)
        .await
        .context("protocol::uot::write_udp_stream_frame: failed to write frame")
}

fn check_udp_stream_frame(context: &str, frame_type: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize {
        bail!("{context}: payload too large: {}", payload.len());
    }
    if !matches!(
        frame_type,
        UDP_STREAM_DATA | UDP_STREAM_READY | UDP_STREAM_CLOSE | UDP_STREAM_REJECT
    ) {
        bail!("{context}: invalid frame type: {frame_type}");
    }
    match frame_type {
        UDP_STREAM_DATA => {}
        UDP_STREAM_READY | UDP_STREAM_CLOSE if payload.is_empty() => {}
        UDP_STREAM_REJECT if payload.len() == 1 => {
            FlowErrorCode::try_from(payload[0])?;
        }
        _ => bail!("{context}: control frame payload"),
    }
    Ok(())
}

async fn read_u16_frame_len<R: AsyncRead + Unpin>(
    context: &str,
    reader: &mut R,
) -> Result<Option<usize>> {
    let mut first = [0u8; 1];
    let n = reader
        .read(&mut first)
        .await
        .with_context(|| format!("{context}: failed to read length"))?;
    if n == 0 {
        return Ok(None);
    }
    // Read the first byte separately so callers can distinguish clean EOF
    // before a frame from a truncated two-byte length field.
    let mut second = [0u8; 1];
    reader
        .read_exact(&mut second)
        .await
        .with_context(|| format!("{context}: failed to read complete length"))?;
    Ok(Some(u16::from_be_bytes([first[0], second[0]]) as usize))
}

#[cfg(test)]
#[path = "../tests/protocol/uot.rs"]
mod tests;
