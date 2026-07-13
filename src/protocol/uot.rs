// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP control and packet framing.

use anyhow::{Context, Result, bail};
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::util::{TARGET_LEN_MAX, check_target_len, validate_target};

/// Reserved TCP request target that switches an authenticated stream into UoT.
pub const UOT_MAGIC_TARGET: &str = "uot.nowhere.invalid:0";
/// UDP packet carried by a UoT stream.
pub const UDP_STREAM_DATA: u8 = 1;
/// Flow-open acknowledgement carried by a paired UoT downlink.
pub const UDP_STREAM_OPEN_ACK: u8 = 2;
/// Explicit paired-flow close notification.
pub const UDP_STREAM_CLOSE: u8 = 3;

/// One typed frame carried after UoT setup.
#[derive(Debug, Eq, PartialEq)]
pub enum UdpStreamFrame {
    /// One complete UDP packet. The payload may be empty.
    Data(Vec<u8>),
    /// Flow-open acknowledgement.
    OpenAck,
    /// Flow-close notification.
    Close,
}

/// Returns whether a TCP request target is the UoT switch target.
pub fn is_uot_magic_target(target_addr: &str) -> bool {
    target_addr == UOT_MAGIC_TARGET
}

/// Reads the initial UoT target frame.
pub async fn read_uot_setup_target<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    read_target_frame("protocol::uot::read_uot_setup_target", reader).await
}

/// Encodes the initial UoT target frame.
pub fn write_uot_setup_frame(target_addr: &str) -> Result<Vec<u8>> {
    write_target_frame("protocol::uot::write_uot_setup_frame", target_addr)
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
        .expect("frame type was present");
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("protocol::uot::read_udp_stream_frame: failed to read payload")?;
    match frame_type[0] {
        UDP_STREAM_DATA => Ok(Some(UdpStreamFrame::Data(payload))),
        UDP_STREAM_OPEN_ACK if payload.is_empty() => Ok(Some(UdpStreamFrame::OpenAck)),
        UDP_STREAM_CLOSE if payload.is_empty() => Ok(Some(UdpStreamFrame::Close)),
        UDP_STREAM_OPEN_ACK | UDP_STREAM_CLOSE => {
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
        UDP_STREAM_DATA | UDP_STREAM_OPEN_ACK | UDP_STREAM_CLOSE
    ) {
        bail!("{context}: invalid frame type: {frame_type}");
    }
    if frame_type != UDP_STREAM_DATA && !payload.is_empty() {
        bail!("{context}: control frame payload");
    }
    Ok(())
}

async fn read_target_frame<R: AsyncRead + Unpin>(context: &str, reader: &mut R) -> Result<String> {
    let Some(target_len) = read_u16_frame_len(context, reader).await? else {
        bail!("{context}: missing target");
    };
    if !(1..=TARGET_LEN_MAX).contains(&target_len) {
        bail!("{context}: invalid target length: {target_len}");
    }
    let mut target = vec![0; target_len];
    reader
        .read_exact(&mut target)
        .await
        .with_context(|| format!("{context}: failed to read target"))?;
    let target_addr = String::from_utf8(target)
        .with_context(|| format!("{context}: target is not valid UTF-8"))?;
    validate_target(&target_addr).map_err(|e| anyhow::anyhow!("{context}: {e}"))?;
    Ok(target_addr)
}

fn write_target_frame(context: &str, target_addr: &str) -> Result<Vec<u8>> {
    check_target_len(context, target_addr)?;
    validate_target(target_addr).map_err(|e| anyhow::anyhow!("{context}: {e}"))?;
    if target_addr.len() > u16::MAX as usize {
        bail!("{context}: target too long: {}", target_addr.len());
    }
    let mut frame = Vec::with_capacity(2 + target_addr.len());
    frame.extend_from_slice(&(target_addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(target_addr.as_bytes());
    Ok(frame)
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
