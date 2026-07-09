// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP control and packet framing.

use anyhow::{Context, Result, bail};
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::util::{TARGET_LEN_MAX, check_target_len, validate_target};

/// Reserved TCP request target that switches an authenticated stream into UoT.
pub const UOT_MAGIC_TARGET: &str = "uot.nowhere.invalid:0";

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

/// Reads one length-prefixed UoT packet, returning `None` on clean EOF.
pub async fn read_uot_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let Some(length) = read_u16_frame_len("protocol::uot::read_uot_packet", reader).await? else {
        return Ok(None);
    };
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("protocol::uot::read_uot_packet: failed to read payload")?;
    Ok(Some(payload))
}

/// Encodes one length-prefixed UoT packet.
pub fn write_uot_packet_frame(payload: &[u8]) -> Result<Vec<u8>> {
    check_uot_packet_len("protocol::uot::write_uot_packet_frame", payload.len())?;
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Writes one length-prefixed UoT packet without first concatenating a frame.
pub async fn write_uot_packet<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    check_uot_packet_len("protocol::uot::write_uot_packet", payload.len())?;
    let length = (payload.len() as u16).to_be_bytes();
    let mut frame = Buf::chain(&length[..], payload);
    writer
        .write_all_buf(&mut frame)
        .await
        .context("protocol::uot::write_uot_packet: failed to write frame")
}

fn check_uot_packet_len(context: &str, len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        bail!("{context}: payload too large: {len}");
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
