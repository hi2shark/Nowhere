// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed QUIC UDP frames with bounded application-layer fragmentation.

use anyhow::{Result, bail};

/// Fixed discriminator carried by every QUIC UDP frame.
pub const UDP_FRAME_MAGIC: [u8; 4] = *b"NOWU";
/// Carries one target-free UDP packet fragment.
pub const UDP_FRAME_DATA: u8 = 1;
/// Closes a flow.
pub const UDP_FRAME_CLOSE: u8 = 2;

/// Largest UDP payload representable by the protocol.
pub const UDP_PACKET_MAX: usize = u16::MAX as usize;

const CONTROL_HEADER_LEN: usize = UDP_FRAME_MAGIC.len() + 1 + 8;
const FRAGMENT_HEADER_LEN: usize = 4 + 1 + 1 + 2;
const DATA_HEADER_LEN: usize = CONTROL_HEADER_LEN + FRAGMENT_HEADER_LEN;

/// Borrowed fragment metadata decoded from a DATA frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFragment<'a> {
    /// Packet identifier scoped to one UDP flow.
    pub packet_id: u32,
    /// Zero-based fragment index.
    pub fragment_id: u8,
    /// Total fragments in the original UDP packet.
    pub fragment_count: u8,
    /// Original UDP packet length before fragmentation.
    pub total_len: u16,
    /// Fragment payload.
    pub payload: &'a [u8],
}

/// One decoded QUIC UDP frame.
#[derive(Debug, Eq, PartialEq)]
pub enum UdpFrame<'a> {
    /// Target-free packet fragment.
    Data {
        /// Flow identifier.
        flow_id: u64,
        /// Packet fragment.
        fragment: UdpFragment<'a>,
    },
    /// Flow-close request or notification.
    Close {
        /// Closed flow identifier.
        flow_id: u64,
    },
}

/// Encodes a target-free DATA packet into DATAGRAM-sized fragments.
pub fn encode_udp_data_fragments(
    flow_id: u64,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_flow_id(flow_id, "encode_udp_data_fragments")?;
    validate_packet_id(packet_id, "encode_udp_data_fragments")?;
    encode_fragments(flow_id, packet_id, payload, max_datagram_size)
}

/// Encodes a CLOSE control frame.
pub fn encode_udp_close(flow_id: u64) -> Result<Vec<u8>> {
    validate_flow_id(flow_id, "encode_udp_close")?;
    let mut out = Vec::with_capacity(CONTROL_HEADER_LEN);
    write_base_header(&mut out, UDP_FRAME_CLOSE, flow_id);
    Ok(out)
}

fn encode_fragments(
    flow_id: u64,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>> {
    if payload.len() > UDP_PACKET_MAX {
        bail!(
            "protocol::datagram::encode_fragments: UDP payload too large: {}",
            payload.len()
        );
    }
    let max_payload = max_datagram_size.checked_sub(DATA_HEADER_LEN).ok_or_else(|| {
        anyhow::anyhow!(
            "protocol::datagram::encode_fragments: DATAGRAM limit {max_datagram_size} smaller than header {DATA_HEADER_LEN}"
        )
    })?;
    if max_payload == 0 && !payload.is_empty() {
        bail!("protocol::datagram::encode_fragments: no DATAGRAM payload capacity");
    }
    let fragment_count = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(max_payload)
    };
    if fragment_count > u8::MAX as usize {
        bail!("protocol::datagram::encode_fragments: too many fragments: {fragment_count}");
    }
    let total_len = payload.len() as u16;
    let mut frames = Vec::with_capacity(fragment_count);
    for fragment_id in 0..fragment_count {
        let start = fragment_id * max_payload;
        let end = payload.len().min(start.saturating_add(max_payload));
        let fragment_payload = &payload[start..end];
        let mut out = Vec::with_capacity(DATA_HEADER_LEN + fragment_payload.len());
        write_base_header(&mut out, UDP_FRAME_DATA, flow_id);
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(fragment_id as u8);
        out.push(fragment_count as u8);
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(fragment_payload);
        debug_assert!(out.len() <= max_datagram_size);
        frames.push(out);
    }
    Ok(frames)
}

fn write_base_header(out: &mut Vec<u8>, frame_type: u8, flow_id: u64) {
    out.extend_from_slice(&UDP_FRAME_MAGIC);
    out.push(frame_type);
    out.extend_from_slice(&flow_id.to_be_bytes());
}

/// Decodes one fixed QUIC UDP frame.
pub fn decode_udp_frame(buf: &[u8]) -> Result<UdpFrame<'_>> {
    if buf.len() < CONTROL_HEADER_LEN || buf[..UDP_FRAME_MAGIC.len()] != UDP_FRAME_MAGIC {
        bail!("protocol::datagram::decode_udp_frame: invalid magic or short header");
    }
    let frame_type = buf[UDP_FRAME_MAGIC.len()];
    let flow_id = u64::from_be_bytes(
        buf[UDP_FRAME_MAGIC.len() + 1..CONTROL_HEADER_LEN]
            .try_into()
            .expect("fixed flow id"),
    );
    validate_flow_id(flow_id, "decode_udp_frame")?;
    match frame_type {
        UDP_FRAME_CLOSE => {
            if buf.len() != CONTROL_HEADER_LEN {
                bail!("protocol::datagram::decode_udp_frame: CLOSE payload");
            }
            Ok(UdpFrame::Close { flow_id })
        }
        UDP_FRAME_DATA => Ok(UdpFrame::Data {
            flow_id,
            fragment: decode_fragment(buf, CONTROL_HEADER_LEN)?,
        }),
        value => bail!("protocol::datagram::decode_udp_frame: invalid type: {value}"),
    }
}

fn decode_fragment(buf: &[u8], offset: usize) -> Result<UdpFragment<'_>> {
    let payload_offset = offset.saturating_add(FRAGMENT_HEADER_LEN);
    if buf.len() < payload_offset {
        bail!("protocol::datagram::decode_udp_frame: short fragment header");
    }
    let packet_id =
        u32::from_be_bytes(buf[offset..offset + 4].try_into().expect("fixed packet id"));
    validate_packet_id(packet_id, "decode_udp_frame")?;
    let fragment_id = buf[offset + 4];
    let fragment_count = buf[offset + 5];
    let total_len = u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]);
    let payload = &buf[payload_offset..];
    if fragment_count == 0 || fragment_id >= fragment_count {
        bail!("protocol::datagram::decode_udp_frame: invalid fragment index");
    }
    if payload.len() > total_len as usize {
        bail!("protocol::datagram::decode_udp_frame: fragment exceeds total length");
    }
    if total_len == 0 {
        if fragment_count != 1 || fragment_id != 0 || !payload.is_empty() {
            bail!("protocol::datagram::decode_udp_frame: invalid empty packet");
        }
    } else if payload.is_empty() || fragment_count == 1 && payload.len() != total_len as usize {
        bail!("protocol::datagram::decode_udp_frame: invalid fragment payload");
    }
    Ok(UdpFragment {
        packet_id,
        fragment_id,
        fragment_count,
        total_len,
        payload,
    })
}

fn validate_flow_id(flow_id: u64, operation: &str) -> Result<()> {
    if flow_id == 0 {
        bail!("protocol::datagram::{operation}: zero flow id");
    }
    Ok(())
}

fn validate_packet_id(packet_id: u32, operation: &str) -> Result<()> {
    if packet_id == 0 {
        bail!("protocol::datagram::{operation}: zero packet id");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/protocol/datagram.rs"]
mod tests;
