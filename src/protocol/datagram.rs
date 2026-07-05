// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP datagram frame encoding and decoding.

use anyhow::{Result, bail};

use super::spec::{EffectiveProtocolSpec, PROXY_FRAME_VERSION, UdpFrameElement};
use super::util::{TARGET_LEN_MAX, check_target_len, validate_target};

use super::Carrier;

/// Client-to-portal UDP payload frame.
pub const DATAGRAM_UDP_REQUEST: u8 = 1;
/// Portal-to-client UDP payload frame.
pub const DATAGRAM_UDP_RESPONSE: u8 = 2;
/// Client request to close a UDP flow.
pub const DATAGRAM_UDP_CLOSE: u8 = 3;

/// First payload for a flow using the compact v1 data plane.
pub const DATAGRAM_UDP_OPEN_DATA: u8 = 0x11;
/// Portal acknowledgement that compact DATA frames may be used.
pub const DATAGRAM_UDP_OPEN_ACK: u8 = 0x12;
/// Target-free compact payload frame.
pub const DATAGRAM_UDP_DATA: u8 = 0x13;
/// Compact flow close frame.
pub const DATAGRAM_UDP_COMPACT_CLOSE: u8 = 0x14;

const COMPACT_HEADER_LEN: usize = 1 + 1 + 8;

#[derive(Debug)]
pub enum CompactUdpFrame<'a> {
    OpenData {
        flow_id: u64,
        downlink: Carrier,
        target: String,
        payload: &'a [u8],
    },
    OpenAck {
        flow_id: u64,
    },
    Data {
        flow_id: u64,
        payload: &'a [u8],
    },
    Close {
        flow_id: u64,
    },
}

pub fn encode_udp_open_data(
    flow_id: u64,
    downlink: Carrier,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    validate_target(target)
        .map_err(|e| anyhow::anyhow!("protocol::datagram::encode_udp_open_data: {e}"))?;
    check_target_len("protocol::datagram::encode_udp_open_data", target)?;
    if flow_id == 0 {
        bail!("protocol::datagram::encode_udp_open_data: zero flow id");
    }
    let mut out = Vec::with_capacity(COMPACT_HEADER_LEN + 3 + target.len() + payload.len());
    write_compact_header(&mut out, DATAGRAM_UDP_OPEN_DATA, flow_id);
    out.push(downlink as u8);
    out.extend_from_slice(&(target.len() as u16).to_be_bytes());
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_udp_compact(frame_type: u8, flow_id: u64, payload: &[u8]) -> Result<Vec<u8>> {
    if flow_id == 0 {
        bail!("protocol::datagram::encode_udp_compact: zero flow id");
    }
    if !matches!(
        frame_type,
        DATAGRAM_UDP_OPEN_ACK | DATAGRAM_UDP_DATA | DATAGRAM_UDP_COMPACT_CLOSE
    ) {
        bail!("protocol::datagram::encode_udp_compact: invalid type: {frame_type}");
    }
    if frame_type != DATAGRAM_UDP_DATA && !payload.is_empty() {
        bail!("protocol::datagram::encode_udp_compact: control frame payload");
    }
    let mut out = Vec::with_capacity(COMPACT_HEADER_LEN + payload.len());
    write_compact_header(&mut out, frame_type, flow_id);
    out.extend_from_slice(payload);
    Ok(out)
}

fn write_compact_header(out: &mut Vec<u8>, frame_type: u8, flow_id: u64) {
    out.push(PROXY_FRAME_VERSION);
    out.push(frame_type);
    out.extend_from_slice(&flow_id.to_be_bytes());
}

pub fn decode_udp_compact(buf: &[u8]) -> Result<CompactUdpFrame<'_>> {
    if buf.len() < COMPACT_HEADER_LEN || buf[0] != PROXY_FRAME_VERSION {
        bail!("protocol::datagram::decode_udp_compact: invalid header");
    }
    let frame_type = buf[1];
    let flow_id = u64::from_be_bytes(buf[2..10].try_into().expect("fixed flow id"));
    if flow_id == 0 {
        bail!("protocol::datagram::decode_udp_compact: zero flow id");
    }
    match frame_type {
        DATAGRAM_UDP_OPEN_DATA => {
            if buf.len() < COMPACT_HEADER_LEN + 3 {
                bail!("protocol::datagram::decode_udp_compact: short open frame");
            }
            let downlink = match buf[10] {
                1 => Carrier::Tcp,
                2 => Carrier::Udp,
                value => bail!("protocol::datagram::decode_udp_compact: invalid carrier: {value}"),
            };
            let target_len = u16::from_be_bytes([buf[11], buf[12]]) as usize;
            let target_end = 13usize.saturating_add(target_len);
            if target_len == 0 || target_len > TARGET_LEN_MAX || target_end > buf.len() {
                bail!("protocol::datagram::decode_udp_compact: invalid target length");
            }
            let target = std::str::from_utf8(&buf[13..target_end])?.to_string();
            validate_target(&target)
                .map_err(|e| anyhow::anyhow!("protocol::datagram::decode_udp_compact: {e}"))?;
            Ok(CompactUdpFrame::OpenData {
                flow_id,
                downlink,
                target,
                payload: &buf[target_end..],
            })
        }
        DATAGRAM_UDP_OPEN_ACK => {
            if buf.len() != COMPACT_HEADER_LEN {
                bail!("protocol::datagram::decode_udp_compact: ACK payload");
            }
            Ok(CompactUdpFrame::OpenAck { flow_id })
        }
        DATAGRAM_UDP_DATA => Ok(CompactUdpFrame::Data {
            flow_id,
            payload: &buf[COMPACT_HEADER_LEN..],
        }),
        DATAGRAM_UDP_COMPACT_CLOSE => {
            if buf.len() != COMPACT_HEADER_LEN {
                bail!("protocol::datagram::decode_udp_compact: CLOSE payload");
            }
            Ok(CompactUdpFrame::Close { flow_id })
        }
        value => bail!("protocol::datagram::decode_udp_compact: invalid type: {value}"),
    }
}

const DATAGRAM_HEADER_FIXED_LEN: usize = 1 + 1 + 8 + 2;

/// Owned header fields plus the offset of the borrowed payload.
pub(crate) struct DecodedUdpDatagram {
    pub(crate) frame_type: u8,
    pub(crate) flow_id: u64,
    pub(crate) target_addr: String,
    pub(crate) payload_offset: usize,
}

/// Encodes a UDP datagram frame with payload.
pub fn encode_udp_datagram(
    frame_type: u8,
    flow_id: u64,
    target_addr: &str,
    payload: &[u8],
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<Vec<u8>> {
    let header = new_udp_datagram_header(frame_type, flow_id, target_addr, protocol_spec)
        .map_err(|e| anyhow::anyhow!("protocol::datagram::encode_udp_datagram: {e}"))?;
    let mut buf = header;
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Builds only the reusable UDP datagram header for a flow.
pub fn new_udp_datagram_header(
    frame_type: u8,
    flow_id: u64,
    target_addr: &str,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<Vec<u8>> {
    udp_datagram_header_size(frame_type, target_addr)
        .map_err(|e| anyhow::anyhow!("protocol::datagram::new_udp_datagram_header: {e}"))?;
    let mut buf = vec![0; DATAGRAM_HEADER_FIXED_LEN + target_addr.len()];
    write_udp_datagram_header(&mut buf, frame_type, flow_id, target_addr, protocol_spec);
    Ok(buf)
}

fn udp_datagram_header_size(frame_type: u8, target_addr: &str) -> Result<usize> {
    if !matches!(
        frame_type,
        DATAGRAM_UDP_REQUEST | DATAGRAM_UDP_RESPONSE | DATAGRAM_UDP_CLOSE
    ) {
        bail!("protocol::datagram::udp_datagram_header_size: invalid frame type: {frame_type}");
    }
    validate_target(target_addr)
        .map_err(|e| anyhow::anyhow!("protocol::datagram::udp_datagram_header_size: {e}"))?;
    check_target_len("protocol::datagram::udp_datagram_header_size", target_addr)?;
    Ok(DATAGRAM_HEADER_FIXED_LEN + target_addr.len())
}

fn write_udp_datagram_header(
    buf: &mut [u8],
    frame_type: u8,
    flow_id: u64,
    target_addr: &str,
    protocol_spec: &EffectiveProtocolSpec,
) {
    let target_len = (target_addr.len() as u16).to_be_bytes();
    let mut offset = 0;
    // The field order is part of the effective spec, so encode by walking the
    // derived layout instead of writing the canonical order directly.
    for element in protocol_spec.frame_layout.udp {
        match element {
            UdpFrameElement::Version => {
                buf[offset] = PROXY_FRAME_VERSION;
                offset += 1;
            }
            UdpFrameElement::Type => {
                buf[offset] = frame_type;
                offset += 1;
            }
            UdpFrameElement::FlowId => {
                buf[offset..offset + 8].copy_from_slice(&flow_id.to_be_bytes());
                offset += 8;
            }
            UdpFrameElement::Target => {
                buf[offset..offset + 2].copy_from_slice(&target_len);
                offset += 2;
                buf[offset..offset + target_addr.len()].copy_from_slice(target_addr.as_bytes());
                offset += target_addr.len();
            }
        }
    }
    debug_assert_eq!(offset, buf.len());
}

/// Decodes a UDP datagram frame and returns the remaining payload slice.
pub fn decode_udp_datagram<'a>(
    buf: &'a [u8],
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<(u8, u64, String, &'a [u8])> {
    let decoded = decode_udp_datagram_parts(buf, protocol_spec)?;
    Ok((
        decoded.frame_type,
        decoded.flow_id,
        decoded.target_addr,
        &buf[decoded.payload_offset..],
    ))
}

/// Decodes the owned header fields while leaving payload ownership to the caller.
pub(crate) fn decode_udp_datagram_parts(
    buf: &[u8],
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<DecodedUdpDatagram> {
    if buf.len() < DATAGRAM_HEADER_FIXED_LEN {
        bail!("protocol::datagram::decode_udp_datagram: frame too short");
    }

    let mut offset = 0;
    let mut frame_type = None;
    let mut flow_id = None;
    let mut target_addr = None;
    // Decode fields in the same spec-derived order used during encoding.
    for element in protocol_spec.frame_layout.udp {
        match element {
            UdpFrameElement::Version => {
                let version = *buf.get(offset).ok_or_else(|| {
                    anyhow::anyhow!("protocol::datagram::decode_udp_datagram: missing version")
                })?;
                offset += 1;
                if version != PROXY_FRAME_VERSION {
                    bail!(
                        "protocol::datagram::decode_udp_datagram: unsupported frame version: {version}"
                    );
                }
            }
            UdpFrameElement::Type => {
                frame_type = Some(*buf.get(offset).ok_or_else(|| {
                    anyhow::anyhow!("protocol::datagram::decode_udp_datagram: missing frame type")
                })?);
                offset += 1;
            }
            UdpFrameElement::FlowId => {
                let Some(bytes) = buf.get(offset..offset + 8) else {
                    bail!("protocol::datagram::decode_udp_datagram: missing flow id");
                };
                flow_id = Some(u64::from_be_bytes(bytes.try_into().expect("slice len")));
                offset += 8;
            }
            UdpFrameElement::Target => {
                let Some(len_bytes) = buf.get(offset..offset + 2) else {
                    bail!("protocol::datagram::decode_udp_datagram: missing target length");
                };
                let target_len =
                    u16::from_be_bytes(len_bytes.try_into().expect("slice len")) as usize;
                offset += 2;
                if target_len == 0 || target_len > TARGET_LEN_MAX || buf.len() < offset + target_len
                {
                    bail!(
                        "protocol::datagram::decode_udp_datagram: invalid target length: {target_len}"
                    );
                }
                let target = std::str::from_utf8(&buf[offset..offset + target_len])
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "protocol::datagram::decode_udp_datagram: invalid target UTF-8: {e}"
                        )
                    })?
                    .to_string();
                offset += target_len;
                validate_target(&target)
                    .map_err(|e| anyhow::anyhow!("protocol::datagram::decode_udp_datagram: {e}"))?;
                target_addr = Some(target);
            }
        }
    }

    let frame_type = frame_type.ok_or_else(|| {
        anyhow::anyhow!("protocol::datagram::decode_udp_datagram: missing frame type")
    })?;
    if !matches!(
        frame_type,
        DATAGRAM_UDP_REQUEST | DATAGRAM_UDP_RESPONSE | DATAGRAM_UDP_CLOSE
    ) {
        bail!("protocol::datagram::decode_udp_datagram: invalid frame type: {frame_type}");
    }
    let flow_id = flow_id.ok_or_else(|| {
        anyhow::anyhow!("protocol::datagram::decode_udp_datagram: missing flow id")
    })?;
    let target_addr = target_addr.ok_or_else(|| {
        anyhow::anyhow!("protocol::datagram::decode_udp_datagram: missing target")
    })?;

    Ok(DecodedUdpDatagram {
        frame_type,
        flow_id,
        target_addr,
        payload_offset: offset,
    })
}

/// Reuses an output allocation by replacing it with `header || payload`.
pub fn append_frame_payload(dst: &mut Vec<u8>, header: &[u8], payload: &[u8]) {
    dst.clear();
    dst.reserve(header.len() + payload.len());
    dst.extend_from_slice(header);
    dst.extend_from_slice(payload);
}

#[cfg(test)]
#[path = "../tests/protocol/datagram.rs"]
mod tests;
