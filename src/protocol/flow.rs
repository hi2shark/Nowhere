// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Compact logical-flow metadata shared by every carrier.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Logical session identifier shared by a transport bundle.
pub const SESSION_ID_LEN: usize = 16;
/// Fixed binary flow header length.
pub const FLOW_HEADER_LEN: usize = 5;

const ROLE_MASK: u8 = 0b0000_0011;
const KIND_BIT: u8 = 0b0000_0100;
const UPLINK_BIT: u8 = 0b0000_1000;
const DOWNLINK_BIT: u8 = 0b0001_0000;
const RESERVED_MASK: u8 = 0b1110_0000;

pub type SessionId = [u8; SESSION_ID_LEN];
/// Flow identifier scoped to one logical session.
pub type FlowId = u32;

/// Relationship of the current physical lane to a logical flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowRole {
    /// One symmetric lane carries both directions.
    Duplex = 0,
    /// First half of an asymmetric flow; carries the target and uplink.
    Open = 1,
    /// Second half of an asymmetric flow; carries the downlink.
    Attach = 2,
}

/// Proxied payload semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowKind {
    Tcp = 0,
    Udp = 1,
}

/// Physical carrier selected for one flow direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Carrier {
    TlsTcp = 0,
    Quic = 1,
}

/// Fully decoded logical-flow metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowHeader {
    pub role: FlowRole,
    pub flow_id: FlowId,
    pub kind: FlowKind,
    pub uplink: Carrier,
    pub downlink: Carrier,
}

impl FlowHeader {
    /// Validates role, ID, and carrier invariants independent of the current lane.
    pub fn validate(self) -> Result<()> {
        if self.flow_id == 0 {
            bail!("protocol::flow::FlowHeader::validate: zero flow id");
        }
        match self.role {
            FlowRole::Duplex if self.uplink != self.downlink => {
                bail!("protocol::flow::FlowHeader::validate: duplex carrier mismatch")
            }
            FlowRole::Open | FlowRole::Attach if self.uplink == self.downlink => {
                bail!("protocol::flow::FlowHeader::validate: split carriers must differ")
            }
            _ => Ok(()),
        }
    }

    /// Validates that this header arrived on the physical carrier it declares.
    pub fn validate_on(self, current: Carrier) -> Result<()> {
        self.validate()?;
        let expected = match self.role {
            FlowRole::Duplex | FlowRole::Open => self.uplink,
            FlowRole::Attach => self.downlink,
        };
        if current != expected {
            bail!("protocol::flow::FlowHeader::validate_on: carrier mismatch");
        }
        Ok(())
    }

    /// Whether this lane is followed by a binary target.
    pub const fn carries_target(self) -> bool {
        matches!(self.role, FlowRole::Duplex | FlowRole::Open)
    }
}

/// Encodes a header after validating its semantic invariants.
pub fn encode_flow_header(header: FlowHeader) -> Result<[u8; FLOW_HEADER_LEN]> {
    header.validate()?;
    Ok(write_flow_header(header))
}

/// Encodes a flow header into a fixed stack array.
///
/// Callers accepting untrusted or dynamically assembled metadata should use
/// [`encode_flow_header`] first. This low-level spelling remains allocation-free
/// and matches the existing request-building call sites.
pub fn write_flow_header(header: FlowHeader) -> [u8; FLOW_HEADER_LEN] {
    let flags = header.role as u8
        | (header.kind as u8) << 2
        | (header.uplink as u8) << 3
        | (header.downlink as u8) << 4;
    let mut output = [0; FLOW_HEADER_LEN];
    output[0] = flags;
    output[1..].copy_from_slice(&header.flow_id.to_be_bytes());
    output
}

/// Decodes exactly one fixed flow header.
pub fn decode_flow_header(bytes: &[u8]) -> Result<FlowHeader> {
    if bytes.len() != FLOW_HEADER_LEN {
        bail!(
            "protocol::flow::decode_flow_header: invalid header length: {}",
            bytes.len()
        );
    }
    let flags = bytes[0];
    if flags & RESERVED_MASK != 0 {
        bail!("protocol::flow::decode_flow_header: reserved flags are non-zero");
    }
    let role = match flags & ROLE_MASK {
        0 => FlowRole::Duplex,
        1 => FlowRole::Open,
        2 => FlowRole::Attach,
        value => bail!("protocol::flow::decode_flow_header: invalid role: {value}"),
    };
    let kind = if flags & KIND_BIT == 0 {
        FlowKind::Tcp
    } else {
        FlowKind::Udp
    };
    let uplink = if flags & UPLINK_BIT == 0 {
        Carrier::TlsTcp
    } else {
        Carrier::Quic
    };
    let downlink = if flags & DOWNLINK_BIT == 0 {
        Carrier::TlsTcp
    } else {
        Carrier::Quic
    };
    let header = FlowHeader {
        role,
        flow_id: u32::from_be_bytes(bytes[1..].try_into().expect("fixed flow id")),
        kind,
        uplink,
        downlink,
    };
    header.validate()?;
    Ok(header)
}

/// Reads exactly one flow header, leaving initial payload buffered behind it.
pub async fn read_flow_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FlowHeader> {
    let mut bytes = [0; FLOW_HEADER_LEN];
    reader
        .read_exact(&mut bytes)
        .await
        .context("protocol::flow::read_flow_header: failed to read header")?;
    decode_flow_header(&bytes)
}

#[cfg(test)]
#[path = "../tests/protocol/flow.rs"]
mod tests;
