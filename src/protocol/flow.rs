// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport-independent logical flow envelope used to pair TCP and QUIC halves.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const SESSION_ID_LEN: usize = 16;
pub type SessionId = [u8; SESSION_ID_LEN];

pub const FLOW_FRAME_MAGIC: u8 = 0xf1;
const FLOW_FRAME_VERSION: u8 = 1;
const FLOW_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowRole {
    Open = 1,
    Attach = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowKind {
    Tcp = 1,
    Udp = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Carrier {
    Tcp = 1,
    Udp = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowHeader {
    pub role: FlowRole,
    pub flow_id: u64,
    pub kind: FlowKind,
    pub uplink: Carrier,
    pub downlink: Carrier,
}

pub fn write_flow_header(header: FlowHeader) -> [u8; FLOW_HEADER_LEN] {
    let mut out = [0; FLOW_HEADER_LEN];
    out[0] = FLOW_FRAME_MAGIC;
    out[1] = FLOW_FRAME_VERSION;
    out[2] = header.role as u8;
    out[3..11].copy_from_slice(&header.flow_id.to_be_bytes());
    out[11] = header.kind as u8;
    out[12] = header.uplink as u8;
    out[13] = header.downlink as u8;
    out
}

pub async fn read_flow_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FlowHeader> {
    let mut bytes = [0; FLOW_HEADER_LEN];
    reader
        .read_exact(&mut bytes)
        .await
        .context("protocol::flow::read_flow_header: failed to read header")?;
    if bytes[0] != FLOW_FRAME_MAGIC || bytes[1] != FLOW_FRAME_VERSION {
        bail!("protocol::flow::read_flow_header: invalid magic or version");
    }
    let role = match bytes[2] {
        1 => FlowRole::Open,
        2 => FlowRole::Attach,
        value => bail!("protocol::flow::read_flow_header: invalid role: {value}"),
    };
    let flow_id = u64::from_be_bytes(bytes[3..11].try_into().expect("fixed flow id"));
    if flow_id == 0 {
        bail!("protocol::flow::read_flow_header: zero flow id");
    }
    let kind = match bytes[11] {
        1 => FlowKind::Tcp,
        2 => FlowKind::Udp,
        value => bail!("protocol::flow::read_flow_header: invalid kind: {value}"),
    };
    let carrier = |value| match value {
        1 => Ok(Carrier::Tcp),
        2 => Ok(Carrier::Udp),
        value => bail!("protocol::flow::read_flow_header: invalid carrier: {value}"),
    };
    Ok(FlowHeader {
        role,
        flow_id,
        kind,
        uplink: carrier(bytes[12])?,
        downlink: carrier(bytes[13])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let expected = FlowHeader {
            role: FlowRole::Attach,
            flow_id: 42,
            kind: FlowKind::Udp,
            uplink: Carrier::Tcp,
            downlink: Carrier::Udp,
        };
        let bytes = write_flow_header(expected);
        assert_eq!(bytes, [0xf1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 42, 2, 1, 2]);
        assert_eq!(
            read_flow_header(&mut bytes.as_slice()).await.unwrap(),
            expected
        );
    }
}
