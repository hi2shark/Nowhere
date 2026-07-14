// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport-independent logical flow envelope used to pair TCP and QUIC halves.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SESSION_ID_LEN: usize = 16;
pub type SessionId = [u8; SESSION_ID_LEN];

pub const FLOW_FRAME_MAGIC: u8 = 0xf1;
const FLOW_FRAME_VERSION: u8 = 1;
const FLOW_HEADER_LEN: usize = 14;

pub const FLOW_RESULT_MAGIC: u8 = 0xf2;
const FLOW_RESULT_VERSION: u8 = 1;
const FLOW_RESULT_LEN: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowRole {
    Open = 1,
    Attach = 2,
    Duplex = 3,
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
    TlsTcp = 1,
    Quic = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowStatus {
    Ready = 1,
    Reject = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowErrorCode {
    InvalidRequest = 1,
    MetadataConflict = 2,
    PairTimeout = 3,
    FlowLimit = 4,
    DialFailed = 5,
    SessionReplaced = 6,
    InternalError = 7,
}

impl TryFrom<u8> for FlowErrorCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::MetadataConflict),
            3 => Ok(Self::PairTimeout),
            4 => Ok(Self::FlowLimit),
            5 => Ok(Self::DialFailed),
            6 => Ok(Self::SessionReplaced),
            7 => Ok(Self::InternalError),
            value => bail!("protocol::flow: invalid flow error code: {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowResult {
    Ready,
    Reject(FlowErrorCode),
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
        3 => FlowRole::Duplex,
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
        1 => Ok(Carrier::TlsTcp),
        2 => Ok(Carrier::Quic),
        value => bail!("protocol::flow::read_flow_header: invalid carrier: {value}"),
    };
    let header = FlowHeader {
        role,
        flow_id,
        kind,
        uplink: carrier(bytes[12])?,
        downlink: carrier(bytes[13])?,
    };
    match header.role {
        FlowRole::Duplex if header.uplink != header.downlink => {
            bail!("protocol::flow::read_flow_header: duplex carrier mismatch")
        }
        FlowRole::Open | FlowRole::Attach if header.uplink == header.downlink => {
            bail!("protocol::flow::read_flow_header: split carriers must differ")
        }
        _ => Ok(header),
    }
}

pub fn encode_flow_result(result: FlowResult) -> [u8; FLOW_RESULT_LEN] {
    let (status, code) = match result {
        FlowResult::Ready => (FlowStatus::Ready as u8, 0),
        FlowResult::Reject(code) => (FlowStatus::Reject as u8, code as u8),
    };
    [FLOW_RESULT_MAGIC, FLOW_RESULT_VERSION, status, code]
}

pub async fn write_flow_result<W: AsyncWrite + Unpin>(
    writer: &mut W,
    result: FlowResult,
) -> Result<()> {
    writer
        .write_all(&encode_flow_result(result))
        .await
        .context("protocol::flow::write_flow_result: failed to write result")
}

pub async fn read_flow_result<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FlowResult> {
    let mut bytes = [0; FLOW_RESULT_LEN];
    reader
        .read_exact(&mut bytes)
        .await
        .context("protocol::flow::read_flow_result: failed to read result")?;
    if bytes[0] != FLOW_RESULT_MAGIC || bytes[1] != FLOW_RESULT_VERSION {
        bail!("protocol::flow::read_flow_result: invalid magic or version");
    }
    match (bytes[2], bytes[3]) {
        (status, 0) if status == FlowStatus::Ready as u8 => Ok(FlowResult::Ready),
        (status, code) if status == FlowStatus::Reject as u8 => {
            Ok(FlowResult::Reject(code.try_into()?))
        }
        _ => bail!("protocol::flow::read_flow_result: invalid status or code"),
    }
}

#[cfg(test)]
#[path = "../tests/protocol/flow.rs"]
mod tests;
