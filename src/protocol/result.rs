// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Single-byte flow setup result shared by stream transports.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Fixed setup-result frame length.
pub const SETUP_RESULT_LEN: usize = 1;

/// Direct wire representation of a flow setup outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SetupResult {
    Ready = 0,
    InvalidRequest = 1,
    MetadataConflict = 2,
    PairTimeout = 3,
    FlowLimit = 4,
    DialFailed = 5,
    SessionReplaced = 6,
    InternalError = 7,
}

impl SetupResult {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::InvalidRequest => "invalid request",
            Self::MetadataConflict => "metadata conflict",
            Self::PairTimeout => "pair timeout",
            Self::FlowLimit => "flow limit",
            Self::DialFailed => "dial failed",
            Self::SessionReplaced => "session replaced",
            Self::InternalError => "internal error",
        }
    }
}

impl TryFrom<u8> for SetupResult {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::MetadataConflict),
            3 => Ok(Self::PairTimeout),
            4 => Ok(Self::FlowLimit),
            5 => Ok(Self::DialFailed),
            6 => Ok(Self::SessionReplaced),
            7 => Ok(Self::InternalError),
            value => bail!("protocol::result: invalid setup result: {value}"),
        }
    }
}

/// Rejection codes retained as a convenient application-level type.
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
        let setup = SetupResult::try_from(value)?;
        Self::try_from(setup)
    }
}

impl TryFrom<SetupResult> for FlowErrorCode {
    type Error = anyhow::Error;

    fn try_from(value: SetupResult) -> Result<Self> {
        match value {
            SetupResult::Ready => bail!("protocol::result: READY is not an error"),
            SetupResult::InvalidRequest => Ok(Self::InvalidRequest),
            SetupResult::MetadataConflict => Ok(Self::MetadataConflict),
            SetupResult::PairTimeout => Ok(Self::PairTimeout),
            SetupResult::FlowLimit => Ok(Self::FlowLimit),
            SetupResult::DialFailed => Ok(Self::DialFailed),
            SetupResult::SessionReplaced => Ok(Self::SessionReplaced),
            SetupResult::InternalError => Ok(Self::InternalError),
        }
    }
}

impl From<FlowErrorCode> for SetupResult {
    fn from(value: FlowErrorCode) -> Self {
        match value {
            FlowErrorCode::InvalidRequest => Self::InvalidRequest,
            FlowErrorCode::MetadataConflict => Self::MetadataConflict,
            FlowErrorCode::PairTimeout => Self::PairTimeout,
            FlowErrorCode::FlowLimit => Self::FlowLimit,
            FlowErrorCode::DialFailed => Self::DialFailed,
            FlowErrorCode::SessionReplaced => Self::SessionReplaced,
            FlowErrorCode::InternalError => Self::InternalError,
        }
    }
}

/// Application-level setup outcome used by existing pairing code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowResult {
    Ready,
    Reject(FlowErrorCode),
}

impl From<FlowResult> for SetupResult {
    fn from(value: FlowResult) -> Self {
        match value {
            FlowResult::Ready => Self::Ready,
            FlowResult::Reject(code) => code.into(),
        }
    }
}

impl From<SetupResult> for FlowResult {
    fn from(value: SetupResult) -> Self {
        if value == SetupResult::Ready {
            Self::Ready
        } else {
            Self::Reject(FlowErrorCode::try_from(value).expect("non-READY setup result"))
        }
    }
}

pub const fn encode_setup_result(result: SetupResult) -> [u8; SETUP_RESULT_LEN] {
    [result as u8]
}

pub fn decode_setup_result(bytes: &[u8]) -> Result<SetupResult> {
    if bytes.len() != SETUP_RESULT_LEN {
        bail!(
            "protocol::result::decode_setup_result: invalid result length: {}",
            bytes.len()
        );
    }
    bytes[0].try_into()
}

pub fn encode_flow_result(result: FlowResult) -> [u8; SETUP_RESULT_LEN] {
    encode_setup_result(result.into())
}

pub async fn write_setup_result<W: AsyncWrite + Unpin>(
    writer: &mut W,
    result: SetupResult,
) -> Result<()> {
    writer
        .write_all(&encode_setup_result(result))
        .await
        .context("protocol::result::write_setup_result: failed to write result")
}

pub async fn read_setup_result<R: AsyncRead + Unpin>(reader: &mut R) -> Result<SetupResult> {
    let mut byte = [0; SETUP_RESULT_LEN];
    reader
        .read_exact(&mut byte)
        .await
        .context("protocol::result::read_setup_result: failed to read result")?;
    decode_setup_result(&byte)
}

pub async fn write_flow_result<W: AsyncWrite + Unpin>(
    writer: &mut W,
    result: FlowResult,
) -> Result<()> {
    write_setup_result(writer, result.into()).await
}

pub async fn read_flow_result<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FlowResult> {
    Ok(read_setup_result(reader).await?.into())
}

#[cfg(test)]
#[path = "../tests/protocol/result.rs"]
mod tests;
