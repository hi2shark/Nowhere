// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Logical TCP flow setup across every carrier combination.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::common::socks::{
    REPLY_CONNECTION_NOT_ALLOWED, REPLY_GENERAL_FAILURE, REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED, REPLY_TTL_EXPIRED, SocksAddress,
};
use crate::common::{handshake_timeout, tcp_read_timeout};
use crate::protocol::{
    AUTH_FRAME_LEN, AuthFrame, Carrier, FLOW_HEADER_LEN, FlowHeader, FlowKind, FlowResult,
    FlowRole, SetupResult, TARGET_MAX_ENCODED_LEN, Target, encode_target_into, read_flow_result,
    write_flow_header,
};

use super::VectorInner;
use super::config::CarrierMode;
use super::flow_id::FlowLease;
use super::session::{LinkGuard, QuicSession};
pub(super) type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
pub(super) type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

pub(super) struct PhysicalLane {
    pub(super) reader: Option<BoxReader>,
    pub(super) writer: Option<BoxWriter>,
    pending_auth: Option<AuthFrame>,
    pending_quic_auth: bool,
    _link: Option<LinkGuard>,
    pub(super) _quic: Option<Arc<QuicSession>>,
}

impl PhysicalLane {
    pub(super) fn take_reader(&mut self) -> BoxReader {
        self.reader.take().expect("physical lane reader")
    }

    pub(super) fn take_writer(&mut self) -> BoxWriter {
        self.writer.take().expect("physical lane writer")
    }

    pub(super) fn take_pending_auth(&mut self) -> Option<AuthFrame> {
        self.pending_auth.take()
    }

    pub(super) fn mark_auth_sent(&mut self) {
        self.pending_quic_auth = false;
    }
}

impl Drop for PhysicalLane {
    fn drop(&mut self) {
        if self.pending_quic_auth
            && let Some(session) = &self._quic
        {
            session
                .connection
                .close(quinn::VarInt::from_u32(0), b"authentication abandoned");
        }
    }
}

pub(super) struct TcpTunnel {
    reader: BoxReader,
    writer: BoxWriter,
    _lanes: Vec<PhysicalLane>,
    _lease: FlowLease,
    uplink: Carrier,
    downlink: Carrier,
    _flow_permit: OwnedSemaphorePermit,
}

impl TcpTunnel {
    pub(super) fn socks_reply(&self) -> u8 {
        REPLY_SUCCEEDED
    }
}

pub(super) async fn open_tcp(
    vector: Arc<VectorInner>,
    target: &SocksAddress,
) -> std::result::Result<TcpTunnel, OpenFlowError> {
    let target = to_target(target).map_err(OpenFlowError::Protocol)?;
    let flow_permit = vector
        .tcp_flow_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| OpenFlowError::Setup(SetupResult::FlowLimit))?;
    let lease = vector
        .flow_ids
        .allocate()
        .map_err(OpenFlowError::Protocol)?;
    let flow_id = lease.id();
    let uplink = carrier(vector.config.up);
    let downlink = carrier(vector.config.down);

    if uplink == downlink {
        let mut lane = open_lane(vector.clone(), vector.config.up)
            .await
            .map_err(OpenFlowError::Transport)?;
        let header = FlowHeader {
            role: FlowRole::Duplex,
            flow_id,
            kind: FlowKind::Tcp,
            uplink,
            downlink,
        };
        let pending_auth = lane.take_pending_auth();
        write_open_request(
            lane.writer.as_mut().expect("lane writer"),
            pending_auth,
            header,
            &target,
        )
        .await
        .map_err(OpenFlowError::Transport)?;
        lane.mark_auth_sent();
        read_ready(lane.reader.as_mut().expect("lane reader"))
            .await
            .map_err(OpenFlowError::Setup)?;
        let reader = lane.take_reader();
        let writer = lane.take_writer();
        return Ok(TcpTunnel {
            reader,
            writer,
            _lanes: vec![lane],
            _lease: lease,
            uplink,
            downlink,
            _flow_permit: flow_permit,
        });
    }

    let (uplink_result, downlink_result) = tokio::join!(
        open_lane(vector.clone(), vector.config.up),
        open_lane(vector.clone(), vector.config.down),
    );
    let mut uplink_lane = uplink_result.map_err(OpenFlowError::Transport)?;
    let mut downlink_lane = downlink_result.map_err(OpenFlowError::Transport)?;
    let open_header = FlowHeader {
        role: FlowRole::Open,
        flow_id,
        kind: FlowKind::Tcp,
        uplink,
        downlink,
    };
    let attach_header = FlowHeader {
        role: FlowRole::Attach,
        ..open_header
    };
    let pending_auth = uplink_lane.take_pending_auth();
    write_open_request(
        uplink_lane.writer.as_mut().expect("uplink writer"),
        pending_auth,
        open_header,
        &target,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    uplink_lane.mark_auth_sent();
    let pending_auth = downlink_lane.take_pending_auth();
    write_header(
        downlink_lane.writer.as_mut().expect("downlink writer"),
        pending_auth,
        attach_header,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    downlink_lane.mark_auth_sent();
    read_ready(downlink_lane.reader.as_mut().expect("downlink reader"))
        .await
        .map_err(OpenFlowError::Setup)?;

    let writer = uplink_lane.take_writer();
    let reader = downlink_lane.take_reader();
    Ok(TcpTunnel {
        reader,
        writer,
        _lanes: vec![uplink_lane, downlink_lane],
        _lease: lease,
        uplink,
        downlink,
        _flow_permit: flow_permit,
    })
}

pub(super) async fn relay_tcp(
    vector: Arc<VectorInner>,
    client: TcpStream,
    mut tunnel: TcpTunnel,
    client_peer: std::net::SocketAddr,
    target: &SocksAddress,
) -> Result<()> {
    vector.stats.add_session(false);
    let _session = SessionGuard::new(vector.clone(), false);
    vector.logger.debug(format_args!(
        "vector::flow::relay_tcp: exchange starting: UP[{}] {client_peer} -> {} -> {} -> {target} | DOWN[{}] {target} -> {} -> {} -> {client_peer}",
        carrier_name(tunnel.uplink),
        vector.config.socks.endpoint(),
        vector.config.portal_endpoint(),
        carrier_name(tunnel.downlink),
        vector.config.portal_endpoint(),
        vector.config.socks.endpoint(),
    ));

    let (mut client_read, mut client_write) = client.into_split();
    let mut up_buffer = vector.buffers.get_tcp_buffer();
    let mut down_buffer = vector.buffers.get_tcp_buffer();
    let client_to_portal = async {
        loop {
            let read = client_read.read(&mut up_buffer).await?;
            if read == 0 {
                tunnel.writer.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(rate) = &vector.rate_limiter {
                rate.wait_read(read as i64).await;
            }
            tunnel.writer.write_all(&up_buffer[..read]).await?;
            vector
                .stats
                .tcp_rx
                .fetch_add(read as u64, Ordering::Relaxed);
            carrier_counter(&vector, tunnel.uplink, true).fetch_add(read as u64, Ordering::Relaxed);
        }
    };
    let portal_to_client = async {
        loop {
            let read = tunnel.reader.read(&mut down_buffer).await?;
            if read == 0 {
                client_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(rate) = &vector.rate_limiter {
                rate.wait_write(read as i64).await;
            }
            client_write.write_all(&down_buffer[..read]).await?;
            vector
                .stats
                .tcp_tx
                .fetch_add(read as u64, Ordering::Relaxed);
            carrier_counter(&vector, tunnel.downlink, false)
                .fetch_add(read as u64, Ordering::Relaxed);
        }
    };
    tokio::pin!(client_to_portal);
    tokio::pin!(portal_to_client);
    let result = tokio::select! {
        result = &mut client_to_portal => {
            result?;
            timeout(tcp_read_timeout(), &mut portal_to_client).await.unwrap_or(Ok(()))
        }
        result = &mut portal_to_client => {
            result?;
            timeout(tcp_read_timeout(), &mut client_to_portal).await.unwrap_or(Ok(()))
        }
    };
    vector.logger.debug(format_args!(
        "vector::flow::relay_tcp: exchange complete: {}",
        match &result {
            Ok(()) => "EOF".to_owned(),
            Err(error) => error.to_string(),
        }
    ));
    result
}

pub(super) async fn open_lane(vector: Arc<VectorInner>, mode: CarrierMode) -> Result<PhysicalLane> {
    match mode {
        CarrierMode::Tcp => {
            let parts = vector.tls_pool.acquire().await?.into_parts();
            Ok(PhysicalLane {
                reader: Some(Box::pin(parts.reader)),
                writer: Some(Box::pin(parts.writer)),
                pending_auth: parts.pending_auth,
                pending_quic_auth: false,
                _link: Some(parts.link),
                _quic: None,
            })
        }
        CarrierMode::Udp => {
            let session = vector.quic.get().await?;
            let (writer, reader, pending_auth) = session.open_bi().await?;
            let pending_quic_auth = pending_auth.is_some();
            Ok(PhysicalLane {
                reader: Some(Box::pin(reader)),
                writer: Some(Box::pin(writer)),
                pending_auth,
                pending_quic_auth,
                _link: None,
                _quic: Some(session),
            })
        }
    }
}

pub(super) async fn write_open_request(
    writer: &mut BoxWriter,
    pending_auth: Option<AuthFrame>,
    header: FlowHeader,
    target: &Target,
) -> Result<()> {
    header.validate()?;
    let flow = write_flow_header(header);
    let mut request = [0u8; AUTH_FRAME_LEN + FLOW_HEADER_LEN + TARGET_MAX_ENCODED_LEN];
    let auth_len = if let Some(auth) = pending_auth {
        request[..AUTH_FRAME_LEN].copy_from_slice(&auth);
        AUTH_FRAME_LEN
    } else {
        0
    };
    request[auth_len..auth_len + FLOW_HEADER_LEN].copy_from_slice(&flow);
    let target_offset = auth_len + FLOW_HEADER_LEN;
    let target_len = encode_target_into(target, &mut request[target_offset..])?;
    timeout(handshake_timeout(), async {
        writer
            .write_all(&request[..target_offset + target_len])
            .await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("vector::flow::write_open_request: request write timeout"))?
    .context("vector::flow::write_open_request: failed to write request")?;
    Ok(())
}

pub(super) async fn write_header(
    writer: &mut BoxWriter,
    pending_auth: Option<AuthFrame>,
    header: FlowHeader,
) -> Result<()> {
    header.validate()?;
    let flow = write_flow_header(header);
    let mut request = [0u8; AUTH_FRAME_LEN + FLOW_HEADER_LEN];
    let auth_len = if let Some(auth) = pending_auth {
        request[..AUTH_FRAME_LEN].copy_from_slice(&auth);
        AUTH_FRAME_LEN
    } else {
        0
    };
    request[auth_len..auth_len + FLOW_HEADER_LEN].copy_from_slice(&flow);
    timeout(handshake_timeout(), async {
        writer
            .write_all(&request[..auth_len + FLOW_HEADER_LEN])
            .await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("vector::flow::write_header: flow header write timeout"))?
    .context("vector::flow::write_header: failed to write flow header")?;
    Ok(())
}

pub(super) async fn read_ready(reader: &mut BoxReader) -> std::result::Result<(), SetupResult> {
    let result = timeout(handshake_timeout(), read_flow_result(reader))
        .await
        .map_err(|_| SetupResult::InternalError)
        .and_then(|result| result.map_err(|_| SetupResult::InternalError))?;
    match result {
        FlowResult::Ready => Ok(()),
        FlowResult::Reject(error) => Err(error.into()),
    }
}

pub(super) fn to_target(address: &SocksAddress) -> Result<Target> {
    match address {
        SocksAddress::Ip(address) => Target::ip(*address),
        SocksAddress::Domain(host, port) => Target::domain(host.clone(), *port),
    }
}

pub(super) fn carrier(mode: CarrierMode) -> Carrier {
    match mode {
        CarrierMode::Tcp => Carrier::TlsTcp,
        CarrierMode::Udp => Carrier::Quic,
    }
}

pub(super) fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::TlsTcp => "TCP",
        Carrier::Quic => "UDP",
    }
}

pub(super) fn carrier_counter(
    vector: &VectorInner,
    carrier: Carrier,
    uplink: bool,
) -> &std::sync::atomic::AtomicU64 {
    match (carrier, uplink) {
        (Carrier::TlsTcp, true) => &vector.stats.up_tcp,
        (Carrier::Quic, true) => &vector.stats.up_udp,
        (Carrier::TlsTcp, false) => &vector.stats.down_tcp,
        (Carrier::Quic, false) => &vector.stats.down_udp,
    }
}

pub(super) enum OpenFlowError {
    Setup(SetupResult),
    Transport(anyhow::Error),
    Protocol(anyhow::Error),
}

impl OpenFlowError {
    pub(super) fn socks_reply(&self) -> u8 {
        match self {
            Self::Setup(SetupResult::InvalidRequest | SetupResult::FlowLimit) => {
                REPLY_CONNECTION_NOT_ALLOWED
            }
            Self::Setup(SetupResult::DialFailed) => REPLY_HOST_UNREACHABLE,
            Self::Setup(SetupResult::PairTimeout) => REPLY_TTL_EXPIRED,
            Self::Setup(_) => REPLY_GENERAL_FAILURE,
            Self::Transport(_) => REPLY_NETWORK_UNREACHABLE,
            Self::Protocol(_) => REPLY_GENERAL_FAILURE,
        }
    }
}

impl std::fmt::Display for OpenFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(result) => write!(formatter, "flow setup rejected: {}", result.as_str()),
            Self::Transport(error) | Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

pub(super) struct SessionGuard {
    vector: Arc<VectorInner>,
    udp: bool,
}

impl SessionGuard {
    pub(super) fn new(vector: Arc<VectorInner>, udp: bool) -> Self {
        Self { vector, udp }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.vector.stats.done_session(self.udp);
    }
}

#[cfg(test)]
#[path = "../tests/vector/flow.rs"]
mod tests;
