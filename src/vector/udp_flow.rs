// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Target-scoped UDP flow setup and packet transport.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::common::handshake_timeout;
use crate::common::socks::SocksAddress;
use crate::protocol::{Carrier, FlowHeader, FlowKind, FlowRole, write_udp_packet};

use super::VectorInner;
use super::config::CarrierMode;
use super::flow::{
    BoxReader, BoxWriter, OpenFlowError, PhysicalLane, SessionGuard, carrier, carrier_counter,
    open_lane, read_ready, to_target, write_header, write_open_request,
};
use super::flow_id::FlowLease;
use super::session::{QueuedDatagram, QuicSession};
pub(super) struct UdpTunnel {
    flow_id: u32,
    reader: Option<BoxReader>,
    writer: Option<BoxWriter>,
    down_datagrams: Option<mpsc::Receiver<QueuedDatagram>>,
    quic: Option<Arc<QuicSession>>,
    packet_id: u32,
    uot_read: UotReadState,
    pub(super) uplink: Carrier,
    pub(super) downlink: Carrier,
    vector: Arc<VectorInner>,
    _lanes: Vec<PhysicalLane>,
    _lease: FlowLease,
    _session: SessionGuard,
    _flow_permit: OwnedSemaphorePermit,
}

impl UdpTunnel {
    pub(super) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        if let Some(writer) = &mut self.writer {
            write_udp_packet(writer, payload).await?;
        } else if let Some(quic) = &self.quic {
            quic.send_udp(self.flow_id, &mut self.packet_id, payload)
                .await?;
        } else {
            bail!("vector::udp_flow::UdpTunnel::send: no uplink carrier");
        }
        self.vector
            .stats
            .udp_rx
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        carrier_counter(&self.vector, self.uplink, true)
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub(super) async fn recv_into(
        &mut self,
        payload: &mut Vec<u8>,
    ) -> Result<Option<ReceivedUdpPacket>> {
        let packet = if let Some(reader) = &mut self.reader {
            let Some(size) = self.uot_read.read_packet(reader, payload).await? else {
                return Ok(None);
            };
            ReceivedUdpPacket::Buffered(size)
        } else if let Some(receiver) = &mut self.down_datagrams {
            let Some(packet) = receiver.recv().await else {
                return Ok(None);
            };
            ReceivedUdpPacket::Owned(packet.payload)
        } else {
            bail!("vector::udp_flow::UdpTunnel::recv: no downlink carrier");
        };
        let size = packet.len();
        self.vector
            .stats
            .udp_tx
            .fetch_add(size as u64, Ordering::Relaxed);
        carrier_counter(&self.vector, self.downlink, false)
            .fetch_add(size as u64, Ordering::Relaxed);
        Ok(Some(packet))
    }

    pub(super) async fn close(&mut self) {
        if let Some(writer) = &mut self.writer {
            let _ = timeout(handshake_timeout(), writer.shutdown()).await;
        }
        if let Some(quic) = &self.quic {
            quic.close_udp(self.flow_id);
        }
    }
}

/// A UoT packet already in the reusable read buffer, or an owned zero-copy
/// slice received from Quinn.
pub(super) enum ReceivedUdpPacket {
    Buffered(usize),
    Owned(Bytes),
}

impl ReceivedUdpPacket {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Buffered(size) => *size,
            Self::Owned(payload) => payload.len(),
        }
    }

    pub(super) fn payload<'a>(&'a self, buffered: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Buffered(size) => &buffered[..*size],
            Self::Owned(payload) => payload,
        }
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        if let Some(quic) = &self.quic {
            quic.remove_udp(self.flow_id);
        }
    }
}

pub(super) async fn open_udp(
    vector: Arc<VectorInner>,
    address: &SocksAddress,
) -> std::result::Result<UdpTunnel, OpenFlowError> {
    let target = to_target(address).map_err(OpenFlowError::Protocol)?;
    let flow_permit = vector
        .udp_flow_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| OpenFlowError::Setup(crate::protocol::SetupResult::FlowLimit))?;
    let lease = vector
        .flow_ids
        .allocate()
        .map_err(OpenFlowError::Protocol)?;
    let flow_id = lease.id();
    let uplink = carrier(vector.config.up);
    let downlink = carrier(vector.config.down);

    let mut lanes = if uplink == downlink {
        vec![
            open_lane(vector.clone(), vector.config.up)
                .await
                .map_err(OpenFlowError::Transport)?,
        ]
    } else {
        let (uplink_lane, downlink_lane) = tokio::join!(
            open_lane(vector.clone(), vector.config.up),
            open_lane(vector.clone(), vector.config.down),
        );
        vec![
            uplink_lane.map_err(OpenFlowError::Transport)?,
            downlink_lane.map_err(OpenFlowError::Transport)?,
        ]
    };

    let quic = lanes.iter().find_map(|lane| lane._quic.clone());
    let mut down_datagrams = if vector.config.down == CarrierMode::Udp {
        Some(
            quic.as_ref()
                .expect("QUIC downlink has session")
                .register_udp(flow_id)
                .map_err(OpenFlowError::Transport)?,
        )
    } else {
        None
    };

    if let Err(error) =
        setup_udp_lanes(&vector, &mut lanes, flow_id, uplink, downlink, &target).await
    {
        if let Some(quic) = &quic {
            quic.remove_udp(flow_id);
        }
        return Err(error);
    }
    if down_datagrams.is_some()
        && let Err(error) = quic
            .as_ref()
            .expect("QUIC downlink has session")
            .activate_udp(flow_id)
    {
        if let Some(quic) = &quic {
            quic.remove_udp(flow_id);
        }
        return Err(OpenFlowError::Transport(error));
    }

    let writer = if vector.config.up == CarrierMode::Tcp {
        Some(lanes[0].take_writer())
    } else {
        None
    };
    let down_index = usize::from(uplink != downlink);
    let reader = if vector.config.down == CarrierMode::Tcp {
        Some(lanes[down_index].take_reader())
    } else {
        None
    };
    vector.stats.add_session(true);
    Ok(UdpTunnel {
        flow_id,
        reader,
        writer,
        down_datagrams: down_datagrams.take(),
        quic,
        packet_id: 1,
        uot_read: UotReadState::default(),
        uplink,
        downlink,
        _session: SessionGuard::new(vector.clone(), true),
        _flow_permit: flow_permit,
        vector,
        _lanes: lanes,
        _lease: lease,
    })
}

#[derive(Default)]
struct UotReadState {
    header: [u8; 2],
    header_read: usize,
    payload_len: Option<usize>,
    payload_read: usize,
}

impl UotReadState {
    /// Reads incrementally so cancelling an in-progress downlink read to send
    /// an uplink packet cannot lose UoT framing bytes.
    async fn read_packet(
        &mut self,
        reader: &mut BoxReader,
        payload: &mut Vec<u8>,
    ) -> Result<Option<usize>> {
        while self.header_read != self.header.len() {
            let read = reader
                .read(&mut self.header[self.header_read..])
                .await
                .context("vector::udp_flow::UotReadState: failed to read packet length")?;
            if read == 0 {
                if self.header_read == 0 {
                    payload.clear();
                    return Ok(None);
                }
                bail!("vector::udp_flow::UotReadState: truncated packet length");
            }
            self.header_read += read;
        }

        let payload_len = *self
            .payload_len
            .get_or_insert_with(|| u16::from_be_bytes(self.header) as usize);
        payload.resize(payload_len, 0);
        while self.payload_read != payload_len {
            let read = reader
                .read(&mut payload[self.payload_read..])
                .await
                .context("vector::udp_flow::UotReadState: failed to read packet payload")?;
            if read == 0 {
                bail!("vector::udp_flow::UotReadState: truncated packet payload");
            }
            self.payload_read += read;
        }

        self.header_read = 0;
        self.payload_len = None;
        self.payload_read = 0;
        Ok(Some(payload_len))
    }
}

async fn setup_udp_lanes(
    vector: &VectorInner,
    lanes: &mut [PhysicalLane],
    flow_id: u32,
    uplink: Carrier,
    downlink: Carrier,
    target: &crate::protocol::Target,
) -> std::result::Result<(), OpenFlowError> {
    let open = FlowHeader {
        role: if uplink == downlink {
            FlowRole::Duplex
        } else {
            FlowRole::Open
        },
        flow_id,
        kind: FlowKind::Udp,
        uplink,
        downlink,
    };
    let pending_auth = lanes[0].take_pending_auth();
    write_open_request(
        lanes[0].writer.as_mut().expect("uplink writer"),
        pending_auth,
        open,
        target,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    lanes[0].mark_auth_sent();
    if uplink != downlink {
        let pending_auth = lanes[1].take_pending_auth();
        write_header(
            lanes[1].writer.as_mut().expect("downlink writer"),
            pending_auth,
            FlowHeader {
                role: FlowRole::Attach,
                ..open
            },
        )
        .await
        .map_err(OpenFlowError::Transport)?;
        lanes[1].mark_auth_sent();
    }
    if vector.config.up == CarrierMode::Udp {
        timeout(
            handshake_timeout(),
            lanes[0]
                .writer
                .as_mut()
                .expect("QUIC uplink control")
                .shutdown(),
        )
        .await
        .map_err(|_| {
            OpenFlowError::Transport(anyhow::anyhow!(
                "vector::udp_flow::setup_udp_lanes: uplink shutdown timeout"
            ))
        })?
        .map_err(|error| OpenFlowError::Transport(error.into()))?;
    }
    let down_index = usize::from(uplink != downlink);
    if vector.config.down == CarrierMode::Udp && down_index != 0 {
        timeout(
            handshake_timeout(),
            lanes[down_index]
                .writer
                .as_mut()
                .expect("QUIC downlink control")
                .shutdown(),
        )
        .await
        .map_err(|_| {
            OpenFlowError::Transport(anyhow::anyhow!(
                "vector::udp_flow::setup_udp_lanes: downlink shutdown timeout"
            ))
        })?
        .map_err(|error| OpenFlowError::Transport(error.into()))?;
    }
    read_ready(lanes[down_index].reader.as_mut().expect("downlink reader"))
        .await
        .map_err(OpenFlowError::Setup)
}

#[cfg(test)]
#[path = "../tests/vector/udp_flow.rs"]
mod tests;
