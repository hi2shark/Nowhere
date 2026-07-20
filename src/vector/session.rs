// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated TLS pool and shared QUIC carrier lifecycle.

use std::collections::{HashMap, hash_map::Entry};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::lookup_host;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::common::{
    BudgetedDatagram, UdpDatagramSend, handshake_timeout, reserve_udp_budget, send_quic_udp_packet,
    service_cooldown, udp_idle_timeout,
};
use crate::protocol::{
    AuthFrame, AuthKey, AuthTransport, Credentials, DatagramReassembler, FlowId, OwnedUdpFragment,
    OwnedUdpFrame, ReassemblyConfig, ReassemblyOutcome, SessionId, decode_udp_frame_owned,
    encode_auth_frame, encode_udp_close,
};
use crate::transport::Stats;

use super::config::VectorConfig;
use super::tls::{ClientTls, EXPORTER_LABEL};

const WARM_LANE_TTL: Duration = Duration::from_secs(30);
const QUIC_DATAGRAM_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const QUIC_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;
const QUIC_SEND_WINDOW: u64 = 32 * 1024 * 1024;

pub(super) struct TlsLane {
    pub(super) stream: TlsStream<tokio::net::TcpStream>,
    pending_auth: Option<AuthFrame>,
    created_at: Instant,
    _link: LinkGuard,
}

pub(super) struct TlsLaneParts {
    pub(super) reader: tokio::io::ReadHalf<TlsStream<tokio::net::TcpStream>>,
    pub(super) writer: tokio::io::WriteHalf<TlsStream<tokio::net::TcpStream>>,
    pub(super) pending_auth: Option<AuthFrame>,
    pub(super) link: LinkGuard,
}

impl TlsLane {
    fn expired(&self) -> bool {
        self.created_at.elapsed() >= WARM_LANE_TTL
    }

    fn usable(&mut self) -> bool {
        // Poll the TLS stream, not its socket: rustls consumes post-handshake
        // tickets internally and returns Pending, while EOF, alerts, and any
        // unexpected application byte make this idle lane unsafe to reuse.
        idle_stream_usable(&mut self.stream)
    }

    pub(super) fn into_parts(self) -> TlsLaneParts {
        let Self {
            stream,
            pending_auth,
            created_at: _,
            _link,
        } = self;
        let (reader, writer) = tokio::io::split(stream);
        TlsLaneParts {
            reader,
            writer,
            pending_auth,
            link: _link,
        }
    }
}

pub(super) struct LinkGuard {
    stats: Arc<Stats>,
    quic: bool,
}

impl LinkGuard {
    fn new(stats: Arc<Stats>, quic: bool) -> Self {
        if quic {
            stats.link_udp.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.link_tcp.fetch_add(1, Ordering::Relaxed);
        }
        Self { stats, quic }
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        if self.quic {
            self.stats.link_udp.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.stats.link_tcp.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub(super) struct TlsPool {
    target: usize,
    endpoint: String,
    tls: ClientTls,
    auth_key: AuthKey,
    session_id: SessionId,
    stats: Arc<Stats>,
    idle: Mutex<Vec<TlsLane>>,
    preparing: AtomicU64,
    replenish: Notify,
}

impl TlsPool {
    pub(super) fn new(
        config: &VectorConfig,
        tls: ClientTls,
        credentials: &Credentials,
        session_id: SessionId,
        stats: Arc<Stats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            target: config.pool,
            endpoint: config.portal_endpoint(),
            tls,
            auth_key: credentials.auth_key,
            session_id,
            stats,
            idle: Mutex::new(Vec::with_capacity(config.pool)),
            preparing: AtomicU64::new(0),
            replenish: Notify::new(),
        })
    }

    pub(super) async fn acquire(self: &Arc<Self>) -> Result<TlsLane> {
        loop {
            let candidate = self.idle.lock().await.pop();
            match candidate {
                Some(mut lane) if !lane.expired() => {
                    if lane.usable() {
                        self.replenish.notify_one();
                        return Ok(lane);
                    }
                }
                Some(_) => continue,
                None => break,
            }
        }
        let lane = self.connect_lane(false).await?;
        self.replenish.notify_one();
        Ok(lane)
    }

    pub(super) async fn maintain(self: Arc<Self>, shutdown: CancellationToken) {
        if self.target == 0 {
            return;
        }
        loop {
            if shutdown.is_cancelled() {
                self.idle.lock().await.clear();
                return;
            }
            {
                let mut idle = self.idle.lock().await;
                idle.retain(|lane| !lane.expired());
            }
            let idle_count = self.idle.lock().await.len();
            let preparing = self.preparing.load(Ordering::Relaxed) as usize;
            let missing = self.target.saturating_sub(idle_count + preparing);
            if missing > 0 {
                self.preparing.fetch_add(missing as u64, Ordering::Relaxed);
                let mut tasks = tokio::task::JoinSet::new();
                let mut connect_failed = false;
                for _ in 0..missing {
                    let pool = self.clone();
                    tasks.spawn(async move { pool.connect_lane(true).await });
                }
                while let Some(result) = tasks.join_next().await {
                    self.preparing.fetch_sub(1, Ordering::Relaxed);
                    if let Ok(Ok(lane)) = result {
                        let mut idle = self.idle.lock().await;
                        if idle.len() < self.target && !shutdown.is_cancelled() {
                            idle.push(lane);
                        }
                    } else {
                        connect_failed = true;
                    }
                }
                if connect_failed {
                    tokio::select! {
                        _ = shutdown.cancelled() => {}
                        _ = tokio::time::sleep(service_cooldown()) => {}
                    }
                    continue;
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => {},
                _ = self.replenish.notified() => {},
                _ = tokio::time::sleep(WARM_LANE_TTL / 2) => {},
            }
        }
    }

    async fn connect_lane(&self, authenticate_now: bool) -> Result<TlsLane> {
        let (mut stream, exporter) = self.tls.connect_tcp(&self.endpoint).await?;
        let auth = encode_auth_frame(
            self.auth_key,
            AuthTransport::TlsTcp,
            &exporter,
            self.session_id,
        );
        let pending_auth = if authenticate_now {
            timeout(handshake_timeout(), stream.write_all(&auth))
                .await
                .map_err(|_| anyhow!("vector::session::TlsPool::connect_lane: auth write timeout"))?
                .context("vector::session::TlsPool::connect_lane: auth write failed")?;
            None
        } else {
            Some(auth)
        };
        Ok(TlsLane {
            stream,
            pending_auth,
            created_at: Instant::now(),
            _link: LinkGuard::new(self.stats.clone(), false),
        })
    }

    pub(super) async fn idle_count(&self) -> usize {
        self.idle.lock().await.len()
    }
}

fn idle_stream_usable<R: AsyncRead + Unpin>(reader: &mut R) -> bool {
    let mut byte = [0u8; 1];
    let mut buffer = ReadBuf::new(&mut byte);
    let mut context = TaskContext::from_waker(Waker::noop());
    matches!(
        Pin::new(reader).poll_read(&mut context, &mut buffer),
        Poll::Pending
    )
}

/// Lazily created, reconnecting shared QUIC session.
pub(super) struct QuicManager {
    config: VectorConfig,
    tls: ClientTls,
    auth_key: AuthKey,
    session_id: SessionId,
    stats: Arc<Stats>,
    state: Mutex<Option<Arc<QuicSession>>>,
    connect_lock: Mutex<()>,
    retry_after: Mutex<Option<Instant>>,
    shutdown: CancellationToken,
    queue_bytes: usize,
}

impl QuicManager {
    pub(super) fn new(
        config: VectorConfig,
        tls: ClientTls,
        credentials: &Credentials,
        session_id: SessionId,
        stats: Arc<Stats>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            tls,
            auth_key: credentials.auth_key,
            session_id,
            stats,
            state: Mutex::new(None),
            connect_lock: Mutex::new(()),
            retry_after: Mutex::new(None),
            shutdown,
            queue_bytes: crate::common::env_int("NOW_QUIC_UDP_QUEUE_BYTES", 4 * 1024 * 1024)
                .clamp(2, i32::MAX) as usize,
        })
    }

    pub(super) async fn get(&self) -> Result<Arc<QuicSession>> {
        if let Some(session) = self.live_session().await {
            return Ok(session);
        }
        let _connecting = self.connect_lock.lock().await;
        if let Some(session) = self.live_session().await {
            return Ok(session);
        }
        if let Some(retry_after) = *self.retry_after.lock().await {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    bail!("vector::session::QuicManager: shutting down")
                }
                _ = tokio::time::sleep_until(retry_after) => {}
            }
        }
        let session = match self.connect().await {
            Ok(session) => {
                *self.retry_after.lock().await = None;
                session
            }
            Err(error) => {
                *self.retry_after.lock().await = Some(Instant::now() + service_cooldown());
                return Err(error);
            }
        };
        *self.state.lock().await = Some(session.clone());
        Ok(session)
    }

    async fn live_session(&self) -> Option<Arc<QuicSession>> {
        self.state
            .lock()
            .await
            .as_ref()
            .filter(|session| session.connection.close_reason().is_none())
            .cloned()
    }

    async fn connect(&self) -> Result<Arc<QuicSession>> {
        let resolved = timeout(
            handshake_timeout(),
            lookup_host((self.config.remote_host.as_str(), self.config.remote_port)),
        )
        .await
        .map_err(|_| anyhow!("vector::session::QuicManager::connect: Portal DNS timeout"))?
        .context("vector::session::QuicManager::connect: Portal DNS failed")?;
        let addresses: Vec<_> = resolved.collect();
        if addresses.is_empty() {
            bail!("vector::session::QuicManager::connect: no Portal address resolved");
        }
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(session) => return Ok(session),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("vector::session::QuicManager::connect failed")))
    }

    async fn connect_address(&self, address: SocketAddr) -> Result<Arc<QuicSession>> {
        let bind = if address.is_ipv4() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = Endpoint::client(bind)
            .with_context(|| format!("vector::session::QuicManager: bind {bind} failed"))?;
        let mut client_config = self.tls.quic_client_config()?;
        configure_quic_transport(&mut client_config)?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(address, &self.tls.quic_server_name())
            .context("vector::session::QuicManager: invalid QUIC endpoint")?;
        let connection = timeout(handshake_timeout(), connecting)
            .await
            .map_err(|_| anyhow!("vector::session::QuicManager: QUIC handshake timeout"))?
            .context("vector::session::QuicManager: QUIC handshake failed")?;
        let mut exporter = [0u8; crate::protocol::TLS_EXPORTER_LEN];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .map_err(|error| anyhow!("vector::session::QuicManager: exporter failed: {error:?}"))?;
        let (auth_send, auth_recv) = timeout(handshake_timeout(), connection.open_bi())
            .await
            .map_err(|_| anyhow!("vector::session::QuicManager: auth stream open timeout"))?
            .context("vector::session::QuicManager: failed to open auth stream")?;
        let auth = encode_auth_frame(
            self.auth_key,
            AuthTransport::Quic,
            &exporter,
            self.session_id,
        );
        let reassembly_config = ReassemblyConfig {
            max_slots: 64,
            max_bytes: self.queue_bytes,
            ttl: Duration::from_secs(10),
        };
        let session = Arc::new(QuicSession {
            _endpoint: endpoint,
            connection,
            first_stream: Mutex::new(Some((auth_send, auth_recv, auth))),
            routes: StdMutex::new(HashMap::new()),
            reassembler: StdMutex::new(DatagramReassembler::new(reassembly_config)),
            queue_budget: Arc::new(Semaphore::new(self.queue_bytes)),
            _link: LinkGuard::new(self.stats.clone(), true),
        });
        spawn_datagram_loop(Arc::downgrade(&session), self.shutdown.clone());
        Ok(session)
    }

    pub(super) async fn close(&self, deadline: Instant) {
        if let Some(session) = self.state.lock().await.take() {
            session.connection.close(VarInt::from_u32(0), b"");
            let _ = timeout_at(deadline, session.connection.closed()).await;
        }
    }
}

pub(super) struct QuicSession {
    _endpoint: Endpoint,
    pub(super) connection: Connection,
    first_stream: Mutex<Option<(SendStream, RecvStream, AuthFrame)>>,
    routes: StdMutex<HashMap<FlowId, UdpRoute>>,
    reassembler: StdMutex<DatagramReassembler<OwnedSemaphorePermit>>,
    queue_budget: Arc<Semaphore>,
    _link: LinkGuard,
}

pub(super) type QueuedDatagram = BudgetedDatagram;

struct UdpRoute {
    sender: mpsc::Sender<QueuedDatagram>,
    ready: bool,
}

impl QuicSession {
    pub(super) async fn open_bi(&self) -> Result<(SendStream, RecvStream, Option<AuthFrame>)> {
        if let Some((send, recv, auth)) = self.first_stream.lock().await.take() {
            return Ok((send, recv, Some(auth)));
        }
        let (send, recv) = timeout(handshake_timeout(), self.connection.open_bi())
            .await
            .map_err(|_| anyhow!("vector::session::QuicSession: stream open timeout"))?
            .context("vector::session::QuicSession: failed to open stream")?;
        Ok((send, recv, None))
    }

    pub(super) fn register_udp(&self, flow_id: FlowId) -> Result<mpsc::Receiver<QueuedDatagram>> {
        let (sender, receiver) = mpsc::channel(64);
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        match routes.entry(flow_id) {
            Entry::Vacant(route) => {
                route.insert(UdpRoute {
                    sender,
                    ready: false,
                });
            }
            Entry::Occupied(_) => {
                bail!("vector::session::QuicSession: duplicate UDP flow");
            }
        }
        Ok(receiver)
    }

    pub(super) fn activate_udp(&self, flow_id: FlowId) -> Result<()> {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let route = routes.get_mut(&flow_id).ok_or_else(|| {
            anyhow!("vector::session::QuicSession: UDP route closed before READY")
        })?;
        route.ready = true;
        Ok(())
    }

    pub(super) fn remove_udp(&self, flow_id: FlowId) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        routes.remove(&flow_id);
        reassembler.remove_flow(flow_id);
    }

    fn clear_udp(&self) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        routes.clear();
        reassembler.clear();
    }

    pub(super) async fn send_udp(
        &self,
        flow_id: FlowId,
        packet_id: &mut u32,
        payload: &[u8],
    ) -> Result<UdpDatagramSend> {
        send_quic_udp_packet(&self.connection, flow_id, packet_id, payload).await
    }

    pub(super) fn close_udp(&self, flow_id: FlowId) {
        self.remove_udp(flow_id);
        if let Ok(frame) = encode_udp_close(flow_id) {
            let _ = self
                .connection
                .send_datagram(Bytes::copy_from_slice(&frame));
        }
    }

    fn receive_data(&self, flow_id: FlowId, payload: Bytes) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let Some(route) = routes.get(&flow_id).filter(|route| route.ready) else {
            return;
        };
        let Some(permit) = reserve_udp_budget(self.queue_budget.clone(), payload.len()) else {
            return;
        };
        let queued = QueuedDatagram::new(payload, permit);
        if let Err(TrySendError::Closed(_)) = route.sender.try_send(queued) {
            routes.remove(&flow_id);
            self.reassembler
                .lock()
                .unwrap_or_else(|lock| lock.into_inner())
                .remove_flow(flow_id);
        }
    }

    fn receive_fragment(&self, flow_id: FlowId, fragment: OwnedUdpFragment) {
        // Every operation touching both maps takes routes first. Keeping this
        // guard through insertion prevents remove_udp from leaving a stale
        // partial packet after the route has been removed.
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let Some(route) = routes.get(&flow_id).filter(|route| route.ready) else {
            return;
        };
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let outcome =
            reassembler.push_with(flow_id, fragment, std::time::Instant::now(), |packet_len| {
                reserve_udp_budget(self.queue_budget.clone(), usize::from(packet_len))
            });
        if let ReassemblyOutcome::Complete {
            payload,
            reservation,
            ..
        } = outcome
        {
            let queued = QueuedDatagram::new(payload, reservation);
            if let Err(TrySendError::Closed(_)) = route.sender.try_send(queued) {
                routes.remove(&flow_id);
                reassembler.remove_flow(flow_id);
            }
        }
    }
}

fn spawn_datagram_loop(session: Weak<QuicSession>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let session = loop {
            let Some(session) = session.upgrade() else {
                return;
            };
            tokio::select! {
                _ = shutdown.cancelled() => break session,
                _ = cleanup.tick() => {
                    session.reassembler.lock().unwrap_or_else(|lock| lock.into_inner())
                        .expire(std::time::Instant::now());
                }
                datagram = session.connection.read_datagram() => {
                    let Ok(datagram) = datagram else { break session; };
                    match decode_udp_frame_owned(datagram) {
                        Ok(OwnedUdpFrame::Data { flow_id, payload }) => {
                            session.receive_data(flow_id, payload);
                        }
                        Ok(OwnedUdpFrame::Fragment { flow_id, fragment }) => {
                            session.receive_fragment(flow_id, fragment);
                        }
                        Ok(OwnedUdpFrame::Close { flow_id }) => session.remove_udp(flow_id),
                        Err(_) => {}
                    }
                }
            }
        };
        session.clear_udp();
    });
}

fn configure_quic_transport(config: &mut quinn::ClientConfig) -> Result<()> {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER_SIZE));
    transport.datagram_send_buffer_size(QUIC_DATAGRAM_BUFFER_SIZE);
    transport.stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW));
    transport.send_window(QUIC_SEND_WINDOW);
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(udp_idle_timeout())?));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    config.transport_config(Arc::new(transport));
    Ok(())
}

#[cfg(test)]
#[path = "../tests/vector/session.rs"]
mod tests;
