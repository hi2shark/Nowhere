// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry tests.

use super::*;
use crate::protocol::{Carrier, FlowKind, FlowRole, SESSION_ID_LEN};
use crate::transport::Stats;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};

fn quic_udp_budget() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(256))
}

fn header(role: FlowRole) -> FlowHeader {
    header_with_id(role, 7)
}

fn header_with_id(role: FlowRole, flow_id: u64) -> FlowHeader {
    FlowHeader {
        role,
        flow_id,
        kind: FlowKind::Tcp,
        uplink: Carrier::Tcp,
        downlink: Carrier::Udp,
    }
}

fn path() -> LinkPath {
    LinkPath {
        peer: "client.test:1234".into(),
        local: "portal.test:2077".into(),
    }
}

fn tcp_half() -> LinkHalf {
    LinkHalf::tcp(path())
}

fn quic_half(generation: u64) -> LinkHalf {
    LinkHalf::quic(path(), generation)
}

#[test]
fn newer_quic_session_replaces_previous_generation() {
    let registry = Arc::new(PairingRegistry::new());
    let stats = Arc::new(Stats::default());
    let session_id = [9; SESSION_ID_LEN];
    let first_replaced = tokio_util::sync::CancellationToken::new();
    let first = registry.register_quic_link(
        session_id,
        stats.clone(),
        first_replaced.clone(),
        quic_udp_budget(),
    );
    let second_replaced = tokio_util::sync::CancellationToken::new();
    let second = registry.register_quic_link(
        session_id,
        stats.clone(),
        second_replaced.clone(),
        quic_udp_budget(),
    );
    assert!(first_replaced.is_cancelled());
    assert!(!second_replaced.is_cancelled());
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 1);
    drop(first);
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 1);
    drop(second);
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn newer_generation_replaces_pending_quic_half() {
    let registry = Arc::new(PairingRegistry::new());
    let stats = Arc::new(Stats::default());
    let session_id = [8; SESSION_ID_LEN];
    let first = registry.register_quic_link(
        session_id,
        stats.clone(),
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (old_down, mut old_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(FlowRole::Attach),
                "target.test:443".into(),
                quic_half(first.quic_generation()),
                None,
                Some(Box::pin(old_down)),
            )
            .await
            .unwrap()
            .is_none()
    );

    let second = registry.register_quic_link(
        session_id,
        stats,
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (new_down, mut new_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(FlowRole::Attach),
                "target.test:443".into(),
                quic_half(second.quic_generation()),
                None,
                Some(Box::pin(new_down)),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(old_peer.read(&mut [0; 1]).await.unwrap(), 0);

    let (up, _) = tokio::io::duplex(64);
    let mut paired = registry
        .submit_tcp(
            session_id,
            header(FlowRole::Open),
            "target.test:443".into(),
            tcp_half(),
            Some(Box::pin(up)),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    paired.downlink.write_all(b"new").await.unwrap();
    let mut received = [0; 3];
    new_peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"new");
}

#[tokio::test]
async fn stale_timeout_does_not_remove_replacement_half() {
    let registry = Arc::new(PairingRegistry {
        tcp: Mutex::new(HashMap::new()),
        udp: Mutex::new(HashMap::new()),
        links: StdMutex::new(HashMap::new()),
        next_quic_generation: AtomicU64::new(1),
        next_pending_epoch: AtomicU64::new(1),
        max_pending: 16,
        timeout: Duration::from_millis(200),
    });
    let stats = Arc::new(Stats::default());
    let session_id = [6; SESSION_ID_LEN];
    let first = registry.register_quic_link(
        session_id,
        stats.clone(),
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (old_down, _) = tokio::io::duplex(64);
    registry
        .submit_tcp(
            session_id,
            header(FlowRole::Attach),
            "target.test:443".into(),
            quic_half(first.quic_generation()),
            None,
            Some(Box::pin(old_down)),
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = registry.register_quic_link(
        session_id,
        stats,
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (new_down, mut new_peer) = tokio::io::duplex(64);
    registry
        .submit_tcp(
            session_id,
            header(FlowRole::Attach),
            "target.test:443".into(),
            quic_half(second.quic_generation()),
            None,
            Some(Box::pin(new_down)),
        )
        .await
        .unwrap();

    // The first half's timer has fired, while the replacement's timer has not.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let (up, _) = tokio::io::duplex(64);
    let mut paired = registry
        .submit_tcp(
            session_id,
            header(FlowRole::Open),
            "target.test:443".into(),
            tcp_half(),
            Some(Box::pin(up)),
            None,
        )
        .await
        .unwrap()
        .expect("replacement half must survive the stale timer");
    paired.downlink.write_all(b"new").await.unwrap();
    let mut received = [0; 3];
    new_peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"new");
}

#[tokio::test]
async fn pairs_out_of_order_and_rejects_conflicting_metadata() {
    let registry = Arc::new(PairingRegistry::new());
    let stats = Arc::new(Stats::default());
    let session_one = registry.register_quic_link(
        [1; SESSION_ID_LEN],
        stats.clone(),
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (_, down) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                [1; SESSION_ID_LEN],
                header(FlowRole::Attach),
                "target.test:443".into(),
                quic_half(session_one.quic_generation()),
                None,
                Some(Box::pin(down)),
            )
            .await
            .unwrap()
            .is_none()
    );

    let (up, _) = tokio::io::duplex(64);
    let paired = registry
        .submit_tcp(
            [1; SESSION_ID_LEN],
            header(FlowRole::Open),
            "target.test:443".into(),
            tcp_half(),
            Some(Box::pin(up)),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paired.target, "target.test:443");
    assert_eq!(paired.uplink_carrier, Carrier::Tcp);
    assert_eq!(paired.downlink_carrier, Carrier::Udp);

    let session_two = registry.register_quic_link(
        [2; SESSION_ID_LEN],
        stats,
        tokio_util::sync::CancellationToken::new(),
        quic_udp_budget(),
    );
    let (up, _) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                [2; SESSION_ID_LEN],
                header(FlowRole::Open),
                "a.test:1".into(),
                tcp_half(),
                Some(Box::pin(up)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );
    let (_, down) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                [2; SESSION_ID_LEN],
                header(FlowRole::Attach),
                "b.test:1".into(),
                quic_half(session_two.quic_generation()),
                None,
                Some(Box::pin(down)),
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pending_limit_is_enforced_per_session() {
    let registry = Arc::new(PairingRegistry {
        tcp: Mutex::new(HashMap::new()),
        udp: Mutex::new(HashMap::new()),
        links: StdMutex::new(HashMap::new()),
        next_quic_generation: AtomicU64::new(1),
        next_pending_epoch: AtomicU64::new(1),
        max_pending: 1,
        timeout: Duration::from_secs(60),
    });

    for (session, flow_id) in [([1; SESSION_ID_LEN], 1), ([2; SESSION_ID_LEN], 1)] {
        let (up, _) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_tcp(
                    session,
                    header_with_id(FlowRole::Open, flow_id),
                    "target.test:443".into(),
                    tcp_half(),
                    Some(Box::pin(up)),
                    None,
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    let (up, _) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                [1; SESSION_ID_LEN],
                header_with_id(FlowRole::Open, 2),
                "target.test:443".into(),
                tcp_half(),
                Some(Box::pin(up)),
                None,
            )
            .await
            .is_err()
    );

    let (up, _) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_udp(
                [1; SESSION_ID_LEN],
                FlowHeader {
                    role: FlowRole::Open,
                    flow_id: 3,
                    kind: FlowKind::Udp,
                    uplink: Carrier::Tcp,
                    downlink: Carrier::Udp,
                },
                "target.test:53".into(),
                tcp_half(),
                UdpHalf::Uplink {
                    uplink: UdpUp::Tcp(Box::pin(up)),
                    udp_ack: None,
                    flow_permit: None,
                },
            )
            .await
            .is_err()
    );
}
