// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC UDP flow queue tests.

use std::sync::{Arc, Weak};

use bytes::Bytes;
use tokio::sync::Semaphore;

use super::*;

#[tokio::test]
async fn flow_queue_is_fifo_and_drops_the_new_datagram_when_full() {
    let (flow, mut receiver) =
        PortalUdpFlow::new(Weak::new(), UdpFlowKey::new(7, "example.test:53"));
    let budget = Arc::new(Semaphore::new(UDP_FLOW_QUEUE_DATAGRAMS + 1));

    for value in 0..UDP_FLOW_QUEUE_DATAGRAMS {
        let permit = budget.clone().try_acquire_owned().unwrap();
        assert!(flow.enqueue(QueuedDatagram::new(Bytes::from(vec![value as u8]), permit,)));
    }
    let overflow = budget.clone().try_acquire_owned().unwrap();
    assert!(!flow.enqueue(QueuedDatagram::new(Bytes::from_static(b"new"), overflow,)));

    for expected in 0..UDP_FLOW_QUEUE_DATAGRAMS {
        let datagram = receiver.recv().await.unwrap();
        assert_eq!(datagram.payload.as_ref(), &[expected as u8]);
    }
    assert_eq!(budget.available_permits(), UDP_FLOW_QUEUE_DATAGRAMS + 1);
}
