// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP frame tests.

use super::*;

#[tokio::test]
async fn setup_target_frame_round_trips() {
    let frame = write_uot_setup_frame("example.com:53").unwrap();
    let mut reader = frame.as_slice();

    assert_eq!(
        read_uot_setup_target(&mut reader).await.unwrap(),
        "example.com:53"
    );
}

#[tokio::test]
async fn packet_frame_round_trips_and_reports_eof() {
    let mut frame = write_uot_packet_frame(b"abc").unwrap();
    frame.extend_from_slice(&write_uot_packet_frame(b"").unwrap());
    let mut reader = frame.as_slice();

    assert_eq!(
        read_uot_packet(&mut reader).await.unwrap(),
        Some(b"abc".to_vec())
    );
    assert_eq!(
        read_uot_packet(&mut reader).await.unwrap(),
        Some(Vec::new())
    );
    assert_eq!(read_uot_packet(&mut reader).await.unwrap(), None);
}

#[tokio::test]
async fn packet_writer_matches_encoded_frame() {
    let mut out = Vec::new();

    write_uot_packet(&mut out, b"abc").await.unwrap();

    assert_eq!(out, write_uot_packet_frame(b"abc").unwrap());
}

#[test]
fn rejects_invalid_setup_target() {
    assert!(write_uot_setup_frame("example.com").is_err());
}

#[tokio::test]
async fn rejects_oversized_setup_target() {
    let target = format!("{}:53", "a".repeat(510));
    let mut frame = Vec::with_capacity(2 + target.len());
    frame.extend_from_slice(&(target.len() as u16).to_be_bytes());
    frame.extend_from_slice(target.as_bytes());
    let mut reader = frame.as_slice();

    assert!(read_uot_setup_target(&mut reader).await.is_err());
}

#[test]
fn rejects_oversized_packet_frame() {
    let payload = vec![0; u16::MAX as usize + 1];

    assert!(write_uot_packet_frame(&payload).is_err());
}
