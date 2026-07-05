// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authentication frame and credential tests.

use super::*;

#[test]
fn credentials_match_sha256_username() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    assert_eq!(
        credentials.key,
        [
            0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3, 0x8b, 0xd3, 0x03, 0x61, 0xaa, 0x85,
            0x56, 0x86, 0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6, 0xa2, 0x5f, 0xe9, 0x7b,
            0xf5, 0x27, 0xa2, 0x5b,
        ]
    );
    assert_eq!(
        credentials.protocol_spec.effective_alpn,
        credentials.protocol_spec.default_alpn
    );
}

#[test]
fn credentials_percent_decode_username() {
    let url = Url::parse("portal://sec%20ret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();

    assert_eq!(credentials.key, Sha256::digest(b"sec ret").as_slice());
}

#[test]
fn rejects_password_credentials() {
    let url = Url::parse("portal://secret:old@127.0.0.1:443").unwrap();
    assert!(Credentials::new(&url).is_err());
}

#[test]
fn rejects_missing_key() {
    let url = Url::parse("portal://127.0.0.1:443").unwrap();
    assert!(Credentials::new(&url).is_err());
}

#[test]
fn auth_frame_round_trip_and_bad_key() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    assert_eq!(frame.len(), auth_frame_len(&credentials.protocol_spec));
    assert_eq!(
        frame[auth_field_offset(&credentials.protocol_spec, AuthFrameElement::Padding)],
        credentials.protocol_spec.auth_padding_len
    );
    validate_auth_frame(&frame, credentials.key, &credentials.protocol_spec).unwrap();
    validate_auth_frame(&frame, [1; 32], &credentials.protocol_spec).unwrap_err();
}

#[test]
fn auth_frame_returns_and_authenticates_session_id() {
    let credentials =
        Credentials::new(&Url::parse("portal://secret@127.0.0.1:443").unwrap()).unwrap();
    let session_id = [0x5a; SESSION_ID_LEN];
    let frame = write_session_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
        session_id,
    );
    assert_eq!(
        validate_auth_frame(&frame, credentials.key, &credentials.protocol_spec).unwrap(),
        session_id
    );
    let mut changed = frame;
    *changed.last_mut().unwrap() ^= 1;
    validate_auth_frame(&changed, credentials.key, &credentials.protocol_spec).unwrap_err();
}

#[test]
fn auth_frame_fixed_nonce_vectors() {
    let cases = [
        (
            "portal://secret@127.0.0.1:443",
            "9f5c48262539a0c11b36f1c68104707b5e8ed40b43095a4bbf116a0841d627bbd065c573fe8427ef058b0eb2d90a070707070707070707070707070707070707070707070707070707070707070700000000000000000000000000000000",
        ),
        (
            "portal://secret@127.0.0.1:443?spec=edge-a",
            "4aac8618aec3963e460c00ef25b0b998a1fa9057caff3c7022cd7d4bcae1eaa61e45f46ff130d7843823958bb0fc0e8eebd66a60e5fab1f83233cb5e4e8c4344dfe8d3da0bdf90070707070707070707070707070707070707070707070707070707070707070700000000000000000000000000000000",
        ),
    ];

    for (raw_url, expected_hex) in cases {
        let credentials = Credentials::new(&Url::parse(raw_url).unwrap()).unwrap();
        let frame = write_auth_frame(
            credentials.key,
            &credentials.protocol_spec,
            [7; AUTH_NONCE_LEN],
        );

        assert_eq!(hex(&frame), expected_hex);
        validate_auth_frame(&frame, credentials.key, &credentials.protocol_spec).unwrap();
    }
}

#[test]
fn auth_frame_binds_shared_key_and_effective_spec() {
    let a = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap();
    let b = Url::parse("portal://secret@127.0.0.1:443?spec=edge-b").unwrap();
    let c = Url::parse("portal://other@127.0.0.1:443?spec=edge-a").unwrap();
    let a = Credentials::new(&a).unwrap();
    let b = Credentials::new(&b).unwrap();
    let c = Credentials::new(&c).unwrap();

    let frame = write_auth_frame(a.key, &a.protocol_spec, [7; AUTH_NONCE_LEN]);

    validate_auth_frame(&frame, a.key, &a.protocol_spec).unwrap();
    validate_auth_frame(&frame, b.key, &b.protocol_spec).unwrap_err();
    validate_auth_frame(&frame, c.key, &c.protocol_spec).unwrap_err();
}

#[test]
fn rejects_short_auth_frame() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );

    assert!(
        validate_auth_frame(
            &frame[..frame.len() - 1],
            credentials.key,
            &credentials.protocol_spec
        )
        .is_err()
    );
}

#[test]
fn rejects_legacy_fixed_auth_frame() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();

    assert!(
        validate_auth_frame(
            &[0; AUTH_MAGIC_LEN + AUTH_NONCE_LEN + AUTH_TAG_LEN],
            credentials.key,
            &credentials.protocol_spec
        )
        .is_err()
    );
}

#[test]
fn rejects_fixed_order_padded_auth_frame() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let frame = fixed_order_padded_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );

    validate_auth_frame(&frame, credentials.key, &credentials.protocol_spec).unwrap_err();
}

#[test]
fn rejects_bad_padding_length_padding_and_tag() {
    let url = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );

    let mut bad_magic = frame.clone();
    let magic_offset = auth_field_offset(&credentials.protocol_spec, AuthFrameElement::Magic);
    bad_magic[magic_offset] ^= 1;
    let bad_magic_error =
        validate_auth_frame(&bad_magic, credentials.key, &credentials.protocol_spec).unwrap_err();

    let padding_offset = auth_field_offset(&credentials.protocol_spec, AuthFrameElement::Padding);
    let mut bad_len = frame.clone();
    bad_len[padding_offset] = bad_len[padding_offset].wrapping_add(1);
    let bad_len_error =
        validate_auth_frame(&bad_len, credentials.key, &credentials.protocol_spec).unwrap_err();

    let mut bad_padding = frame.clone();
    bad_padding[padding_offset + 1] ^= 1;
    let bad_padding_error =
        validate_auth_frame(&bad_padding, credentials.key, &credentials.protocol_spec).unwrap_err();

    let mut bad_tag = frame;
    let tag_offset = auth_field_offset(&credentials.protocol_spec, AuthFrameElement::Tag);
    bad_tag[tag_offset] ^= 1;
    let bad_tag_error =
        validate_auth_frame(&bad_tag, credentials.key, &credentials.protocol_spec).unwrap_err();

    let expected_error = "protocol::crypto::validate_auth_frame: invalid authentication frame";
    for error in [
        bad_magic_error,
        bad_len_error,
        bad_padding_error,
        bad_tag_error,
    ] {
        assert_eq!(error.to_string(), expected_error);
    }
}

#[test]
fn rejects_trailing_auth_frame_bytes() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let mut frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    frame.push(0);

    validate_auth_frame(&frame, credentials.key, &credentials.protocol_spec).unwrap_err();
}

#[tokio::test]
async fn reads_auth_frame_from_async_reader() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    let mut reader = frame.as_slice();

    read_auth_stream(&mut reader, credentials.key, &credentials.protocol_spec)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_auth_frame_leaves_following_bytes() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let mut bytes = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    bytes.extend_from_slice(b"request");
    let mut reader = bytes.as_slice();

    read_auth_frame(&mut reader, credentials.key, &credentials.protocol_spec)
        .await
        .unwrap();

    let mut following = Vec::new();
    reader.read_to_end(&mut following).await.unwrap();
    assert_eq!(following, b"request");
}

#[tokio::test]
async fn read_auth_stream_rejects_trailing_bytes() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let mut frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    frame.push(0);
    let mut reader = frame.as_slice();

    read_auth_stream(&mut reader, credentials.key, &credentials.protocol_spec)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn read_auth_stream_checks_end_before_frame_contents() {
    let url = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let credentials = Credentials::new(&url).unwrap();
    let mut frame = write_auth_frame(
        credentials.key,
        &credentials.protocol_spec,
        [7; AUTH_NONCE_LEN],
    );
    let magic_offset = auth_field_offset(&credentials.protocol_spec, AuthFrameElement::Magic);
    frame[magic_offset] ^= 1;
    frame.push(0);
    let mut reader = frame.as_slice();

    let error = read_auth_stream(&mut reader, credentials.key, &credentials.protocol_spec)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "protocol::crypto::read_auth_stream: trailing auth stream bytes"
    );
}

fn auth_field_offset(
    protocol_spec: &EffectiveProtocolSpec,
    target_element: AuthFrameElement,
) -> usize {
    let mut offset = 0;
    for element in protocol_spec.auth_frame_order {
        if element == target_element {
            return offset;
        }
        offset += auth_field_len(element, protocol_spec);
    }
    panic!("auth field not found");
}

fn fixed_order_padded_auth_frame(
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
    nonce: [u8; AUTH_NONCE_LEN],
) -> Vec<u8> {
    let padding = auth_padding_bytes(protocol_spec, &nonce);
    let payload = auth_payload(
        &nonce,
        protocol_spec.auth_padding_len,
        &padding,
        &[0; SESSION_ID_LEN],
    );
    let tag = auth_tag(key, protocol_spec, &payload);

    let mut frame = Vec::with_capacity(auth_frame_len(protocol_spec));
    frame.extend_from_slice(&protocol_spec.auth_magic);
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&tag);
    frame
}

fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
