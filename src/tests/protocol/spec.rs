// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Protocol-spec derivation tests.

use super::*;
use crate::protocol::SESSION_ID_LEN;

#[test]
fn default_spec_matches_explicit_auto() {
    let omitted = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let explicit = Url::parse("portal://secret@127.0.0.1:443?spec=auto").unwrap();
    let key = b"secret";

    let omitted = EffectiveProtocolSpec::new(&omitted, key).unwrap();
    let explicit = EffectiveProtocolSpec::new(&explicit, key).unwrap();

    assert_eq!(omitted.effective_spec, DEFAULT_SPEC);
    assert_eq!(explicit.effective_spec, DEFAULT_SPEC);
    assert_eq!(omitted, explicit);
}

#[test]
fn explicit_spec_is_kept_for_display() {
    let url = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap();
    let spec = EffectiveProtocolSpec::new(&url, b"secret").unwrap();

    assert_eq!(spec.effective_spec, "edge-a");
}

#[test]
fn empty_spec_and_alpn_query_matches_omitted_query() {
    let omitted = Url::parse("portal://secret@127.0.0.1:443").unwrap();
    let empty = Url::parse("portal://secret@127.0.0.1:443?spec=&alpn=").unwrap();
    let key = b"secret";

    let omitted = EffectiveProtocolSpec::new(&omitted, key).unwrap();
    let empty = EffectiveProtocolSpec::new(&empty, key).unwrap();

    assert_eq!(omitted, empty);
}

#[test]
fn explicit_alpn_overrides_only_effective_alpn() {
    let url = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a&alpn=x7a2").unwrap();
    let spec = EffectiveProtocolSpec::new(&url, b"secret").unwrap();
    let without_alpn = EffectiveProtocolSpec::new(
        &Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap(),
        b"secret",
    )
    .unwrap();

    assert_eq!(spec.default_alpn, DEFAULT_ALPN);
    assert_eq!(spec.effective_alpn, "x7a2");
    assert_eq!(without_alpn.effective_alpn, DEFAULT_ALPN);
    assert_eq!(spec.auth_magic, without_alpn.auth_magic);
    assert_eq!(spec.auth_info, without_alpn.auth_info);
    assert_eq!(spec.auth_context, without_alpn.auth_context);
    assert_eq!(spec.auth_padding_len, without_alpn.auth_padding_len);
    assert_eq!(spec.auth_padding_key, without_alpn.auth_padding_key);
    assert_eq!(spec.auth_frame_order, without_alpn.auth_frame_order);
    assert_eq!(spec.tcp_padding_len, without_alpn.tcp_padding_len);
    assert_eq!(spec.tcp_padding_key, without_alpn.tcp_padding_key);
    assert_eq!(spec.frame_layout, without_alpn.frame_layout);
}

#[test]
fn auth_surfaces_are_spec_derived() {
    let a = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a&alpn=same").unwrap();
    let b = Url::parse("portal://secret@127.0.0.1:443?spec=edge-b&alpn=same").unwrap();
    let c = Url::parse("portal://other@127.0.0.1:443?spec=edge-a&alpn=same").unwrap();
    let a = EffectiveProtocolSpec::new(&a, b"secret").unwrap();
    let b = EffectiveProtocolSpec::new(&b, b"secret").unwrap();
    let c = EffectiveProtocolSpec::new(&c, b"other").unwrap();

    assert_ne!(a.effective_spec_id, b.effective_spec_id);
    assert_ne!(a.auth_magic, b.auth_magic);
    assert_ne!(a.auth_info, b.auth_info);
    assert_ne!(a.auth_context, b.auth_context);
    assert_ne!(a.auth_padding_key, b.auth_padding_key);
    assert_ne!(a.tcp_padding_key, b.tcp_padding_key);
    assert_eq!(a.auth_magic, c.auth_magic);
    assert_eq!(a.auth_info, c.auth_info);
    assert_eq!(a.auth_context, c.auth_context);
    assert_eq!(a.auth_padding_len, c.auth_padding_len);
    assert_eq!(a.auth_padding_key, c.auth_padding_key);
    assert_eq!(a.auth_frame_order, c.auth_frame_order);
    assert_eq!(a.tcp_padding_len, c.tcp_padding_len);
    assert_eq!(a.tcp_padding_key, c.tcp_padding_key);
    assert_eq!(a.frame_layout, c.frame_layout);
}

#[test]
fn auth_padding_is_spec_derived_and_nonce_bound() {
    let a = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap();
    let b = Url::parse("portal://secret@127.0.0.1:443?spec=edge-b").unwrap();
    let a = EffectiveProtocolSpec::new(&a, b"secret").unwrap();
    let b = EffectiveProtocolSpec::new(&b, b"secret").unwrap();

    assert!((1..=255).contains(&usize::from(a.auth_padding_len)));
    assert_eq!(
        auth_frame_len(&a),
        AUTH_MAGIC_LEN
            + AUTH_NONCE_LEN
            + 1
            + a.auth_padding_len as usize
            + AUTH_TAG_LEN
            + SESSION_ID_LEN
    );
    assert_eq!(
        auth_padding_bytes(&a, &[7; AUTH_NONCE_LEN]).len(),
        a.auth_padding_len as usize
    );
    assert_ne!(
        auth_padding_bytes(&a, &[7; AUTH_NONCE_LEN]),
        auth_padding_bytes(&a, &[8; AUTH_NONCE_LEN])
    );
    assert_ne!(
        auth_padding_bytes(&a, &[7; AUTH_NONCE_LEN]),
        auth_padding_bytes(&b, &[7; AUTH_NONCE_LEN])
    );
}

#[test]
fn auth_frame_order_rotates_canonical_shuffle() {
    assert_eq!(
        auth_frame_order_from_seed(&[3, 2, 1]),
        [
            AuthFrameElement::Nonce,
            AuthFrameElement::Padding,
            AuthFrameElement::Tag,
            AuthFrameElement::Magic,
        ]
    );
}

#[test]
fn tcp_padding_is_spec_derived_and_target_bound() {
    let a = Url::parse("portal://secret@127.0.0.1:443?spec=edge-a").unwrap();
    let b = Url::parse("portal://secret@127.0.0.1:443?spec=edge-b").unwrap();
    let a = EffectiveProtocolSpec::new(&a, b"secret").unwrap();
    let b = EffectiveProtocolSpec::new(&b, b"secret").unwrap();

    assert!(usize::from(a.tcp_padding_len) < TCP_PADDING_LEN_MAX);
    assert_eq!(
        tcp_request_padding_bytes(&a, "example.com:443").len(),
        a.tcp_padding_len as usize
    );
    assert_ne!(
        tcp_request_padding_bytes(&a, "example.com:443"),
        tcp_request_padding_bytes(&a, "example.net:443")
    );
    assert_ne!(
        tcp_request_padding_bytes(&a, "example.com:443"),
        tcp_request_padding_bytes(&b, "example.com:443")
    );
}

#[test]
fn rejects_overlong_inputs() {
    let value = "x".repeat(MAX_INPUT_LEN + 1);
    let url = Url::parse(&format!("portal://secret@127.0.0.1:443?spec={value}")).unwrap();

    assert!(EffectiveProtocolSpec::new(&url, b"secret").is_err());
    assert!(
        EffectiveProtocolSpec::new(
            &Url::parse("portal://secret@127.0.0.1:443").unwrap(),
            value.as_bytes()
        )
        .is_err()
    );
}

#[test]
fn username_is_percent_decoded() {
    let url = Url::parse("portal://sec%20ret@127.0.0.1:443").unwrap();

    assert_eq!(decode_username(&url).unwrap(), b"sec ret");
}

#[test]
fn query_plus_is_not_treated_as_space() {
    let url = Url::parse("portal://secret@127.0.0.1:443?spec=edge+a&alpn=x+y").unwrap();
    let spec = EffectiveProtocolSpec::new(&url, b"secret").unwrap();
    let encoded = Url::parse("portal://secret@127.0.0.1:443?spec=edge%2Ba&alpn=x%2By").unwrap();
    let encoded = EffectiveProtocolSpec::new(&encoded, b"secret").unwrap();

    assert_eq!(spec, encoded);
    assert_eq!(spec.effective_alpn, "x+y");
}
