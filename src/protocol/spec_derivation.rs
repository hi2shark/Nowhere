// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! HKDF-style derivation helpers for spec-dependent frame material.

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{
    AUTH_MAGIC_LEN, AUTH_NONCE_LEN, AUTH_PADDING_BYTES_LABEL, AUTH_TAG_LEN, EffectiveProtocolSpec,
    TCP_PADDING_BYTES_LABEL,
};
use crate::protocol::flow::SESSION_ID_LEN;

pub(super) fn hkdf_extract(salt: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(input);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub(super) fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;

    while out.len() < len {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }

    out.truncate(len);
    out
}

pub(super) fn base64_url_no_pad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(in crate::protocol) fn auth_message_prefix(spec: &EffectiveProtocolSpec) -> Vec<u8> {
    let mut info = Vec::with_capacity(spec.auth_info.len() + spec.auth_context.len());
    info.extend_from_slice(&spec.auth_info);
    info.extend_from_slice(&spec.auth_context);
    info
}

pub(in crate::protocol) fn auth_frame_len(spec: &EffectiveProtocolSpec) -> usize {
    AUTH_MAGIC_LEN
        + AUTH_NONCE_LEN
        + 1
        + spec.auth_padding_len as usize
        + AUTH_TAG_LEN
        + SESSION_ID_LEN
}

pub(in crate::protocol) fn auth_padding_bytes(
    spec: &EffectiveProtocolSpec,
    nonce: &[u8],
) -> Vec<u8> {
    let mut info = Vec::with_capacity(AUTH_PADDING_BYTES_LABEL.len() + nonce.len() + 1);
    info.extend_from_slice(AUTH_PADDING_BYTES_LABEL);
    info.extend_from_slice(nonce);
    info.push(spec.auth_padding_len);
    hkdf_expand(
        &spec.auth_padding_key,
        &info,
        spec.auth_padding_len as usize,
    )
}

pub(in crate::protocol) fn tcp_request_padding_bytes(
    spec: &EffectiveProtocolSpec,
    target: &str,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(TCP_PADDING_BYTES_LABEL.len() + target.len() + 1);
    info.extend_from_slice(TCP_PADDING_BYTES_LABEL);
    info.extend_from_slice(target.as_bytes());
    info.push(spec.tcp_padding_len);
    hkdf_expand(&spec.tcp_padding_key, &info, spec.tcp_padding_len as usize)
}
