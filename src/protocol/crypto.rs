// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authentication key derivation and auth-frame encoding/validation.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use url::Url;

use super::spec::{
    AUTH_MAGIC_LEN, AUTH_NONCE_LEN, AUTH_TAG_LEN, AuthFrameElement, EffectiveProtocolSpec,
    auth_frame_len, auth_message_prefix, auth_padding_bytes, decode_username,
};

use super::{SESSION_ID_LEN, SessionId};

/// Fixed-size authentication key derived from the shared URL username.
pub type Key = [u8; 32];

/// Parsed credentials and the effective protocol spec tied to those credentials.
#[derive(Clone, Debug)]
pub struct Credentials {
    /// SHA-256 digest of the shared key bytes.
    pub key: Key,
    /// Protocol material derived from URL `spec`/`alpn` and the shared key.
    pub protocol_spec: EffectiveProtocolSpec,
}

impl Credentials {
    /// Builds credentials from a portal URL.
    ///
    /// The URL username is the shared key. Password credentials are rejected so
    /// the wire auth contract has a single canonical credential source.
    pub fn new(parsed_url: &Url) -> Result<Self> {
        if parsed_url.password().is_some() {
            bail!(
                "protocol::crypto::Credentials::new: password credentials are no longer supported"
            );
        }

        let shared_key = decode_username(parsed_url)?;
        let protocol_spec = EffectiveProtocolSpec::new(parsed_url, &shared_key)?;
        let digest = Sha256::digest(&shared_key);
        let mut key = [0; 32];
        key.copy_from_slice(&digest);
        Ok(Self { key, protocol_spec })
    }
}

/// Reads and validates an auth frame from a stream that may carry more data later.
pub async fn read_auth_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<SessionId> {
    let msg = read_auth_bytes(reader, protocol_spec)
        .await
        .context("protocol::crypto::read_auth_frame: failed to read auth")?;

    validate_auth_frame(&msg, key, protocol_spec)
}

/// Reads and validates an auth frame from a stream that must end after auth.
pub async fn read_auth_stream<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<SessionId> {
    let msg = read_auth_bytes(reader, protocol_spec)
        .await
        .context("protocol::crypto::read_auth_stream: failed to read auth")?;

    let mut trailing = [0u8; 1];
    let n = reader
        .read(&mut trailing)
        .await
        .context("protocol::crypto::read_auth_stream: failed to read auth stream end")?;
    if n != 0 {
        bail!("protocol::crypto::read_auth_stream: trailing auth stream bytes");
    }
    validate_auth_frame(&msg, key, protocol_spec)
}

async fn read_auth_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    protocol_spec: &EffectiveProtocolSpec,
) -> std::io::Result<Vec<u8>> {
    let mut msg = vec![0u8; auth_frame_len(protocol_spec)];
    reader.read_exact(&mut msg).await?;
    Ok(msg)
}

/// Validates an auth frame without leaking which authenticated field failed.
pub fn validate_auth_frame(
    msg: &[u8],
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<SessionId> {
    let expected_len = auth_frame_len(protocol_spec);
    if msg.len() != expected_len {
        bail!("protocol::crypto::validate_auth_frame: invalid authentication frame");
    }
    let parts = split_auth_frame(msg, protocol_spec);
    let padding = &parts.padding[1..];
    let session_id: SessionId = msg[msg.len() - SESSION_ID_LEN..]
        .try_into()
        .expect("validated auth frame length");
    let expected_padding = auth_padding_bytes(protocol_spec, parts.nonce);
    let payload = auth_payload(
        parts.nonce,
        protocol_spec.auth_padding_len,
        padding,
        &session_id,
    );
    let expected = auth_tag(key, protocol_spec, &payload);

    // Collapse all field mismatches into one branch so local logs do not
    // disclose whether magic, padding, or tag validation failed.
    let mut diff = 0u8;
    diff |= constant_time_diff(parts.magic, &protocol_spec.auth_magic);
    diff |= parts.padding[0] ^ protocol_spec.auth_padding_len;
    diff |= constant_time_diff(padding, &expected_padding);
    diff |= constant_time_diff(parts.tag, &expected);
    if diff != 0 {
        bail!("protocol::crypto::validate_auth_frame: invalid authentication frame");
    }
    Ok(session_id)
}

/// Encodes a complete auth frame using the spec-derived field order.
pub fn write_auth_frame(
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
    nonce: [u8; AUTH_NONCE_LEN],
) -> Vec<u8> {
    write_session_auth_frame(key, protocol_spec, nonce, [0; SESSION_ID_LEN])
}

/// Encodes an auth frame bound to a client-generated logical session ID.
pub fn write_session_auth_frame(
    key: Key,
    protocol_spec: &EffectiveProtocolSpec,
    nonce: [u8; AUTH_NONCE_LEN],
    session_id: SessionId,
) -> Vec<u8> {
    let padding = auth_padding_bytes(protocol_spec, &nonce);
    let mut padding_block = Vec::with_capacity(1 + padding.len());
    padding_block.push(protocol_spec.auth_padding_len);
    padding_block.extend_from_slice(&padding);
    let payload = auth_payload(
        &nonce,
        protocol_spec.auth_padding_len,
        &padding,
        &session_id,
    );
    let tag = auth_tag(key, protocol_spec, &payload);

    let mut msg = Vec::with_capacity(auth_frame_len(protocol_spec));
    for element in protocol_spec.auth_frame_order {
        match element {
            AuthFrameElement::Magic => msg.extend_from_slice(&protocol_spec.auth_magic),
            AuthFrameElement::Nonce => msg.extend_from_slice(&nonce),
            AuthFrameElement::Padding => msg.extend_from_slice(&padding_block),
            AuthFrameElement::Tag => msg.extend_from_slice(&tag),
        }
    }
    msg.extend_from_slice(&session_id);
    msg
}

struct AuthFrameParts<'a> {
    magic: &'a [u8],
    nonce: &'a [u8],
    padding: &'a [u8],
    tag: &'a [u8],
}

fn split_auth_frame<'a>(
    msg: &'a [u8],
    protocol_spec: &EffectiveProtocolSpec,
) -> AuthFrameParts<'a> {
    let mut offset = 0;
    let mut magic = None;
    let mut nonce = None;
    let mut padding = None;
    let mut tag = None;

    for element in protocol_spec.auth_frame_order {
        let field_len = auth_field_len(element, protocol_spec);
        let field = &msg[offset..offset + field_len];
        offset += field_len;
        match element {
            AuthFrameElement::Magic => magic = Some(field),
            AuthFrameElement::Nonce => nonce = Some(field),
            AuthFrameElement::Padding => padding = Some(field),
            AuthFrameElement::Tag => tag = Some(field),
        }
    }

    debug_assert_eq!(offset + SESSION_ID_LEN, msg.len());
    AuthFrameParts {
        magic: magic.expect("auth frame order includes magic"),
        nonce: nonce.expect("auth frame order includes nonce"),
        padding: padding.expect("auth frame order includes padding"),
        tag: tag.expect("auth frame order includes tag"),
    }
}

fn auth_field_len(element: AuthFrameElement, protocol_spec: &EffectiveProtocolSpec) -> usize {
    match element {
        AuthFrameElement::Magic => AUTH_MAGIC_LEN,
        AuthFrameElement::Nonce => AUTH_NONCE_LEN,
        AuthFrameElement::Padding => 1 + protocol_spec.auth_padding_len as usize,
        AuthFrameElement::Tag => AUTH_TAG_LEN,
    }
}

fn auth_payload(nonce: &[u8], pad_len: u8, padding: &[u8], session_id: &SessionId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(nonce.len() + 1 + padding.len() + session_id.len());
    payload.extend_from_slice(nonce);
    payload.push(pad_len);
    payload.extend_from_slice(padding);
    payload.extend_from_slice(session_id);
    payload
}

fn auth_tag(key: Key, protocol_spec: &EffectiveProtocolSpec, payload: &[u8]) -> [u8; AUTH_TAG_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&auth_message_prefix(protocol_spec));
    mac.update(payload);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0; AUTH_TAG_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn constant_time_diff(a: &[u8], b: &[u8]) -> u8 {
    let mut diff = u8::from(a.len() != b.len());
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff
}

#[cfg(test)]
#[path = "../tests/protocol/crypto.rs"]
mod tests;
