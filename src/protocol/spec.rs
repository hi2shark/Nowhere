// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Effective protocol-spec derivation from portal URLs.

#[path = "spec_derivation.rs"]
mod derivation;
#[path = "spec_input.rs"]
mod input;
#[path = "spec_layout.rs"]
mod layout;

use anyhow::Result;
use sha2::{Digest, Sha256};
use url::Url;

pub(super) use self::derivation::{
    auth_frame_len, auth_message_prefix, auth_padding_bytes, tcp_request_padding_bytes,
};
use self::derivation::{base64_url_no_pad, hkdf_expand, hkdf_extract};
pub(super) use self::input::decode_username;
use self::input::{query_value, validate_optional, validate_required};
use self::layout::auth_frame_order_from_seed;
pub use self::layout::{AuthFrameElement, ProxyFrameLayout, TcpFrameElement};

/// Default ALPN advertised by the portal.
pub const DEFAULT_ALPN: &str = "now/1";
/// Default protocol spec seed when the URL omits `spec`.
pub const DEFAULT_SPEC: &str = "auto";
/// Current proxy frame version byte.
pub const PROXY_FRAME_VERSION: u8 = 1;
/// Length of the spec-derived auth magic.
pub const AUTH_MAGIC_LEN: usize = 8;
/// Length of the auth nonce.
pub const AUTH_NONCE_LEN: usize = 32;
/// Length of the auth HMAC tag.
pub const AUTH_TAG_LEN: usize = 32;

const MAX_INPUT_LEN: usize = 255;
const SPEC_ID_LEN: usize = 8;
const AUTH_INFO_LEN: usize = 32;
const AUTH_CONTEXT_LEN: usize = 32;
const AUTH_PADDING_LEN_SEED_LEN: usize = 2;
const AUTH_PADDING_LEN_MAX: usize = 255;
const AUTH_PADDING_KEY_LEN: usize = 32;
const TCP_PADDING_LEN_SEED_LEN: usize = 1;
const TCP_PADDING_LEN_MAX: usize = 64;
const TCP_PADDING_KEY_LEN: usize = 32;

const SPEC_ID_LABEL: &[u8] = b"spec id";
const AUTH_MAGIC_LABEL: &[u8] = b"auth magic";
const AUTH_INFO_LABEL: &[u8] = b"auth hmac info";
const AUTH_CONTEXT_LABEL: &[u8] = b"auth context";
const AUTH_PADDING_LENGTH_LABEL: &[u8] = b"auth padding length";
const AUTH_PADDING_KEY_LABEL: &[u8] = b"auth padding key";
const AUTH_PADDING_BYTES_LABEL: &[u8] = b"auth padding bytes";
const TCP_PADDING_LENGTH_LABEL: &[u8] = b"tcp request padding length";
const TCP_PADDING_KEY_LABEL: &[u8] = b"tcp request padding key";
const TCP_PADDING_BYTES_LABEL: &[u8] = b"tcp request padding bytes";
const AUTH_FRAME_LAYOUT_LABEL: &[u8] = b"auth frame layout";
const FRAME_LAYOUT_LABEL: &[u8] = b"proxy frame layout";

/// Concrete protocol material derived from URL inputs and the shared key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveProtocolSpec {
    /// Effective spec string after applying defaults.
    pub effective_spec: String,
    /// Effective ALPN after applying defaults.
    pub effective_alpn: String,
    /// Default ALPN advertised for this implementation.
    pub default_alpn: String,
    /// Short, display-safe identifier derived from the effective spec.
    pub effective_spec_id: String,
    /// Spec-derived auth frame field order.
    pub auth_frame_order: [AuthFrameElement; 4],
    /// Spec-derived auth magic.
    pub auth_magic: [u8; AUTH_MAGIC_LEN],
    /// Spec-derived HMAC info bytes.
    pub auth_info: [u8; AUTH_INFO_LEN],
    /// Spec-derived auth context bytes.
    pub auth_context: [u8; AUTH_CONTEXT_LEN],
    /// Number of padding bytes carried in auth frames.
    pub auth_padding_len: u8,
    /// Key material used to derive auth padding bytes.
    pub auth_padding_key: [u8; AUTH_PADDING_KEY_LEN],
    /// Number of padding bytes carried in TCP request frames.
    pub tcp_padding_len: u8,
    /// Key material used to derive TCP request padding bytes.
    pub tcp_padding_key: [u8; TCP_PADDING_KEY_LEN],
    /// Spec-derived TCP request frame layout.
    pub frame_layout: ProxyFrameLayout,
}

impl EffectiveProtocolSpec {
    /// Derives all effective protocol material from the parsed URL and shared key.
    pub fn new(parsed_url: &Url, shared_key: &[u8]) -> Result<Self> {
        validate_required("shared key", shared_key)?;

        let explicit_spec = query_value(parsed_url, "spec")?;
        let (effective_spec, effective_spec_bytes) = explicit_spec
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                validate_optional("spec", value.as_bytes())
                    .map(|_| (value.to_string(), value.as_bytes().to_vec()))
            })
            .transpose()?
            .unwrap_or_else(|| (DEFAULT_SPEC.to_string(), DEFAULT_SPEC.as_bytes().to_vec()));

        let spec_salt = Sha256::digest(&effective_spec_bytes);
        let spec_prk = hkdf_extract(spec_salt.as_ref(), &effective_spec_bytes);
        let default_alpn = DEFAULT_ALPN.to_string();
        let explicit_alpn = query_value(parsed_url, "alpn")?;
        let effective_alpn = explicit_alpn
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| validate_optional("alpn", value.as_bytes()).map(|_| value.to_string()))
            .transpose()?
            .unwrap_or_else(|| default_alpn.clone());

        let mut auth_magic = [0u8; AUTH_MAGIC_LEN];
        auth_magic.copy_from_slice(&hkdf_expand(&spec_prk, AUTH_MAGIC_LABEL, AUTH_MAGIC_LEN));
        let mut auth_info = [0u8; AUTH_INFO_LEN];
        auth_info.copy_from_slice(&hkdf_expand(&spec_prk, AUTH_INFO_LABEL, AUTH_INFO_LEN));
        let mut auth_context = [0u8; AUTH_CONTEXT_LEN];
        auth_context.copy_from_slice(&hkdf_expand(
            &spec_prk,
            AUTH_CONTEXT_LABEL,
            AUTH_CONTEXT_LEN,
        ));
        let auth_padding_len_seed = hkdf_expand(
            &spec_prk,
            AUTH_PADDING_LENGTH_LABEL,
            AUTH_PADDING_LEN_SEED_LEN,
        );
        let auth_padding_len = 1
            + (u16::from_be_bytes(
                auth_padding_len_seed
                    .as_slice()
                    .try_into()
                    .expect("padding length seed length"),
            ) as usize
                % AUTH_PADDING_LEN_MAX);
        let auth_padding_len = auth_padding_len as u8;
        let mut auth_padding_key = [0u8; AUTH_PADDING_KEY_LEN];
        auth_padding_key.copy_from_slice(&hkdf_expand(
            &spec_prk,
            AUTH_PADDING_KEY_LABEL,
            AUTH_PADDING_KEY_LEN,
        ));
        let tcp_padding_len = hkdf_expand(
            &spec_prk,
            TCP_PADDING_LENGTH_LABEL,
            TCP_PADDING_LEN_SEED_LEN,
        )[0] % TCP_PADDING_LEN_MAX as u8;
        let mut tcp_padding_key = [0u8; TCP_PADDING_KEY_LEN];
        tcp_padding_key.copy_from_slice(&hkdf_expand(
            &spec_prk,
            TCP_PADDING_KEY_LABEL,
            TCP_PADDING_KEY_LEN,
        ));
        let auth_frame_order =
            auth_frame_order_from_seed(&hkdf_expand(&spec_prk, AUTH_FRAME_LAYOUT_LABEL, 8));
        let frame_layout =
            ProxyFrameLayout::from_seed(&hkdf_expand(&spec_prk, FRAME_LAYOUT_LABEL, 8));

        Ok(Self {
            effective_spec,
            effective_alpn,
            default_alpn,
            effective_spec_id: base64_url_no_pad(&hkdf_expand(
                &spec_prk,
                SPEC_ID_LABEL,
                SPEC_ID_LEN,
            )),
            auth_frame_order,
            auth_magic,
            auth_info,
            auth_context,
            auth_padding_len,
            auth_padding_key,
            tcp_padding_len,
            tcp_padding_key,
            frame_layout,
        })
    }
}

#[cfg(test)]
#[path = "../tests/protocol/spec.rs"]
mod tests;
