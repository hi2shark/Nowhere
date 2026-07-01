// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Strict parsing and redacted display for the `socks` URL parameter.

use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use percent_encoding::percent_decode_str;
use url::Url;

#[derive(Clone)]
struct SocksCredentials {
    username: String,
    password: String,
}

/// Validated SOCKS5 endpoint and optional RFC 1929 credentials.
#[derive(Clone)]
pub(crate) struct SocksConfig {
    host: String,
    port: u16,
    credentials: Option<SocksCredentials>,
}

impl fmt::Debug for SocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksConfig")
            .field("endpoint", &self.endpoint())
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

impl SocksConfig {
    /// Parses the unique raw `socks` query value without decoding delimiters first.
    pub(crate) fn from_url(parsed_url: &Url) -> Result<Option<Self>> {
        let Some(query) = parsed_url.query() else {
            return Ok(None);
        };
        let mut raw_value = None;
        for pair in query.split('&') {
            let (raw_key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode_component(raw_key, "query key")?;
            if key != "socks" {
                continue;
            }
            if raw_value.replace(value).is_some() {
                bail!("common::socks::SocksConfig::from_url: duplicate socks parameter");
            }
        }

        let Some(raw_value) = raw_value else {
            return Ok(None);
        };
        if raw_value.is_empty() || decode_component(raw_value, "socks value")? == "none" {
            return Ok(None);
        }

        let (raw_endpoint, credentials) = parse_credentials(raw_value)?;
        let endpoint = decode_component(raw_endpoint, "socks endpoint")?;
        let (host, port) = parse_host_port(&endpoint, "socks endpoint")?;
        Ok(Some(Self {
            host,
            port,
            credentials,
        }))
    }

    /// Returns the credential-free endpoint used in operator output.
    pub(crate) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    pub(super) fn credentials(&self) -> Option<(&str, &str)> {
        self.credentials
            .as_ref()
            .map(|value| (value.username.as_str(), value.password.as_str()))
    }
}

fn parse_credentials(raw_value: &str) -> Result<(&str, Option<SocksCredentials>)> {
    let Some((raw_credentials, raw_endpoint)) = raw_value.split_once('@') else {
        return Ok((raw_value, None));
    };
    if raw_endpoint.contains('@') {
        bail!("common::socks::SocksConfig::from_url: invalid socks credentials");
    }
    let (raw_username, raw_password) = raw_credentials.split_once(':').ok_or_else(|| {
        anyhow!("common::socks::SocksConfig::from_url: invalid socks credentials")
    })?;
    if raw_password.contains(':') {
        bail!("common::socks::SocksConfig::from_url: reserved credentials must be percent-encoded");
    }
    validate_raw_credential(raw_username)?;
    validate_raw_credential(raw_password)?;
    let username = decode_component(raw_username, "socks username")?;
    let password = decode_component(raw_password, "socks password")?;
    validate_credential("username", &username)?;
    validate_credential("password", &password)?;
    Ok((raw_endpoint, Some(SocksCredentials { username, password })))
}

pub(super) fn parse_host_port(value: &str, name: &str) -> Result<(String, u16)> {
    let (host, raw_port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            anyhow!("common::socks::parse_host_port: invalid {name}: missing ']'")
        })?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':').ok_or_else(|| {
            anyhow!("common::socks::parse_host_port: invalid {name}: missing port")
        })?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            bail!("common::socks::parse_host_port: invalid {name}: bracketed host must be IPv6");
        }
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(|| {
            anyhow!("common::socks::parse_host_port: invalid {name}: missing port")
        })?;
        if host.contains(':') {
            bail!("common::socks::parse_host_port: invalid {name}: IPv6 requires brackets");
        }
        (host, port)
    };
    if host.is_empty() {
        bail!("common::socks::parse_host_port: invalid {name}: empty host");
    }
    let port = raw_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("common::socks::parse_host_port: invalid {name}: invalid port"))?;
    Ok((host.to_string(), port))
}

pub(super) fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn validate_credential(name: &str, value: &str) -> Result<()> {
    if !(1..=u8::MAX as usize).contains(&value.len()) {
        bail!("common::socks::validate_credential: {name} length must be 1..255 bytes");
    }
    Ok(())
}

fn validate_raw_credential(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| b":/?#[]@!$&'()*+,;=".contains(&byte))
    {
        bail!(
            "common::socks::validate_raw_credential: reserved credentials must be percent-encoded"
        );
    }
    Ok(())
}

fn decode_component(raw: &str, name: &str) -> Result<String> {
    validate_percent_encoding(raw, name)?;
    percent_decode_str(raw)
        .decode_utf8()
        .with_context(|| format!("common::socks::decode_component: invalid UTF-8 in {name}"))
        .map(|value| value.into_owned())
}

fn validate_percent_encoding(raw: &str, name: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!(
                    "common::socks::validate_percent_encoding: invalid percent encoding in {name}"
                );
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}
