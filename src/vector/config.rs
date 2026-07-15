// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated `vector://` URL parsing with first-value query semantics.

use std::fmt;

use anyhow::{Result, anyhow, bail};
use url::Url;

use crate::common::query_first;
use crate::common::socks::{
    SocksCredentials, first_raw_socks_value, format_host_port, parse_host_port, parse_socks_value,
};

pub(super) const DEFAULT_ALPN: &str = "now/1";
pub(super) const DEFAULT_POOL_SIZE: usize = 5;
pub(super) const MAX_POOL_SIZE: usize = 256;

const VECTOR_QUERY_KEYS: &[&str] = &[
    "up", "down", "pool", "sni", "alpn", "rate", "etar", "socks", "log",
];

/// Physical carrier selected for one logical flow direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierMode {
    Tcp,
    Udp,
}

impl CarrierMode {
    fn parse(value: Option<&str>, name: &str) -> Result<Self> {
        match value {
            None => Ok(Self::Udp),
            Some("tcp") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some(_) => bail!("vector::config: {name} must be tcp or udp"),
        }
    }

    pub(super) fn is_tcp(self) -> bool {
        self == Self::Tcp
    }
}

impl fmt::Display for CarrierMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Validated local SOCKS5 listen endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksListenConfig {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) credentials: Option<SocksCredentials>,
}

impl SocksListenConfig {
    fn from_url(url: &Url) -> Result<Self> {
        let raw_value = first_raw_socks_value(url)
            .ok_or_else(|| anyhow!("vector::config: socks parameter is required"))?;
        if raw_value.is_empty() {
            bail!("vector::config: socks must not be empty");
        }
        let (endpoint, credentials) = parse_socks_value(raw_value)?;
        let (host, port) = parse_host_port(&endpoint, "socks listener", true)?;
        Ok(Self {
            host,
            port,
            credentials,
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    pub(super) fn authenticated(&self) -> bool {
        self.credentials.is_some()
    }
}

/// Fully validated Vector runtime configuration.
#[derive(Clone, Debug)]
pub(crate) struct VectorConfig {
    pub(super) remote_host: String,
    pub(super) remote_port: u16,
    pub(super) up: CarrierMode,
    pub(super) down: CarrierMode,
    pub(super) pool: usize,
    pub(super) alpn: String,
    pub(super) sni: Option<String>,
    pub(super) rate_mbps: i32,
    pub(super) etar_mbps: i32,
    pub(super) socks: SocksListenConfig,
}

impl VectorConfig {
    pub(super) fn from_url(url: &Url) -> Result<Self> {
        if url.scheme() != "vector" {
            bail!("vector::config: URL scheme must be vector");
        }
        if url.password().is_some() {
            bail!("vector::config: URL password component is not supported");
        }
        if url.username().is_empty() {
            bail!("vector::config: missing shared key");
        }
        if url.fragment().is_some() {
            bail!("vector::config: URL fragment is not supported");
        }
        if !url.path().is_empty() {
            bail!("vector::config: URL path is not supported");
        }

        let remote_host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| anyhow!("vector::config: missing Portal host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let remote_port = url
            .port()
            .filter(|port| *port != 0)
            .ok_or_else(|| anyhow!("vector::config: missing Portal port"))?;
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        let up = CarrierMode::parse(query.get("up").map(String::as_str), "up")?;
        let down = CarrierMode::parse(query.get("down").map(String::as_str), "down")?;
        let tcp_only = up.is_tcp() && down.is_tcp();
        let pool = if tcp_only {
            query.get("pool").map_or(Ok(DEFAULT_POOL_SIZE), |value| {
                value
                    .parse::<u128>()
                    .map(|value| value.min(MAX_POOL_SIZE as u128) as usize)
                    .map_err(|_| anyhow!("vector::config: invalid pool size"))
            })?
        } else {
            0
        };

        let alpn = query
            .get("alpn")
            .map(String::as_str)
            .unwrap_or(DEFAULT_ALPN);
        if alpn.is_empty() || alpn.len() > u8::MAX as usize {
            bail!("vector::config: alpn length must be 1..255 bytes");
        }
        let sni = query
            .get("sni")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .map(|value| {
                if !value.is_ascii()
                    || value.len() > 253
                    || value.contains([':', '[', ']'])
                    || value.parse::<std::net::IpAddr>().is_ok()
                {
                    bail!("vector::config: sni must be an ASCII DNS name");
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        let rate_mbps = parse_rate(query.get("rate").map(String::as_str), "rate")?;
        let etar_mbps = parse_rate(query.get("etar").map(String::as_str), "etar")?;
        let socks = SocksListenConfig::from_url(url)?;

        Ok(Self {
            remote_host,
            remote_port,
            up,
            down,
            pool,
            alpn: alpn.to_owned(),
            sni,
            rate_mbps,
            etar_mbps,
            socks,
        })
    }

    pub(super) fn portal_endpoint(&self) -> String {
        format_host_port(&self.remote_host, self.remote_port)
    }

    pub(super) fn checkpoint_mode(&self) -> u8 {
        match (self.up, self.down) {
            (CarrierMode::Tcp, CarrierMode::Tcp) => 0,
            (CarrierMode::Tcp, CarrierMode::Udp) => 1,
            (CarrierMode::Udp, CarrierMode::Tcp) => 2,
            (CarrierMode::Udp, CarrierMode::Udp) => 3,
        }
    }

    pub(super) fn effective_url(&self) -> String {
        format!(
            "vector://{}?up={}&down={}&pool={}&sni={}&alpn={}&rate={}&etar={}&socks={}",
            self.portal_endpoint(),
            self.up,
            self.down,
            self.pool,
            self.sni.as_deref().unwrap_or("none"),
            self.alpn,
            self.rate_mbps,
            self.etar_mbps,
            self.socks.endpoint(),
        )
    }
}

fn parse_rate(value: Option<&str>, name: &str) -> Result<i32> {
    match value {
        None => Ok(0),
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow!("vector::config: {name} must be a non-negative integer")),
    }
}

#[cfg(test)]
#[path = "../tests/vector/config.rs"]
mod tests;
