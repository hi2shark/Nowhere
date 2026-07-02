// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network-mode parsing for TCP, UDP, or mixed service.

use std::fmt;

use anyhow::Result;
use url::Url;

/// Portal listener mode selected by the `net` URL query parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkMode {
    Mix,
    Tcp,
    Udp,
}

impl NetworkMode {
    /// Parses the URL `net` query parameter, defaulting to mixed service.
    pub(super) fn from_url(parsed_url: &Url) -> Result<Self> {
        match parsed_url
            .query_pairs()
            .find(|(key, _)| key == "net")
            .map(|(_, value)| value)
            .as_deref()
        {
            None | Some("") => Ok(Self::Mix),
            Some("mix") => Ok(Self::Mix),
            Some("tcp") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some(_) => Err(anyhow::anyhow!("portal::NetworkMode: invalid net mode")),
        }
    }

    /// Returns whether this mode should accept TLS/TCP connections.
    pub(super) fn listens_tcp(self) -> bool {
        matches!(self, Self::Mix | Self::Tcp)
    }

    /// Returns whether this mode should accept QUIC/UDP connections.
    pub(super) fn listens_udp(self) -> bool {
        matches!(self, Self::Mix | Self::Udp)
    }

    /// Returns the numeric mode reported in checkpoint events.
    pub(super) fn checkpoint_value(self) -> u8 {
        match self {
            Self::Mix => 0,
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mix => formatter.write_str("mix"),
            Self::Tcp => formatter.write_str("tcp"),
            Self::Udp => formatter.write_str("udp"),
        }
    }
}
