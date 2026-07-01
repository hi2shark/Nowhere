// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 configuration and direct-or-proxied outbound dialing.

#[path = "socks/config.rs"]
mod config;
#[path = "socks/outbound.rs"]
mod outbound;
#[path = "socks/protocol.rs"]
mod protocol;
#[path = "socks/udp.rs"]
mod udp;

pub(crate) use config::SocksConfig;
pub(crate) use outbound::OutboundDialer;
pub(crate) use udp::OutboundUdpSocket;

#[cfg(test)]
use protocol::{
    ADDRESS_IPV4, AUTH_NONE, AUTH_PASSWORD, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, SOCKS_VERSION,
    SocksAddress, encode_address, parse_udp_header, read_address,
};

#[cfg(test)]
#[path = "../tests/common/socks.rs"]
mod tests;
