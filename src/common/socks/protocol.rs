// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 method negotiation, commands, and address/UDP header codecs.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::config::parse_host_port;

pub(super) const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
pub(super) const AUTH_NONE: u8 = 0;
pub(super) const AUTH_PASSWORD: u8 = 2;
const AUTH_UNACCEPTABLE: u8 = 0xff;
pub(super) const COMMAND_CONNECT: u8 = 1;
pub(super) const COMMAND_UDP_ASSOCIATE: u8 = 3;
pub(super) const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SocksAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddress {
    pub(super) fn parse(value: &str, name: &str) -> Result<Self> {
        let (host, port) = parse_host_port(value, name)?;
        match host.parse::<IpAddr>() {
            Ok(ip) => Ok(Self::Ip(SocketAddr::new(ip, port))),
            Err(_) => {
                if host.len() > u8::MAX as usize {
                    bail!("common::socks::SocksAddress::parse: {name} host exceeds 255 bytes");
                }
                Ok(Self::Domain(host, port))
            }
        }
    }

    pub(super) fn replace_unspecified_ip(&mut self, proxy_ip: IpAddr) {
        if let Self::Ip(addr) = self
            && addr.ip().is_unspecified()
        {
            *addr = SocketAddr::new(proxy_ip, addr.port());
        }
    }
}

pub(super) async fn negotiate(
    stream: &mut TcpStream,
    credentials: Option<(&str, &str)>,
) -> Result<()> {
    let method = if credentials.is_some() {
        AUTH_PASSWORD
    } else {
        AUTH_NONE
    };
    stream.write_all(&[SOCKS_VERSION, 1, method]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != SOCKS_VERSION {
        bail!("common::socks::negotiate: invalid SOCKS version");
    }
    if response[1] == AUTH_UNACCEPTABLE {
        bail!("common::socks::negotiate: proxy rejected authentication method");
    }
    if response[1] != method {
        bail!("common::socks::negotiate: proxy selected an unadvertised authentication method");
    }

    if let Some((username, password)) = credentials {
        let username = username.as_bytes();
        let password = password.as_bytes();
        let mut request = Vec::with_capacity(3 + username.len() + password.len());
        request.extend_from_slice(&[AUTH_VERSION, username.len() as u8]);
        request.extend_from_slice(username);
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream.write_all(&request).await?;
        stream.read_exact(&mut response).await?;
        if response[0] != AUTH_VERSION || response[1] != 0 {
            bail!("common::socks::negotiate: username/password authentication failed");
        }
    }
    Ok(())
}

pub(super) async fn send_command(
    stream: &mut TcpStream,
    command: u8,
    target: &SocksAddress,
) -> Result<SocksAddress> {
    let mut request = vec![SOCKS_VERSION, command, 0];
    encode_address(&mut request, target)?;
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        bail!("common::socks::send_command: invalid proxy response");
    }
    if header[1] != 0 {
        bail!(
            "common::socks::send_command: proxy command failed with reply {}",
            header[1]
        );
    }
    read_address(stream, header[3]).await
}

pub(super) fn udp_header(target: &SocksAddress) -> Result<Vec<u8>> {
    let mut header = vec![0, 0, 0];
    encode_address(&mut header, target)?;
    Ok(header)
}

pub(super) fn parse_udp_header(packet: &[u8]) -> Result<(usize, u8)> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        bail!("common::socks::parse_udp_header: invalid UDP relay header");
    }
    let address_len = match packet[3] {
        ADDRESS_IPV4 => 1 + 4 + 2,
        ADDRESS_IPV6 => 1 + 16 + 2,
        ADDRESS_DOMAIN => {
            let len = *packet
                .get(4)
                .ok_or_else(|| anyhow!("common::socks::parse_udp_header: truncated domain"))?
                as usize;
            1 + 1 + len + 2
        }
        _ => bail!("common::socks::parse_udp_header: unsupported address type"),
    };
    let header_len = 3 + address_len;
    if packet.len() < header_len {
        bail!("common::socks::parse_udp_header: truncated UDP relay header");
    }
    Ok((header_len, packet[2]))
}

pub(super) fn encode_address(buffer: &mut Vec<u8>, target: &SocksAddress) -> Result<()> {
    match target {
        SocksAddress::Ip(SocketAddr::V4(addr)) => {
            buffer.push(ADDRESS_IPV4);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddress::Ip(SocketAddr::V6(addr)) => {
            buffer.push(ADDRESS_IPV6);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddress::Domain(host, port) => {
            if host.len() > u8::MAX as usize {
                bail!("common::socks::encode_address: domain exceeds 255 bytes");
            }
            buffer.extend_from_slice(&[ADDRESS_DOMAIN, host.len() as u8]);
            buffer.extend_from_slice(host.as_bytes());
            buffer.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

pub(super) async fn read_address(stream: &mut TcpStream, address_type: u8) -> Result<SocksAddress> {
    match address_type {
        ADDRESS_IPV4 => {
            let mut value = [0u8; 6];
            stream.read_exact(&mut value).await?;
            Ok(SocksAddress::Ip(SocketAddr::new(
                IpAddr::from([value[0], value[1], value[2], value[3]]),
                u16::from_be_bytes([value[4], value[5]]),
            )))
        }
        ADDRESS_IPV6 => {
            let mut value = [0u8; 18];
            stream.read_exact(&mut value).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[..16]);
            Ok(SocksAddress::Ip(SocketAddr::new(
                IpAddr::from(ip),
                u16::from_be_bytes([value[16], value[17]]),
            )))
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                bail!("common::socks::read_address: empty domain");
            }
            let mut host = vec![0u8; length];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            Ok(SocksAddress::Domain(
                String::from_utf8(host).context("common::socks::read_address: invalid domain")?,
                port,
            ))
        }
        _ => bail!("common::socks::read_address: unsupported address type"),
    }
}
