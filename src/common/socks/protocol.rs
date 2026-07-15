// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared SOCKS5 client/server negotiation, address, request, reply, and UDP codecs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::Target;

pub(crate) const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
pub(crate) const AUTH_NONE: u8 = 0;
pub(crate) const AUTH_PASSWORD: u8 = 2;
const AUTH_UNACCEPTABLE: u8 = 0xff;

pub(crate) const COMMAND_CONNECT: u8 = 1;
pub(crate) const COMMAND_BIND: u8 = 2;
pub(crate) const COMMAND_UDP_ASSOCIATE: u8 = 3;

pub(crate) const REPLY_SUCCEEDED: u8 = 0;
pub(crate) const REPLY_GENERAL_FAILURE: u8 = 1;
pub(crate) const REPLY_CONNECTION_NOT_ALLOWED: u8 = 2;
pub(crate) const REPLY_NETWORK_UNREACHABLE: u8 = 3;
pub(crate) const REPLY_HOST_UNREACHABLE: u8 = 4;
pub(crate) const REPLY_TTL_EXPIRED: u8 = 6;
pub(crate) const REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
pub(crate) const REPLY_ADDRESS_NOT_SUPPORTED: u8 = 8;

pub(crate) const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

/// SOCKS5 address representation shared by client and server operations.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SocksAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddress {
    pub(crate) fn from_target(target: &Target) -> Self {
        match target {
            Target::Ip(address) => Self::Ip(*address),
            Target::Domain { host, port } => Self::Domain(host.clone(), *port),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub(crate) fn unspecified() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    pub(crate) fn replace_unspecified_ip(&mut self, proxy_ip: IpAddr) {
        if let Self::Ip(address) = self
            && address.ip().is_unspecified()
        {
            *address = SocketAddr::new(proxy_ip, address.port());
        }
    }
}

impl std::fmt::Display for SocksAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Domain(host, port) => write!(formatter, "{host}:{port}"),
        }
    }
}

/// Negotiates the configured method with an upstream SOCKS5 server.
pub(crate) async fn negotiate<S>(stream: &mut S, credentials: Option<(&str, &str)>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

/// Negotiates exactly one configured method with an inbound SOCKS5 client.
pub(crate) async fn authenticate<S>(stream: &mut S, credentials: Option<(&str, &str)>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("common::socks::authenticate: failed to read method header")?;
    if header[0] != SOCKS_VERSION || header[1] == 0 {
        bail!("common::socks::authenticate: invalid method negotiation");
    }
    let mut methods = [0u8; u8::MAX as usize];
    let methods = &mut methods[..header[1] as usize];
    stream
        .read_exact(methods)
        .await
        .context("common::socks::authenticate: failed to read methods")?;
    let selected = if credentials.is_some() {
        AUTH_PASSWORD
    } else {
        AUTH_NONE
    };
    if !methods.contains(&selected) {
        stream
            .write_all(&[SOCKS_VERSION, AUTH_UNACCEPTABLE])
            .await?;
        bail!("common::socks::authenticate: required method was not offered");
    }
    stream.write_all(&[SOCKS_VERSION, selected]).await?;

    if let Some(credentials) = credentials {
        authenticate_password(stream, credentials).await?;
    }
    Ok(())
}

async fn authenticate_password<S>(stream: &mut S, expected: (&str, &str)) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != AUTH_VERSION || header[1] == 0 {
        let _ = stream.write_all(&[AUTH_VERSION, 1]).await;
        bail!("common::socks::authenticate_password: invalid auth header");
    }
    let mut username = [0u8; u8::MAX as usize];
    let username = &mut username[..header[1] as usize];
    stream.read_exact(username).await?;
    let password_len = stream.read_u8().await? as usize;
    if password_len == 0 {
        let _ = stream.write_all(&[AUTH_VERSION, 1]).await;
        bail!("common::socks::authenticate_password: empty password");
    }
    let mut password = [0u8; u8::MAX as usize];
    let password = &mut password[..password_len];
    stream.read_exact(password).await?;

    let accepted = constant_time_equal(username, expected.0.as_bytes())
        & constant_time_equal(password, expected.1.as_bytes());
    stream
        .write_all(&[AUTH_VERSION, u8::from(!accepted)])
        .await?;
    if !accepted {
        bail!("common::socks::authenticate_password: credentials rejected");
    }
    Ok(())
}

pub(crate) async fn send_command<S>(
    stream: &mut S,
    command: u8,
    target: &SocksAddress,
) -> Result<SocksAddress>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(25);
    request.extend_from_slice(&[SOCKS_VERSION, command, 0]);
    encode_address(&mut request, target)?;
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        bail!("common::socks::send_command: invalid proxy response");
    }
    if header[1] != REPLY_SUCCEEDED {
        bail!(
            "common::socks::send_command: proxy command failed with reply {}",
            header[1]
        );
    }
    read_address(stream, header[3]).await
}

pub(crate) struct SocksRequest {
    pub(crate) command: u8,
    pub(crate) address: SocksAddress,
}

pub(crate) async fn read_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("common::socks::read_request: failed to read header")?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        bail!("common::socks::read_request: invalid request header");
    }
    let address = read_address(stream, header[3]).await?;
    Ok(SocksRequest {
        command: header[1],
        address,
    })
}

pub(crate) async fn write_reply<S>(stream: &mut S, reply: u8, address: &SocksAddress) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut message = Vec::with_capacity(25);
    message.extend_from_slice(&[SOCKS_VERSION, reply, 0]);
    encode_address(&mut message, address)?;
    stream
        .write_all(&message)
        .await
        .context("common::socks::write_reply: failed to write reply")
}

pub(crate) fn udp_header(target: &SocksAddress) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(25);
    header.extend_from_slice(&[0, 0, 0]);
    encode_address(&mut header, target)?;
    Ok(header)
}

pub(crate) fn parse_udp_header(packet: &[u8]) -> Result<(usize, u8)> {
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

pub(crate) fn decode_udp_packet(packet: &[u8]) -> Result<(SocksAddress, u8, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        bail!("common::socks::decode_udp_packet: invalid reserved field");
    }
    let (address, consumed) = decode_address(&packet[3..], packet[3])?;
    let payload_offset = 3usize
        .checked_add(consumed)
        .ok_or_else(|| anyhow!("common::socks::decode_udp_packet: length overflow"))?;
    Ok((address, packet[2], &packet[payload_offset..]))
}

pub(crate) fn encode_udp_packet_into(
    packet: &mut Vec<u8>,
    address: &SocksAddress,
    payload: &[u8],
) -> Result<()> {
    packet.clear();
    packet.reserve(3 + 22 + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    encode_address(packet, address)?;
    packet.extend_from_slice(payload);
    Ok(())
}

pub(crate) fn encode_address(buffer: &mut Vec<u8>, address: &SocksAddress) -> Result<()> {
    match address {
        SocksAddress::Ip(SocketAddr::V4(address)) => {
            buffer.push(ADDRESS_IPV4);
            buffer.extend_from_slice(&address.ip().octets());
            buffer.extend_from_slice(&address.port().to_be_bytes());
        }
        SocksAddress::Ip(SocketAddr::V6(address)) => {
            buffer.push(ADDRESS_IPV6);
            buffer.extend_from_slice(&address.ip().octets());
            buffer.extend_from_slice(&address.port().to_be_bytes());
        }
        SocksAddress::Domain(host, port) => {
            if host.is_empty() || host.len() > u8::MAX as usize || !host.is_ascii() {
                bail!("common::socks::encode_address: invalid domain");
            }
            buffer.extend_from_slice(&[ADDRESS_DOMAIN, host.len() as u8]);
            buffer.extend_from_slice(host.as_bytes());
            buffer.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

pub(crate) async fn read_address<S>(stream: &mut S, address_type: u8) -> Result<SocksAddress>
where
    S: AsyncRead + Unpin,
{
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
            if !host.is_ascii() {
                bail!("common::socks::read_address: domain is not ASCII");
            }
            let port = stream.read_u16().await?;
            Ok(SocksAddress::Domain(
                String::from_utf8(host).expect("ASCII is UTF-8"),
                port,
            ))
        }
        _ => bail!("common::socks::read_address: address type is unsupported"),
    }
}

fn decode_address(packet: &[u8], address_type: u8) -> Result<(SocksAddress, usize)> {
    match address_type {
        ADDRESS_IPV4 => {
            if packet.len() < 7 {
                bail!("common::socks::decode_address: truncated IPv4 address");
            }
            Ok((
                SocksAddress::Ip(SocketAddr::new(
                    IpAddr::from([packet[1], packet[2], packet[3], packet[4]]),
                    u16::from_be_bytes([packet[5], packet[6]]),
                )),
                7,
            ))
        }
        ADDRESS_IPV6 => {
            if packet.len() < 19 {
                bail!("common::socks::decode_address: truncated IPv6 address");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&packet[1..17]);
            Ok((
                SocksAddress::Ip(SocketAddr::new(
                    IpAddr::from(ip),
                    u16::from_be_bytes([packet[17], packet[18]]),
                )),
                19,
            ))
        }
        ADDRESS_DOMAIN => {
            let length = *packet
                .get(1)
                .ok_or_else(|| anyhow!("common::socks::decode_address: truncated domain"))?
                as usize;
            if length == 0 || packet.len() < 2 + length + 2 {
                bail!("common::socks::decode_address: invalid domain length");
            }
            let host = &packet[2..2 + length];
            if !host.is_ascii() {
                bail!("common::socks::decode_address: domain is not ASCII");
            }
            let port_offset = 2 + length;
            Ok((
                SocksAddress::Domain(
                    String::from_utf8(host.to_vec()).expect("ASCII is UTF-8"),
                    u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]),
                ),
                port_offset + 2,
            ))
        }
        _ => bail!("common::socks::decode_address: address type is unsupported"),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        diff |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    diff == 0
}

#[cfg(test)]
#[path = "../../tests/common/socks_protocol.rs"]
mod tests;
