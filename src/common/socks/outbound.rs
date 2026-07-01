// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Direct-or-SOCKS5 TCP/UDP connection establishment and proxy address retry.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::{TcpStream, lookup_host};

use super::config::{SocksConfig, format_host_port};
use super::protocol::{
    COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, SocksAddress, negotiate, send_command, udp_header,
};
use super::udp::{OutboundUdpSocket, SocksUdpAssociation};
use crate::common::network::{connect_tcp_addr, connect_udp_addr, filter_addrs, parse_local_ip};
use crate::common::{dial_tcp_from_local_ip, dial_udp_from_local_ip};

/// Direct-or-SOCKS outbound connector shared by every relay path.
#[derive(Clone, Debug)]
pub(crate) struct OutboundDialer {
    dialer_ip: String,
    socks: Option<SocksConfig>,
}

impl OutboundDialer {
    pub(crate) fn new(dialer_ip: String, socks: Option<SocksConfig>) -> Self {
        Self { dialer_ip, socks }
    }

    pub(crate) fn dialer_ip(&self) -> &str {
        &self.dialer_ip
    }

    pub(crate) fn socks_endpoint(&self) -> String {
        self.socks
            .as_ref()
            .map(SocksConfig::endpoint)
            .unwrap_or_else(|| "none".to_string())
    }

    pub(crate) async fn dial_tcp(&self, target: &str, timeout: Duration) -> Result<TcpStream> {
        let Some(config) = &self.socks else {
            return dial_tcp_from_local_ip(&self.dialer_ip, target, timeout).await;
        };
        let target = SocksAddress::parse(target, "target")?;
        tokio::time::timeout(timeout, self.dial_socks_tcp(config, &target))
            .await
            .map_err(|_| anyhow!("common::socks::OutboundDialer::dial_tcp: dial timeout"))?
    }

    pub(crate) async fn dial_udp(
        &self,
        target: &str,
        timeout: Duration,
    ) -> Result<OutboundUdpSocket> {
        let Some(config) = &self.socks else {
            return dial_udp_from_local_ip(&self.dialer_ip, target, timeout)
                .await
                .map(OutboundUdpSocket::Direct);
        };
        let target = SocksAddress::parse(target, "target")?;
        tokio::time::timeout(timeout, self.dial_socks_udp(config, target))
            .await
            .map_err(|_| anyhow!("common::socks::OutboundDialer::dial_udp: dial timeout"))?
    }

    async fn dial_socks_tcp(
        &self,
        config: &SocksConfig,
        target: &SocksAddress,
    ) -> Result<TcpStream> {
        let local_ip = parse_local_ip(&self.dialer_ip);
        let addrs = resolve_proxy(config, local_ip).await?;
        let mut last_err = None;
        for addr in addrs {
            let mut stream = match connect_tcp_addr(local_ip, addr).await {
                Ok(stream) => stream,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };
            if let Err(err) = negotiate(&mut stream, config.credentials()).await {
                last_err = Some(err);
                continue;
            }
            match send_command(&mut stream, COMMAND_CONNECT, target).await {
                Ok(_) => return Ok(stream),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow!("common::socks::OutboundDialer::dial_tcp: no proxy address")
        }))
    }

    async fn dial_socks_udp(
        &self,
        config: &SocksConfig,
        target: SocksAddress,
    ) -> Result<OutboundUdpSocket> {
        let local_ip = parse_local_ip(&self.dialer_ip);
        let addrs = resolve_proxy(config, local_ip).await?;
        let mut last_err = None;
        for addr in addrs {
            match self
                .open_socks_udp_candidate(config, target.clone(), local_ip, addr)
                .await
            {
                Ok(association) => return Ok(OutboundUdpSocket::Socks(association)),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow!("common::socks::OutboundDialer::dial_udp: no proxy address")
        }))
    }

    async fn open_socks_udp_candidate(
        &self,
        config: &SocksConfig,
        target: SocksAddress,
        local_ip: Option<IpAddr>,
        proxy_addr: SocketAddr,
    ) -> Result<SocksUdpAssociation> {
        let mut control = connect_tcp_addr(local_ip, proxy_addr).await?;
        negotiate(&mut control, config.credentials()).await?;
        let unspecified = if proxy_addr.is_ipv4() {
            SocksAddress::Ip(SocketAddr::from(([0, 0, 0, 0], 0)))
        } else {
            SocksAddress::Ip(SocketAddr::from(([0u16; 8], 0)))
        };
        let mut relay = send_command(&mut control, COMMAND_UDP_ASSOCIATE, &unspecified).await?;
        relay.replace_unspecified_ip(proxy_addr.ip());
        let relay_addr = resolve_relay(&relay, local_ip).await?;
        let socket = connect_udp_addr(local_ip, relay_addr).await?;
        let target_header = udp_header(&target)?;
        Ok(SocksUdpAssociation {
            control,
            socket,
            target_header,
        })
    }
}

async fn resolve_proxy(config: &SocksConfig, local_ip: Option<IpAddr>) -> Result<Vec<SocketAddr>> {
    let endpoint = config.endpoint();
    let addrs = lookup_host(endpoint.as_str())
        .await
        .context("common::socks::resolve_proxy: failed to resolve proxy endpoint")?;
    let addrs = filter_addrs(addrs, local_ip);
    if addrs.is_empty() {
        bail!("common::socks::resolve_proxy: no proxy address matches dial address family");
    }
    Ok(addrs)
}

async fn resolve_relay(relay: &SocksAddress, local_ip: Option<IpAddr>) -> Result<SocketAddr> {
    match relay {
        SocksAddress::Ip(addr) => {
            if addr.port() == 0 {
                bail!("common::socks::resolve_relay: proxy returned zero relay port");
            }
            if local_ip.is_some_and(|ip| ip.is_ipv4() != addr.is_ipv4()) {
                bail!("common::socks::resolve_relay: relay address family conflicts with dial");
            }
            Ok(*addr)
        }
        SocksAddress::Domain(host, port) => {
            if *port == 0 {
                bail!("common::socks::resolve_relay: proxy returned zero relay port");
            }
            let endpoint = format_host_port(host, *port);
            let addrs = lookup_host(endpoint.as_str())
                .await
                .context("common::socks::resolve_relay: failed to resolve relay endpoint")?;
            filter_addrs(addrs, local_ip)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("common::socks::resolve_relay: no matching relay address"))
        }
    }
}
