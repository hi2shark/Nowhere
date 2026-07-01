// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared configuration, logging, networking, and TLS utilities.

mod config;
mod logger;
mod network;
mod socks;
mod tls;

pub use config::{
    DEFAULT_DIALER_IP, DEFAULT_RATE_LIMIT, UDP_FRAME_SCRATCH_SIZE, env_duration, env_int,
    handshake_timeout, init_dialer_ip, query_int, quic_max_streams, rate_limit_bytes_per_second,
    reload_interval, report_interval, service_cooldown, shutdown_timeout, tcp_data_buf_size,
    tcp_dial_timeout, tcp_read_timeout, udp_data_buf_size, udp_dial_timeout, udp_idle_timeout,
};
pub use logger::{LogLevel, Logger};
pub use network::{bind_udp_addrs, dial_tcp_from_local_ip, dial_udp_from_local_ip};
pub(crate) use socks::{OutboundDialer, OutboundUdpSocket, SocksConfig};
pub use tls::{TLSMode, new_server_configs};
