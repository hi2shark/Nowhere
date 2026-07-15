// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Command-line entry point for running a Nowhere Portal or Vector.

use std::env;

use anyhow::{Context, Result, bail};
use nowhere::common::{LogLevel, Logger, query_first};
use nowhere::portal::Portal;
use nowhere::vector::Vector;
use url::{ParseError, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP_TEXT: &str = "\
Usage:
  nowhere <portal-or-vector-url>
  nowhere -h | --help
  nowhere -v | --version

Commands:
  <portal-url>     Run the Portal relay service.
  <vector-url>     Run the Vector native SOCKS5 client.
  -h, --help       Print this help message.
  -v, --version    Print version and target platform.

Portal URL:
  portal://<shared-key>@<listen-host>:<listen-port>[?<parameters>]

Vector URL:
  vector://<shared-key>@<portal-host>:<portal-port>?socks=<listen-endpoint>[&<parameters>]

Examples:
  nowhere 'portal://secret@:2077'
  nowhere 'portal://secret@0.0.0.0:2077?log=info&net=tcp'
  nowhere 'portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
  nowhere 'portal://secret@:2077?socks=user:pass@127.0.0.1:1080'
  nowhere 'portal://secret@:2077?rate=100&etar=200'
  nowhere 'vector://secret@relay.example:2077?sni=relay.example&socks=127.0.0.1:1080'
  nowhere 'vector://secret@127.0.0.1:2077?up=tcp&down=tcp&pool=5&socks=:1080'

Required URL parts:
  shared-key       Non-empty URL username. Percent-encode reserved characters.
  endpoint-port    Portal listen port or remote Portal port.
  Password credentials are not supported.

Listen host:
  empty            Bind IPv4 and IPv6 wildcard sockets.
  0.0.0.0          Bind IPv4 wildcard only.
  [::]             Bind IPv6 wildcard only.
  IP or hostname   Bind the resolved listen address.

Portal parameters:
  net=mix|tcp|udp  Listener mode. Default: mix.
  tls=1|2          TLS mode. 1 for RAM certificate; 2 for PEM files. Default: 1.
                   tls=0 is not supported.
  crt=<path>       PEM certificate chain for tls=2.
  key=<path>       PEM private key for tls=2.
  alpn=<value>     TLS/QUIC ALPN. Default: now/1.
  rate=<mbps>      Client-to-target traffic limit. 0 disables it.
  etar=<mbps>      Target-to-client traffic limit. 0 disables it.
  dial=<ip|auto>   Local source IP for outbound target connections. Default: auto.
  socks=<proxy>    SOCKS5 outbound proxy: host:port or user:pass@host:port.
                   Omit, leave empty, or use none to disable.
  log=<level>      none, debug, info, warn, error, event. Default: info.

Vector parameters:
  up=tcp|udp       Upload carrier. Default: udp.
  down=tcp|udp     Download carrier. Default: udp.
  pool=<number>    TLS warm pool for tcp/tcp; default 5, clamped to 256.
                   Ignored for other carrier pairs, which report pool=0.
  sni=<name|none>  Verify the certificate for a DNS name. Empty, omitted, or
                   none disables certificate validation. Default: none.
  alpn=<value>     TLS/QUIC ALPN. Default: now/1.
  rate=<mbps>      SOCKS client-to-target limit. 0 disables it.
  etar=<mbps>      Target-to-SOCKS client limit. 0 disables it.
  socks=<listener> Required SOCKS5 listener: [user:pass@]host:port.
                   An empty host, as in :1080, binds IPv4 and IPv6 wildcards.
  log=<level>      none, debug, info, warn, error, event. Default: info.

Query handling:
  Unknown parameters are ignored. If a parameter appears more than once, only
  its first value is used. Missing optional parameters use their defaults.

Transport capabilities:
  TLS/TCP          TCP relay and UDP-over-TCP (UoT).
  QUIC/UDP         TCP relay streams and DATAGRAM UDP flows.

SOCKS5 outbound:
  CONNECT proxies every TCP relay. UDP ASSOCIATE proxies every DATAGRAM/UoT flow.
  Target hostnames are resolved by the proxy. Proxy failure never falls back direct.
  Percent-encode reserved characters in SOCKS usernames and passwords.

SOCKS5 inbound:
  Vector supports CONNECT and UDP ASSOCIATE. BIND is not supported.
  Configured username/password authentication cannot downgrade to no-auth.
  SOCKS5 UDP fragmentation is not supported.

Environment:
  NOW_QUIC_MAX_STREAMS      Maximum authenticated QUIC streams.
  NOW_QUIC_MAX_UDP_FLOWS    Maximum UDP flows per authenticated logical session.
  NOW_QUIC_UDP_QUEUE_BYTES  Maximum queued/reassembling UDP bytes per QUIC connection.
  NOW_TCP_IDLE_POOL_CONNS   Maximum authenticated idle TLS/TCP connections.
  NOW_MAX_PENDING_PAIRS     Maximum pending logical-flow IDs per session.
  NOW_FLOW_PAIR_TIMEOUT     Timeout for completing a split logical flow.
  NOW_TCP_DATA_BUF_SIZE     TCP relay buffer size.
  NOW_UDP_DATA_BUF_SIZE     UDP target receive buffer size.
  NOW_TCP_DIAL_TIMEOUT      TCP target dial timeout.
  NOW_UDP_DIAL_TIMEOUT      UDP target dial timeout.
  NOW_TCP_READ_TIMEOUT      TCP half-close grace timeout.
  NOW_UDP_IDLE_TIMEOUT      QUIC and DATAGRAM/UoT flow idle timeout.
  NOW_HANDSHAKE_TIMEOUT     Fixed authentication and setup deadline.
  NOW_REPORT_INTERVAL       Local CHECK_POINT and LINK_STATUS report interval.
  NOW_SERVICE_COOLDOWN      Transport reconnect retry delay.
  NOW_SHUTDOWN_TIMEOUT      Graceful shutdown wait.
  NOW_RELOAD_INTERVAL       Minimum PEM certificate reload interval.";

#[tokio::main]
async fn main() {
    if let Err(err) = start(env::args().collect()).await {
        eprintln!(
            "nowhere-{VERSION} {}/{} pid={} error={err:#}",
            env::consts::OS,
            env::consts::ARCH,
            std::process::id(),
        );
        std::process::exit(1);
    }
}

async fn start(args: Vec<String>) -> Result<()> {
    if args.len() < 2 {
        bail!("main::start: missing configuration URL argument");
    }
    if args.len() > 2 {
        bail!("main::start: expected exactly one configuration URL");
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "version" | "--version" | "-v" => {
            println!(
                "nowhere-v{VERSION} {}/{}",
                env::consts::OS,
                env::consts::ARCH
            );
            return Ok(());
        }
        _ => {}
    }

    let command_url =
        parse_command_url(&args[1]).with_context(|| "main::start: failed to parse command URL")?;
    let scheme = command_url.url.scheme().to_string();
    let allowed = match scheme.as_str() {
        "portal" => &[
            "net", "tls", "crt", "key", "alpn", "rate", "etar", "dial", "socks", "log",
        ][..],
        "vector" => &[
            "up", "down", "pool", "sni", "alpn", "rate", "etar", "socks", "log",
        ][..],
        _ => bail!("main::start: unknown URL scheme: {scheme}"),
    };
    let query =
        query_first(&command_url.url, allowed).with_context(|| "main::start: invalid URL query")?;
    let logger = init_logger(query.get("log").map(String::as_str))?;

    match scheme.as_str() {
        "portal" => {
            let portal = Portal::new_with_listen_host(
                command_url.url,
                command_url.listen_host.as_deref(),
                logger,
            )
            .with_context(|| "main::start: failed to create portal")?;
            portal.run().await
        }
        "vector" => {
            let vector = Vector::new(command_url.url, logger)
                .with_context(|| "main::start: failed to create vector")?;
            vector.run().await
        }
        _ => bail!("main::start: unknown URL scheme: {}", scheme),
    }
}

fn print_help() {
    println!(
        "nowhere-v{VERSION} {}/{}\n\n{HELP_TEXT}",
        env::consts::OS,
        env::consts::ARCH
    );
}

struct CommandUrl {
    url: Url,
    listen_host: Option<String>,
}

fn parse_command_url(raw: &str) -> Result<CommandUrl> {
    match Url::parse(raw) {
        Ok(url) => Ok(CommandUrl {
            url,
            listen_host: None,
        }),
        Err(ParseError::EmptyHost) => {
            let normalized = normalize_empty_portal_host(raw)
                .ok_or(ParseError::EmptyHost)
                .and_then(|url| Url::parse(&url))?;
            Ok(CommandUrl {
                url: normalized,
                listen_host: Some(String::new()),
            })
        }
        Err(err) => Err(err.into()),
    }
}

fn normalize_empty_portal_host(raw: &str) -> Option<String> {
    let prefix = "portal://";
    let rest = raw.strip_prefix(prefix)?;
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_len);
    let host_port_start = authority.rfind('@').map_or(0, |idx| idx + 1);
    let host_port = &authority[host_port_start..];

    if !host_port.starts_with(':') || host_port.len() == 1 {
        return None;
    }

    let mut normalized = String::with_capacity(raw.len() + "localhost".len());
    normalized.push_str(prefix);
    normalized.push_str(&authority[..host_port_start]);
    normalized.push_str("localhost");
    normalized.push_str(host_port);
    normalized.push_str(suffix);
    Some(normalized)
}

fn init_logger(level: Option<&str>) -> Result<Logger> {
    let logger = Logger::new(LogLevel::Info, true);
    match level {
        None | Some("info") => {}
        Some("none") => logger.set_log_level(LogLevel::None),
        Some("debug") => {
            logger.set_log_level(LogLevel::Debug);
            logger.debug(format_args!("main::init_logger: log level set to DEBUG"));
        }
        Some("warn") => {
            logger.set_log_level(LogLevel::Warn);
            logger.warn(format_args!("main::init_logger: log level set to WARN"));
        }
        Some("error") => {
            logger.set_log_level(LogLevel::Error);
            logger.error(format_args!("main::init_logger: log level set to ERROR"));
        }
        Some("event") => {
            logger.set_log_level(LogLevel::Event);
            logger.event(format_args!("main::init_logger: log level set to EVENT"));
        }
        Some(value) => bail!("main::init_logger: invalid log level: {value}"),
    }
    Ok(logger)
}

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
