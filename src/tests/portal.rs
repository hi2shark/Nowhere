// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction and formatting tests.

use super::*;
use crate::common::{LogLevel, Logger};
use tokio::net::TcpListener;
use url::Url;

fn test_logger() -> Logger {
    Logger::new(LogLevel::None, false)
}

#[test]
fn empty_host_listens_on_both_wildcard_families() {
    let portal = Portal::new_with_listen_host(
        Url::parse("portal://secret@localhost:2077?dial=127.0.0.1").unwrap(),
        Some(""),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.endpoint_addr, ":2077");
    assert_eq!(
        portal.inner.bind_addrs,
        vec![
            SocketAddr::from(([0, 0, 0, 0], 2077)),
            SocketAddr::from(([0u16; 8], 2077)),
        ]
    );
    assert_eq!(portal.inner.outbound.dialer_ip(), "127.0.0.1");
    assert_eq!(portal.inner.network_mode, NetworkMode::Mix);
    assert_eq!(portal.inner.alpn, "now/1");
    assert_eq!(
        portal.effective_url(),
        "portal://:2077?net=mix&tls=1&alpn=now/1&rate=0&etar=0&dial=127.0.0.1&socks=none"
    );
}

#[test]
fn explicit_wildcard_host_selects_one_address_family() {
    let ipv4 = Portal::new(
        Url::parse("portal://secret@0.0.0.0:2077?dial=auto").unwrap(),
        test_logger(),
    )
    .unwrap();
    let ipv6 = Portal::new(
        Url::parse("portal://secret@[::]:2077?dial=::1").unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(ipv4.inner.endpoint_addr, "0.0.0.0:2077");
    assert_eq!(
        ipv4.inner.bind_addrs,
        vec![SocketAddr::from(([0, 0, 0, 0], 2077))]
    );
    assert_eq!(ipv4.inner.outbound.dialer_ip(), "auto");

    assert_eq!(ipv6.inner.endpoint_addr, "[::]:2077");
    assert_eq!(
        ipv6.inner.bind_addrs,
        vec![SocketAddr::from(([0u16; 8], 2077))]
    );
    assert_eq!(ipv6.inner.outbound.dialer_ip(), "::1");
}

#[test]
fn network_mode_accepts_supported_values_and_defaults_to_mix() {
    let cases = [
        ("", NetworkMode::Mix),
        ("?net=mix", NetworkMode::Mix),
        ("?net=tcp", NetworkMode::Tcp),
        ("?net=udp", NetworkMode::Udp),
    ];

    for (query, expected) in cases {
        let portal = Portal::new(
            Url::parse(&format!("portal://secret@127.0.0.1:2077{query}")).unwrap(),
            test_logger(),
        )
        .unwrap();
        assert_eq!(portal.inner.network_mode, expected);
    }
}

#[test]
fn network_mode_checkpoint_values_match_listener_modes() {
    assert_eq!(NetworkMode::Mix.checkpoint_value(), 0);
    assert_eq!(NetworkMode::Tcp.checkpoint_value(), 1);
    assert_eq!(NetworkMode::Udp.checkpoint_value(), 2);
}

#[test]
fn network_mode_rejects_unknown_values() {
    let error = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?net=auto").unwrap(),
        test_logger(),
    );

    assert!(error.is_err());
}

#[test]
fn socks_configuration_is_validated_and_redacted_in_effective_url() {
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&socks=user:p%40ss@proxy.test:1080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();
    let effective = portal.effective_url();
    assert!(effective.contains("socks=proxy.test:1080"));
    assert!(!effective.contains("user"));
    assert!(!effective.contains("p@ss"));

    let duplicate = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?socks=proxy.test:1080&socks=other.test:1080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert!(duplicate.effective_url().contains("socks=proxy.test:1080"));
}

#[test]
fn all_network_modes_reject_tls_zero() {
    for mode in ["mix", "tcp", "udp"] {
        let portal = Portal::new(
            Url::parse(&format!("portal://secret@127.0.0.1:2077?tls=0&net={mode}")).unwrap(),
            test_logger(),
        );
        assert!(portal.is_err());
    }
}

#[tokio::test]
async fn network_mode_binds_only_selected_transports() {
    for (query, expected_tcp, expected_udp) in [
        ("", 1, 1),
        ("?net=mix", 1, 1),
        ("?net=tcp", 1, 0),
        ("?net=udp", 0, 1),
    ] {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let portal = Portal::new(
            Url::parse(&format!("portal://secret@127.0.0.1:{port}{query}")).unwrap(),
            test_logger(),
        )
        .unwrap();

        let endpoints = portal.listen_endpoints().unwrap();
        let listeners = portal.listen_tcp_listeners().unwrap();
        assert_eq!(listeners.len(), expected_tcp);
        assert_eq!(endpoints.len(), expected_udp);
    }
}

#[test]
fn portal_url_contract_rejects_invalid_structure_and_selected_values() {
    for raw in [
        "vector://secret@127.0.0.1:2077",
        "portal://secret:password@127.0.0.1:2077",
        "portal://secret@127.0.0.1:2077/path",
        "portal://secret@127.0.0.1:2077#fragment",
        "portal://secret@127.0.0.1:2077?net=",
        "portal://secret@127.0.0.1:2077?socks=",
        "portal://secret@127.0.0.1:2077?rate=-1",
        "portal://secret@127.0.0.1:2077?dial=not-an-ip",
        "portal://secret@127.0.0.1:0",
        "portal://secret@127.0.0.1",
    ] {
        assert!(
            Portal::new(Url::parse(raw).unwrap(), test_logger()).is_err(),
            "URL unexpectedly accepted: {raw}"
        );
    }
}

#[test]
fn portal_ignores_unknown_parameters_and_keeps_first_duplicate() {
    let portal = Portal::new(
        Url::parse(
            "portal://secret@127.0.0.1:2077?unknown=value&spec=ignored&net=tcp&net=udp&rate=1&rate=2",
        )
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(portal.inner.network_mode, NetworkMode::Tcp);
    assert_eq!(portal.inner.rate_limit, 1);
    assert!(portal.effective_url().contains("?net=tcp&tls=1&"));
}

#[test]
fn alpn_remains_configurable_with_now_one_as_default() {
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?alpn=private/1").unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(portal.inner.alpn, "private/1");
    assert!(portal.effective_url().contains("alpn=private/1"));
}

#[test]
fn certificate_parameters_are_tied_to_ca_trusted_mode() {
    for raw in [
        "portal://secret@127.0.0.1:2077?crt=cert.pem",
        "portal://secret@127.0.0.1:2077?key=key.pem",
        "portal://secret@127.0.0.1:2077?crt=cert.pem&key=key.pem",
        "portal://secret@127.0.0.1:2077?tls=2&crt=cert.pem",
        "portal://secret@127.0.0.1:2077?tls=2&key=key.pem",
    ] {
        assert!(Portal::new(Url::parse(raw).unwrap(), test_logger()).is_err());
    }
}
