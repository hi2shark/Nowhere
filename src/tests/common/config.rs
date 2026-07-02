// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Configuration parsing tests.

use super::*;

#[test]
fn query_int_accepts_only_positive_values() {
    assert_eq!(query_int(Some("7"), 3), 7);
    assert_eq!(query_int(Some("0"), 3), 3);
    assert_eq!(query_int(Some("-1"), 3), 3);
    assert_eq!(query_int(Some("invalid"), 3), 3);
    assert_eq!(query_int(None, 3), 3);
}

#[test]
fn init_dialer_ip_accepts_only_ip_literals() {
    assert_eq!(init_dialer_ip(Some("127.0.0.1")), "127.0.0.1");
    assert_eq!(init_dialer_ip(Some("::1")), "::1");
    assert_eq!(init_dialer_ip(Some(DEFAULT_DIALER_IP)), DEFAULT_DIALER_IP);
    assert_eq!(init_dialer_ip(Some("example.com")), DEFAULT_DIALER_IP);
    assert_eq!(init_dialer_ip(None), DEFAULT_DIALER_IP);
}

#[test]
fn rate_limit_converts_mbps_to_bytes_per_second() {
    assert_eq!(rate_limit_bytes_per_second(-1), 0);
    assert_eq!(rate_limit_bytes_per_second(0), 0);
    assert_eq!(rate_limit_bytes_per_second(1), 125_000);
    assert_eq!(rate_limit_bytes_per_second(8), 1_000_000);
}

#[test]
fn positive_env_usize_rejects_zero_and_invalid_values() {
    let name = "NOWHERE_TEST_POSITIVE_USIZE";
    unsafe { std::env::remove_var(name) };
    assert_eq!(env_positive_usize(name, 7), (7, false));

    unsafe { std::env::set_var(name, "11") };
    assert_eq!(env_positive_usize(name, 7), (11, false));
    unsafe { std::env::set_var(name, "0") };
    assert_eq!(env_positive_usize(name, 7), (7, true));
    unsafe { std::env::set_var(name, "invalid") };
    assert_eq!(env_positive_usize(name, 7), (7, true));
    unsafe { std::env::remove_var(name) };
}
