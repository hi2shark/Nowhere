// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector construction and formatting tests.

use super::*;

#[test]
fn vector_constructs_for_each_carrier_pair() {
    for (up, down) in [
        ("tcp", "tcp"),
        ("tcp", "udp"),
        ("udp", "tcp"),
        ("udp", "udp"),
    ] {
        let pool = if up == "tcp" && down == "tcp" { 5 } else { 0 };
        let url = Url::parse(&format!(
            "vector://secret@127.0.0.1:2077?up={up}&down={down}&pool={pool}&socks=127.0.0.1:1080"
        ))
        .unwrap();
        Vector::new(url, Logger::new(crate::common::LogLevel::None, false)).unwrap();
    }
}

#[test]
fn effective_url_prints_none_for_absent_sni() {
    let config = VectorConfig::from_url(
        &Url::parse("vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080").unwrap(),
    )
    .unwrap();
    assert!(config.effective_url().contains("&sni=none&"));
}
