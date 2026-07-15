use super::*;

fn parse(raw: &str) -> Result<VectorConfig> {
    VectorConfig::from_url(&Url::parse(raw)?)
}

#[test]
fn defaults_to_quic_both_directions() {
    let config = parse("vector://secret@example.com:2077?socks=:1080").unwrap();
    assert_eq!(config.up, CarrierMode::Udp);
    assert_eq!(config.down, CarrierMode::Udp);
    assert_eq!(config.pool, 0);
    assert_eq!(config.alpn, "now/1");
    assert_eq!(config.sni, None);
    assert_eq!(config.socks.host, "");
    assert_eq!(config.socks.port, 1080);
}

#[test]
fn tcp_pair_defaults_to_five_warm_connections() {
    let config =
        parse("vector://secret@example.com:2077?up=tcp&down=tcp&socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.pool, 5);
    assert_eq!(config.checkpoint_mode(), 0);
}

#[test]
fn parses_authenticated_socks_and_preserves_plus() {
    let config = parse(
        "vector://secret@example.com:2077?socks=user%2Bname:p%40ss%3Aword@%5B%3A%3A1%5D:1080",
    )
    .unwrap();
    let credentials = config.socks.credentials.unwrap();
    assert_eq!(credentials.as_pair(), ("user+name", "p@ss:word"));
    assert_eq!(config.socks.host, "::1");
}

#[test]
fn rejects_missing_or_empty_socks() {
    assert!(parse("vector://secret@example.com:2077").is_err());
    assert!(parse("vector://secret@example.com:2077?socks=").is_err());
}

#[test]
fn pool_clamps_for_tcp_pair_and_is_ignored_for_other_carriers() {
    let clamped =
        parse("vector://secret@example.com:2077?up=tcp&down=tcp&pool=999&socks=:1080").unwrap();
    assert_eq!(clamped.pool, 256);

    for raw in [
        "vector://secret@example.com:2077?up=tcp&down=udp&pool=99&socks=:1080",
        "vector://secret@example.com:2077?up=udp&down=tcp&pool=999&socks=:1080",
        "vector://secret@example.com:2077?pool=invalid&socks=:1080",
    ] {
        assert_eq!(parse(raw).unwrap().pool, 0);
    }
}

#[test]
fn ignores_unknown_values_and_keeps_the_first_duplicate() {
    let config = parse(
        "vector://secret@example.com:2077?wat=1&%FF=x&up=tcp&up=udp&down=tcp&pool=8&pool=2&socks=:1080&socks=:1081",
    )
    .unwrap();
    assert_eq!(config.up, CarrierMode::Tcp);
    assert_eq!(config.down, CarrierMode::Tcp);
    assert_eq!(config.pool, 8);
    assert_eq!(config.socks.port, 1080);
}

#[test]
fn rejects_invalid_selected_values_but_accepts_empty_or_none_sni() {
    assert!(parse("vector://secret@example.com:2077?socks=:1080&up=mix").is_err());
    assert!(parse("vector://secret@example.com:2077?socks=:1080&rate=-1").is_err());
    assert!(
        parse("vector://secret@example.com:2077?up=tcp&down=tcp&pool=invalid&socks=:1080").is_err()
    );
    for sni in ["", "none"] {
        let config = parse(&format!(
            "vector://secret@example.com:2077?sni={sni}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.sni, None);
        assert!(config.effective_url().contains("&sni=none&"));
    }
}

#[test]
fn effective_url_uses_canonical_order_and_always_prints_sni() {
    let config = parse(
        "vector://secret@example.com:2077?log=debug&alpn=private&pool=7&down=tcp&up=tcp&sni=relay.example&etar=2&rate=1&socks=:1080",
    )
    .unwrap();
    assert_eq!(
        config.effective_url(),
        "vector://example.com:2077?up=tcp&down=tcp&pool=7&sni=relay.example&alpn=private&rate=1&etar=2&socks=:1080"
    );
}

#[test]
fn rejects_invalid_authority_shape() {
    assert!(parse("vector://example.com:2077?socks=:1080").is_err());
    assert!(parse("vector://secret:password@example.com:2077?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2077/?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2077/path?socks=:1080").is_err());
}

#[test]
fn normalizes_ipv6_portal_authority() {
    let config = parse("vector://secret@[::1]:2077?socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.remote_host, "::1");
    assert_eq!(config.portal_endpoint(), "[::1]:2077");
}
