use super::*;

fn config(raw: &str) -> VectorConfig {
    VectorConfig::from_url(&url::Url::parse(raw).unwrap()).unwrap()
}

#[test]
fn missing_sni_uses_unverified_policy() {
    let tls = ClientTls::new(&config(
        "vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080",
    ))
    .unwrap();
    assert_eq!(
        config("vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080").sni,
        None
    );
    assert_eq!(tls.quic_server_name(), "127.0.0.1");
    tls.quic_client_config().unwrap();
}

#[test]
fn ipv6_authority_builds_an_ip_server_name() {
    let tls = ClientTls::new(&config("vector://secret@[::1]:2077?socks=127.0.0.1:1080")).unwrap();
    assert_eq!(tls.quic_server_name(), "::1");
}

#[test]
fn explicit_sni_enables_system_verification() {
    let config = config("vector://secret@127.0.0.1:2077?sni=example.com&socks=127.0.0.1:1080");
    let tls = ClientTls::new(&config).unwrap();
    assert_eq!(config.sni.as_deref(), Some("example.com"));
    assert_eq!(tls.quic_server_name(), "example.com");
}
