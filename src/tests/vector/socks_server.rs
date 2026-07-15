use super::*;

#[test]
fn source_request_rejects_other_ips_and_domains() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        validate_udp_source_request(&SocksAddress::Ip("127.0.0.2:1234".parse().unwrap()), peer,)
            .is_err()
    );
    assert!(
        validate_udp_source_request(&SocksAddress::Domain("localhost".into(), 1234), peer).is_err()
    );
}

#[test]
fn source_endpoint_locks_first_port() {
    let endpoint = StdMutex::new(None);
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(!accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1001".parse().unwrap()
    ));
}
