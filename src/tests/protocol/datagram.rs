// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP datagram codec tests.

use super::*;
use url::Url;

fn protocol_spec(spec: &str) -> EffectiveProtocolSpec {
    let url = Url::parse(&format!("portal://secret@127.0.0.1:443?spec={spec}")).unwrap();
    EffectiveProtocolSpec::new(&url, b"secret").unwrap()
}

#[test]
fn udp_datagram_wire_format_uses_derived_order() {
    let spec = protocol_spec("edge-a");
    let frame = encode_udp_datagram(
        DATAGRAM_UDP_REQUEST,
        0x0102030405060708,
        "x.test:53",
        b"abc",
        &spec,
    )
    .unwrap();
    assert_eq!(
        frame.len(),
        DATAGRAM_HEADER_FIXED_LEN + "x.test:53".len() + 3
    );

    let (ty, flow, target, payload) = decode_udp_datagram(&frame, &spec).unwrap();
    assert_eq!(ty, DATAGRAM_UDP_REQUEST);
    assert_eq!(flow, 0x0102030405060708);
    assert_eq!(target, "x.test:53");
    assert_eq!(payload, b"abc");

    let decoded = decode_udp_datagram_parts(&frame, &spec).unwrap();
    assert_eq!(decoded.frame_type, ty);
    assert_eq!(decoded.flow_id, flow);
    assert_eq!(decoded.target_addr, target);
    assert_eq!(&frame[decoded.payload_offset..], payload);
}

#[test]
fn rejects_malformed_udp_datagrams() {
    let spec = protocol_spec("edge-a");
    assert!(decode_udp_datagram(&[], &spec).is_err());

    let mut invalid_type = new_udp_datagram_header(DATAGRAM_UDP_REQUEST, 1, "x.test:53", &spec)
        .expect("valid test header");
    let type_offset = field_offset(&invalid_type, &spec, UdpFrameElement::Type);
    invalid_type[type_offset] = 9;
    assert!(decode_udp_datagram(&invalid_type, &spec).is_err());

    let mut invalid_version = new_udp_datagram_header(DATAGRAM_UDP_REQUEST, 1, "x.test:53", &spec)
        .expect("valid test header");
    let version_offset = field_offset(&invalid_version, &spec, UdpFrameElement::Version);
    invalid_version[version_offset] = PROXY_FRAME_VERSION + 1;
    assert!(decode_udp_datagram(&invalid_version, &spec).is_err());

    let mut zero_target_len = new_udp_datagram_header(DATAGRAM_UDP_REQUEST, 1, "x.test:53", &spec)
        .expect("valid test header");
    let target_offset = field_offset(&zero_target_len, &spec, UdpFrameElement::Target);
    zero_target_len[target_offset..target_offset + 2].copy_from_slice(&0u16.to_be_bytes());
    assert!(decode_udp_datagram(&zero_target_len, &spec).is_err());
}

#[test]
fn append_frame_payload_replaces_previous_contents() {
    let mut dst = vec![9, 9, 9];

    append_frame_payload(&mut dst, &[1, 2], &[3, 4]);

    assert_eq!(dst, [1, 2, 3, 4]);
}

fn field_offset(frame: &[u8], spec: &EffectiveProtocolSpec, target: UdpFrameElement) -> usize {
    let mut offset = 0;
    for element in spec.frame_layout.udp {
        if element == target {
            return offset;
        }
        offset += match element {
            UdpFrameElement::Version | UdpFrameElement::Type => 1,
            UdpFrameElement::FlowId => 8,
            UdpFrameElement::Target => {
                let len = u16::from_be_bytes(
                    frame[offset..offset + 2]
                        .try_into()
                        .expect("target length slice"),
                ) as usize;
                2 + len
            }
        };
    }
    unreachable!("field must exist in UDP frame layout")
}
