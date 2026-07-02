// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Wire-protocol helpers for authentication, requests, datagrams, and UoT.

mod crypto;
mod datagram;
mod request;
mod spec;
mod uot;
mod util;

pub use crypto::{
    Credentials, Key, read_auth_frame, read_auth_stream, validate_auth_frame, write_auth_frame,
};
pub(crate) use datagram::decode_udp_datagram_parts;
pub use datagram::{
    DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE, append_frame_payload,
    decode_udp_datagram, encode_udp_datagram, new_udp_datagram_header,
};
pub use request::{read_request, write_request_frame};
pub use spec::EffectiveProtocolSpec;
pub use uot::{
    UOT_MAGIC_TARGET, is_uot_magic_target, read_uot_packet, read_uot_setup_target,
    write_uot_packet_frame, write_uot_setup_frame,
};
pub use util::validate_target;
