// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Wire-protocol helpers for authentication, requests, datagrams, and UoT.

mod crypto;
mod datagram;
mod flow;
mod request;
mod spec;
mod uot;
mod util;

pub use crypto::{
    Credentials, Key, read_auth_frame, read_auth_stream, validate_auth_frame, write_auth_frame,
    write_session_auth_frame,
};
pub(crate) use datagram::decode_udp_datagram_parts;
pub use datagram::{
    CompactUdpFrame, DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_COMPACT_CLOSE, DATAGRAM_UDP_DATA,
    DATAGRAM_UDP_OPEN_ACK, DATAGRAM_UDP_OPEN_DATA, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE,
    append_frame_payload, decode_udp_compact, decode_udp_datagram, encode_udp_compact,
    encode_udp_datagram, encode_udp_open_data, frame_payload_bytes, new_udp_datagram_header,
};
pub use flow::{
    Carrier, FLOW_FRAME_MAGIC, FlowHeader, FlowKind, FlowRole, SESSION_ID_LEN, SessionId,
    read_flow_header, write_flow_header,
};
pub use request::{read_request, write_request_frame};
pub use spec::EffectiveProtocolSpec;
pub use uot::{
    UOT_MAGIC_TARGET, is_uot_magic_target, read_uot_packet, read_uot_setup_target,
    write_uot_packet, write_uot_packet_frame, write_uot_setup_frame,
};
pub use util::validate_target;
