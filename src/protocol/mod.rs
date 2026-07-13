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
pub use datagram::{
    UDP_FRAME_CLOSE, UDP_FRAME_DATA, UDP_FRAME_MAGIC, UDP_PACKET_MAX, UdpFragment, UdpFrame,
    decode_udp_frame, encode_udp_close, encode_udp_data_fragments,
};
pub use flow::{
    Carrier, FLOW_FRAME_MAGIC, FLOW_RESULT_MAGIC, FlowErrorCode, FlowHeader, FlowKind, FlowResult,
    FlowRole, FlowStatus, SESSION_ID_LEN, SessionId, encode_flow_result, read_flow_header,
    read_flow_result, write_flow_header, write_flow_result,
};
pub use request::{read_request, write_request_frame};
pub use spec::EffectiveProtocolSpec;
pub use uot::{
    UDP_STREAM_CLOSE, UDP_STREAM_DATA, UDP_STREAM_READY, UDP_STREAM_REJECT, UdpStreamFrame,
    encode_udp_stream_frame, read_udp_stream_frame, write_udp_stream_frame,
};
pub use util::validate_target;
