// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal connection submodule tests.

#[path = "conn/admission.rs"]
mod admission;
#[path = "conn/asymmetric.rs"]
mod asymmetric;
#[path = "conn/quic.rs"]
mod quic;
#[path = "conn/support.rs"]
mod support;
#[path = "conn/tcp.rs"]
mod tcp;
#[path = "conn/vector.rs"]
mod vector;
