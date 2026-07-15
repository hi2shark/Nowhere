// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal names for the shared budgeted UDP queue primitives.

pub(in crate::portal) use crate::common::BudgetedDatagram as QueuedDatagram;
pub(super) use crate::common::reserve_udp_budget as reserve_packet_budget;

#[cfg(test)]
#[path = "../../tests/portal/conn/session_flow.rs"]
mod tests;
