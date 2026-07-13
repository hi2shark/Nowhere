// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic frame-layout permutations derived from a spec seed.

/// Fields that make up an authentication frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFrameElement {
    Magic,
    Nonce,
    Padding,
    Tag,
}

/// Fields that make up a TCP request frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpFrameElement {
    Version,
    Target,
    Padding,
}

/// Spec-derived frame ordering for TCP requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyFrameLayout {
    /// TCP request field order.
    pub tcp: [TcpFrameElement; 3],
}

impl ProxyFrameLayout {
    pub(super) fn from_seed(seed: &[u8]) -> Self {
        let mut tcp = [
            TcpFrameElement::Version,
            TcpFrameElement::Target,
            TcpFrameElement::Padding,
        ];
        for i in (1..tcp.len()).rev() {
            let seed_byte = seed.get(tcp.len() - 1 - i).copied().unwrap_or_default();
            tcp.swap(i, seed_byte as usize % (i + 1));
        }

        Self { tcp }
    }
}

pub(super) fn auth_frame_order_from_seed(seed: &[u8]) -> [AuthFrameElement; 4] {
    let canonical = [
        AuthFrameElement::Magic,
        AuthFrameElement::Nonce,
        AuthFrameElement::Padding,
        AuthFrameElement::Tag,
    ];
    let mut order = canonical;
    for i in (1..order.len()).rev() {
        let seed_byte = seed.get(order.len() - 1 - i).copied().unwrap_or_default();
        order.swap(i, seed_byte as usize % (i + 1));
    }
    // Avoid the canonical order for auto-derived specs so the derived layout is
    // visibly different from the legacy fixed layout.
    if order == canonical {
        order.rotate_left(1);
    }
    order
}
