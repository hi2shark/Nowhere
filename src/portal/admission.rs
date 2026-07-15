// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pre-authentication admission limits for incoming connections.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

/// Global number of connections allowed to wait for authentication.
pub(super) const MAX_UNAUTHENTICATED_CONNECTIONS: usize = 256;
/// Per-source number of connections allowed to wait for authentication.
pub(super) const MAX_UNAUTHENTICATED_PER_SOURCE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SourceKey {
    V4(Ipv4Addr),
    V6(u64),
}

impl From<IpAddr> for SourceKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip),
            // Group IPv6 sources by /64 so one host cannot bypass the per-source
            // limit by rotating interface identifiers.
            IpAddr::V6(ip) => Self::V6((u128::from(ip) >> 64) as u64),
        }
    }
}

#[derive(Default)]
struct AdmissionState {
    total: usize,
    per_source: HashMap<SourceKey, usize>,
}

/// Shared admission counter for unauthenticated connections.
pub(super) struct UnauthenticatedAdmission {
    state: Mutex<AdmissionState>,
}

impl UnauthenticatedAdmission {
    /// Creates an empty admission state.
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState::default()),
        }
    }

    /// Tries to reserve an unauthenticated slot for `source`.
    pub(super) fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<UnauthenticatedGuard> {
        let key = SourceKey::from(source);
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let source_count = state.per_source.get(&key).copied().unwrap_or_default();
        if state.total >= MAX_UNAUTHENTICATED_CONNECTIONS
            || source_count >= MAX_UNAUTHENTICATED_PER_SOURCE
        {
            return None;
        }
        state.total += 1;
        state.per_source.insert(key, source_count + 1);
        Some(UnauthenticatedGuard {
            admission: self.clone(),
            key,
        })
    }
}

/// RAII guard that releases an unauthenticated admission slot on drop.
pub(super) struct UnauthenticatedGuard {
    admission: Arc<UnauthenticatedAdmission>,
    key: SourceKey,
}

impl Drop for UnauthenticatedGuard {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.total -= 1;
        if let Some(count) = state.per_source.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                state.per_source.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/portal/admission.rs"]
mod tests;
