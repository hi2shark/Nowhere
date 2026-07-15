// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pre-authentication admission tests.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::portal::admission::{
    MAX_UNAUTHENTICATED_CONNECTIONS, MAX_UNAUTHENTICATED_PER_SOURCE, UnauthenticatedAdmission,
};

use super::super::*;

#[test]
fn authentication_failure_close_uses_access_denied() {
    let (code, reason) = authentication_failure_close();

    assert_eq!(code.into_inner(), 1);
    assert_eq!(reason, b"access denied");
}

#[test]
fn unauthenticated_admission_enforces_per_source_and_releases_with_raii() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut guards = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|_| admission.try_acquire(source).unwrap())
        .collect::<Vec<_>>();

    assert!(admission.try_acquire(source).is_none());
    drop(guards.pop());
    assert!(admission.try_acquire(source).is_some());
}

#[test]
fn unauthenticated_admission_groups_ipv6_by_slash_64() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let guards = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|suffix| {
            admission
                .try_acquire(format!("2001:db8:1:2::{suffix:x}").parse().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(
        admission
            .try_acquire("2001:db8:1:2:ffff::1".parse().unwrap())
            .is_none()
    );
    assert!(
        admission
            .try_acquire("2001:db8:1:3::1".parse().unwrap())
            .is_some()
    );
    drop(guards);
}

#[test]
fn unauthenticated_admission_enforces_shared_global_limit() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let guards = (0..MAX_UNAUTHENTICATED_CONNECTIONS)
        .map(|index| {
            admission
                .try_acquire(IpAddr::V4(Ipv4Addr::from(index as u32)))
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(
        admission
            .try_acquire(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .is_none()
    );
    drop(guards);
    assert!(
        admission
            .try_acquire(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .is_some()
    );
}
