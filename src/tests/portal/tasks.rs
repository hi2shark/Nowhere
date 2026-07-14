// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Flow task tracker lifecycle tests.

use std::sync::Arc;
use std::time::Duration;

use super::FlowTaskTracker;

#[tokio::test]
async fn close_waits_for_existing_tasks_and_rejects_new_tasks() {
    let tracker = Arc::new(FlowTaskTracker::default());
    let (release, released) = tokio::sync::oneshot::channel();
    assert!(tracker.spawn(async move {
        let _ = released.await;
    }));
    tracker.close();
    assert!(!tracker.spawn(async {}));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), tracker.wait())
            .await
            .is_err()
    );
    let _ = release.send(());
    tokio::time::timeout(Duration::from_secs(1), tracker.wait())
        .await
        .unwrap();
}

#[tokio::test]
async fn abort_all_drains_task_guards() {
    let tracker = Arc::new(FlowTaskTracker::default());
    assert!(tracker.spawn(std::future::pending()));
    tracker.close();
    tracker.abort_all();
    tokio::time::timeout(Duration::from_secs(1), tracker.wait())
        .await
        .unwrap();
}
