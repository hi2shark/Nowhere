// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded-shutdown tracking for detached live-flow tasks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, oneshot};
use tokio::task::AbortHandle;

#[derive(Default)]
pub(super) struct FlowTaskTracker {
    state: Mutex<TrackerState>,
    next_id: AtomicU64,
    active: AtomicUsize,
    idle: Notify,
}

#[derive(Default)]
struct TrackerState {
    closed: bool,
    handles: HashMap<u64, AbortHandle>,
}

impl FlowTaskTracker {
    pub(super) fn spawn<F>(self: &Arc<Self>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.state.lock().expect("flow task tracker poisoned");
        if state.closed {
            return false;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::AcqRel);
        let task = tokio::spawn(future);
        let abort_handle = task.abort_handle();
        let (registered, registration) = oneshot::channel();
        let tracker = self.clone();
        tokio::spawn(async move {
            // Registration must win even if the worker finishes immediately;
            // otherwise completion could remove the handle before insertion.
            let _ = registration.await;
            let _ = task.await;
            tracker.done(id);
        });
        state.handles.insert(id, abort_handle);
        drop(state);
        let _ = registered.send(());
        true
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().expect("flow task tracker poisoned");
        state.closed = true;
        if self.active.load(Ordering::Acquire) == 0 {
            self.idle.notify_waiters();
        }
    }

    pub(super) fn abort_all(&self) {
        let state = self.state.lock().expect("flow task tracker poisoned");
        for handle in state.handles.values() {
            handle.abort();
        }
    }

    pub(super) async fn wait(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    fn done(&self, id: u64) {
        self.state
            .lock()
            .expect("flow task tracker poisoned")
            .handles
            .remove(&id);
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
#[path = "../tests/portal/tasks.rs"]
mod tests;
