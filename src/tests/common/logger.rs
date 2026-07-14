// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Logger threshold tests.

use super::*;

#[test]
fn debug_enabled_tracks_shared_threshold() {
    let logger = Logger::new(LogLevel::Info, false);
    let clone = logger.clone();
    assert!(!logger.debug_enabled());

    clone.set_log_level(LogLevel::Debug);
    assert!(logger.debug_enabled());

    logger.set_log_level(LogLevel::None);
    assert!(!clone.debug_enabled());
}
