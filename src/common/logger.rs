// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Minimal terminal logger used by the portal runtime and tests.

use std::fmt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI32, Ordering},
};

use chrono::Local;

/// Log severity threshold used by the lightweight terminal logger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum LogLevel {
    /// Disable all output.
    None = 0,
    /// Verbose diagnostic output.
    Debug = 1,
    /// Normal operational output.
    Info = 2,
    /// Warnings that do not stop the portal.
    Warn = 3,
    /// Errors that usually close a connection or listener path.
    Error = 4,
    /// Machine-readable periodic telemetry.
    Event = 5,
}

const LEVEL_STRINGS: [&str; 6] = ["NONE", "DEBUG", "INFO", "WARN", "ERROR", "EVENT"];
const LEVEL_COLORS: [&str; 6] = [
    "", "\x1b[34m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[36m",
];
const RESET_COLOR: &str = "\x1b[0m";

/// Cloneable logger with shared threshold state and serialized stdout writes.
#[derive(Clone, Debug)]
pub struct Logger {
    level: Arc<AtomicI32>,
    color_enabled: bool,
    output_lock: Arc<Mutex<()>>,
}

impl Logger {
    /// Creates a logger with the initial severity threshold and color mode.
    pub fn new(log_level: LogLevel, enable_color: bool) -> Self {
        Self {
            level: Arc::new(AtomicI32::new(log_level as i32)),
            color_enabled: enable_color,
            output_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Updates the shared severity threshold for all logger clones.
    pub fn set_log_level(&self, log_level: LogLevel) {
        self.level.store(log_level as i32, Ordering::Relaxed);
    }

    /// Returns whether debug messages are enabled at the current threshold.
    pub fn debug_enabled(&self) -> bool {
        self.enabled(LogLevel::Debug)
    }

    /// Emits a debug message when the current threshold allows it.
    pub fn debug(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Debug, args);
    }

    /// Emits an info message when the current threshold allows it.
    pub fn info(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Info, args);
    }

    /// Emits a warning message when the current threshold allows it.
    pub fn warn(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Warn, args);
    }

    /// Emits an error message when the current threshold allows it.
    pub fn error(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Error, args);
    }

    /// Emits an event telemetry message when the current threshold allows it.
    pub fn event(&self, args: fmt::Arguments<'_>) {
        self.do_log(LogLevel::Event, args);
    }

    /// Keeps the CLI-facing logger API explicit even though stdout is unbuffered here.
    pub fn flush(&self) {}

    fn do_log(&self, log_level: LogLevel, args: fmt::Arguments<'_>) {
        if !self.enabled(log_level) {
            return;
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let level = LEVEL_STRINGS[log_level as usize];
        let line = if self.color_enabled {
            format!(
                "{timestamp}  {}{}{}  {args}\n",
                LEVEL_COLORS[log_level as usize], level, RESET_COLOR
            )
        } else {
            format!("{timestamp}  {level}  {args}\n")
        };

        if let Ok(_guard) = self.output_lock.lock() {
            print!("{line}");
        }
    }

    fn enabled(&self, log_level: LogLevel) -> bool {
        let current = self.level.load(Ordering::Relaxed);
        current != LogLevel::None as i32 && (log_level as i32) >= current
    }
}

#[cfg(test)]
#[path = "../tests/common/logger.rs"]
mod tests;
