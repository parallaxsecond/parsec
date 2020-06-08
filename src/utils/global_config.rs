// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Configuration values that affect most or all the
/// components of the service.
#[derive(Default, Debug)]
pub struct GlobalConfig {
    log_error_details: AtomicBool,
}

impl GlobalConfig {
    const fn new() -> Self {
        GlobalConfig {
            log_error_details: AtomicBool::new(false),
        }
    }

    /// Determine whether error logs should include detailed
    /// information about the error
    pub fn log_error_details() -> bool {
        GLOBAL_CONFIG.log_error_details.load(Ordering::Relaxed)
    }
}

static GLOBAL_CONFIG: GlobalConfig = GlobalConfig::new();

pub(super) struct GlobalConfigBuilder {
    log_error_details: bool,
}

impl GlobalConfigBuilder {
    pub fn new() -> Self {
        GlobalConfigBuilder {
            log_error_details: false,
        }
    }

    pub fn with_log_error_details(mut self, log_error_details: bool) -> Self {
        self.log_error_details = log_error_details;

        self
    }

    pub fn build(self) {
        GLOBAL_CONFIG
            .log_error_details
            .store(self.log_error_details, Ordering::Relaxed);
    }
}
