// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::utils::service_builder::DEFAULT_BUFFER_SIZE_LIMIT;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Configuration values that affect most or all the
/// components of the service.
#[derive(Default, Debug)]
pub struct GlobalConfig {
    log_error_details: AtomicBool,
    buffer_size_limit: AtomicUsize,
}

impl GlobalConfig {
    const fn new() -> Self {
        GlobalConfig {
            log_error_details: AtomicBool::new(false),
            buffer_size_limit: AtomicUsize::new(DEFAULT_BUFFER_SIZE_LIMIT), // 1 MB
        }
    }

    /// Determine whether error logs should include detailed
    /// information about the error
    pub fn log_error_details() -> bool {
        GLOBAL_CONFIG.log_error_details.load(Ordering::Relaxed)
    }

    /// Fetch the size limit for buffers within responses (in bytes).
    /// information about the error
    pub fn buffer_size_limit() -> usize {
        GLOBAL_CONFIG.buffer_size_limit.load(Ordering::Relaxed)
    }
}

static GLOBAL_CONFIG: GlobalConfig = GlobalConfig::new();

pub(super) struct GlobalConfigBuilder {
    log_error_details: bool,
    buffer_size_limit: Option<usize>,
}

impl GlobalConfigBuilder {
    pub fn new() -> Self {
        GlobalConfigBuilder {
            log_error_details: false,
            buffer_size_limit: None,
        }
    }

    pub fn with_log_error_details(mut self, log_error_details: bool) -> Self {
        self.log_error_details = log_error_details;

        self
    }

    pub fn with_buffer_size_limit(mut self, buffer_size_limit: usize) -> Self {
        self.buffer_size_limit = Some(buffer_size_limit);

        self
    }

    pub fn build(self) {
        GLOBAL_CONFIG
            .log_error_details
            .store(self.log_error_details, Ordering::Relaxed);
        GLOBAL_CONFIG.buffer_size_limit.store(
            self.buffer_size_limit.unwrap_or(DEFAULT_BUFFER_SIZE_LIMIT),
            Ordering::Relaxed,
        );
    }
}
