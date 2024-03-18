// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Parsec is the Platform AbstRaction for SECurity, a new open-source initiative to provide a
//! common API to secure services in a platform-agnostic way.
//!
//! Parsec documentation is available
//! [here](https://parallaxsecond.github.io/parsec-book/index.html)
//!
//! Most of Parsec configuration comes from its configuration file.
//! Please check the documentation to find more about configuration
//! [here](https://parallaxsecond.github.io/parsec-book/user_guides/configuration.html)
#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

use anyhow::Result;
use clap::Parser;
use libc::{getuid, uid_t};
use log::{info, trace};
use parsec_service::utils::cli::Opts;
use parsec_service::utils::{config::ServiceConfig, ServiceBuilder};
use signal_hook::{consts::SIGHUP, consts::SIGINT, consts::SIGTERM, flag};
use std::io::{Error, ErrorKind};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const MAIN_LOOP_DEFAULT_SLEEP: u64 = 10;

fn main() -> Result<()> {
    // Parsing the command line arguments.
    let opts: Opts = Opts::parse();

    // Register a boolean set to true when the SIGTERM signal is received.
    let kill_signal = Arc::new(AtomicBool::new(false));
    // Register a boolean set to true when the SIGHUP signal is received.
    let reload_signal = Arc::new(AtomicBool::new(false));
    let _ = flag::register(SIGTERM, kill_signal.clone())?;
    let _ = flag::register(SIGINT, kill_signal.clone())?;
    let _ = flag::register(SIGHUP, reload_signal.clone())?;

    let mut config_file = std::fs::read_to_string(opts.config.clone()).map_err(|e| {
        Error::new(
            e.kind(),
            format!("Failed to read config file from path: {}", opts.config),
        )
    })?;
    let mut config: ServiceConfig = toml::from_str(&config_file).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("Failed to parse service configuration ({})", e),
        )
    })?;

    // Guard against running as root. This check can be overridden by changing `allow_root` inside
    // the config file.
    let allow_root = config.core_settings.allow_root.unwrap_or(false);
    let current_id: uid_t = unsafe { getuid() };
    if !allow_root && current_id == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            "Insecure configuration; the Parsec service should not be running as root! You can \
             modify `allow_root` in the config file to bypass this check (not recommended).",
        )
        .into());
    }

    log_setup(&config);

    info!("Parsec started. Configuring the service...");

    let front_end_handler = ServiceBuilder::build_service(&config)?;
    // Multiple threads can not just have a reference of the front end handler because they could
    // outlive the run function. It is needed to give them all ownership of the front end handler
    // through an Arc.
    let mut front_end_handler = Arc::from(front_end_handler);
    let mut listener = ServiceBuilder::start_listener(config.listener)?;
    let mut threadpool = ServiceBuilder::build_threadpool(config.core_settings.thread_pool_size);

    // Notify systemd that the daemon is ready, the start command will block until this point.
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    info!("Parsec is ready.");

    while !kill_signal.load(Ordering::Relaxed) {
        if reload_signal.swap(false, Ordering::Relaxed) {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Reloading]);
            info!("SIGHUP signal received. Reloading the configuration...");

            threadpool.join();

            // Explicitely call drop now because otherwise Rust will drop these variables only
            // after they have been overwritten, in which case some values/libraries might be
            // initialized twice.
            drop(front_end_handler);
            drop(listener);
            drop(threadpool);

            config_file = std::fs::read_to_string(opts.config.clone()).map_err(|e| {
                Error::new(
                    e.kind(),
                    format!("Failed to read config file from path: {}", opts.config),
                )
            })?;
            config = toml::from_str(&config_file).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse service configuration ({})", e),
                )
            })?;
            front_end_handler = Arc::from(ServiceBuilder::build_service(&config)?);
            listener = ServiceBuilder::start_listener(config.listener)?;
            threadpool = ServiceBuilder::build_threadpool(config.core_settings.thread_pool_size);

            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
            info!("Parsec configuration reloaded.");
        }

        if let Some(connection) = listener.accept() {
            let front_end_handler = front_end_handler.clone();
            threadpool.execute(move || {
                front_end_handler.handle_request(connection);
                trace!("handle_request egress");
            });
        } else {
            std::thread::sleep(Duration::from_millis(
                config
                    .core_settings
                    .idle_listener_sleep_duration
                    .unwrap_or(MAIN_LOOP_DEFAULT_SLEEP),
            ));
        }
    }

    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Stopping]);
    info!("SIGTERM or SIGINT signal received. Shutting down Parsec, waiting for all threads to finish...");
    threadpool.join();
    info!("Parsec is now terminated.");

    Ok(())
}

fn log_setup(config: &ServiceConfig) {
    let mut env_log_builder = env_logger::builder();

    if let Some(level) = config.core_settings.log_level {
        let _ = env_log_builder.filter_level(level);
    }
    if let Some(true) = config.core_settings.log_timestamp {
        let _ = env_log_builder.format_timestamp_millis();
    } else {
        let _ = env_log_builder.format_timestamp(None);
    }
    env_log_builder.init();
}
