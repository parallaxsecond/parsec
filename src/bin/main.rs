// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use log::info;
use parsec::utils::{ServiceBuilder, ServiceConfig};
use signal_hook::{flag, SIGHUP, SIGTERM};
use std::io::{Error, ErrorKind};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use structopt::StructOpt;

/// Parsec is the Platform AbstRaction for SECurity, a new open-source initiative to provide a
/// common API to secure services in a platform-agnostic way.
///
/// Parsec documentation is available at:
/// https://parallaxsecond.github.io/parsec-book/index.html
///
/// Most of Parsec configuration comes from its configuration file.
/// Please check the documentation to find more about configuration:
/// https://parallaxsecond.github.io/parsec-book/user_guides/configuration.html
#[derive(StructOpt)]
struct Opts {
    /// Sets the configuration file path
    #[structopt(short, long, default_value = "config.toml")]
    config: String,
}

const MAIN_LOOP_DEFAULT_SLEEP: u64 = 10;

fn main() -> Result<(), Error> {
    // Parsing the command line arguments.
    let opts: Opts = Opts::from_args();

    // Register a boolean set to true when the SIGTERM signal is received.
    let kill_signal = Arc::new(AtomicBool::new(false));
    // Register a boolean set to true when the SIGHUP signal is received.
    let reload_signal = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, kill_signal.clone())?;
    flag::register(SIGHUP, reload_signal.clone())?;

    let mut config_file =
        ::std::fs::read_to_string(opts.config.clone()).expect("Failed to read configuration file");
    let mut config: ServiceConfig =
        toml::from_str(&config_file).expect("Failed to parse service configuration");

    log_setup(&config);

    info!("Parsec started. Configuring the service...");

    let front_end_handler = ServiceBuilder::build_service(&config)
        .ok_or_else(|| Error::new(ErrorKind::Other, "Parsec can not be configured."))?;
    // Multiple threads can not just have a reference of the front end handler because they could
    // outlive the run function. It is needed to give them all ownership of the front end handler
    // through an Arc.
    let mut front_end_handler = Arc::from(front_end_handler);
    let mut listener = ServiceBuilder::start_listener(&config.listener);
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

            config_file = ::std::fs::read_to_string(opts.config.clone())
                .expect("Failed to read configuration file");
            config = toml::from_str(&config_file).expect("Failed to parse service configuration");
            front_end_handler =
                Arc::from(ServiceBuilder::build_service(&config).ok_or_else(|| {
                    Error::new(ErrorKind::Other, "Parsec can not be configured.")
                })?);
            listener = ServiceBuilder::start_listener(&config.listener);
            threadpool = ServiceBuilder::build_threadpool(config.core_settings.thread_pool_size);

            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
            info!("Parsec configuration reloaded.");
        }

        if let Some(stream) = listener.accept() {
            let front_end_handler = front_end_handler.clone();
            threadpool.execute(move || {
                front_end_handler.handle_request(stream);
            });
        } else {
            ::std::thread::sleep(Duration::from_millis(
                config
                    .core_settings
                    .idle_listener_sleep_duration
                    .unwrap_or(MAIN_LOOP_DEFAULT_SLEEP),
            ));
        }
    }

    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Stopping]);
    info!("SIGTERM signal received. Shutting down Parsec, waiting for all threads to finish...");
    threadpool.join();
    info!("Parsec is now terminated.");

    Ok(())
}

fn log_setup(config: &ServiceConfig) {
    let mut env_log_builder = env_logger::builder();

    if let Some(level) = config.core_settings.log_level {
        env_log_builder.filter_level(level);
    }
    if let Some(true) = config.core_settings.log_timestamp {
        env_log_builder.format_timestamp_millis();
    } else {
        env_log_builder.format_timestamp(None);
    }
    env_log_builder.init();
}
