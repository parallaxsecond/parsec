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
use signal_hook::{flag, SIGTERM};
use std::io::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const CONFIG_FILE_PATH: &str = "./config.toml";
const MAIN_LOOP_DEFAULT_SLEEP: u64 = 10;

fn main() -> Result<(), Error> {
    if cfg!(feature = "systemd-daemon") {
        // Logs viewed with journalctl already contain timestamps.
        env_logger::builder().format_timestamp(None).init();
    } else {
        env_logger::init();
    }

    info!("PARSEC started.");

    let config_file =
        ::std::fs::read_to_string(CONFIG_FILE_PATH).expect("Failed to read configuration file");
    let config: ServiceConfig =
        toml::from_str(&config_file).expect("Failed to parse service configuration");

    let front_end_handler = ServiceBuilder::build_service(&config);

    let listener = ServiceBuilder::start_listener(&config.listener);

    // Multiple threads can not just have a reference of the front end handler because they could
    // outlive the run function. It is needed to give them all ownership of the front end handler
    // through an Arc.
    let front_end_handler = Arc::from(front_end_handler);

    // Register a boolean set to true when the SIGTERM signal is received.
    let kill_signal = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, kill_signal.clone())?;

    let threadpool = ServiceBuilder::build_threadpool(config.core_settings.thread_pool_size);

    info!("PARSEC is ready.");

    #[cfg(feature = "systemd-daemon")]
    // Notify systemd that the daemon is ready, the start command will block until this point.
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    loop {
        if kill_signal.load(Ordering::Relaxed) {
            info!("SIGTERM signal received.");
            break;
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

    info!("Shutting down PARSEC, waiting for all threads to finish.");
    threadpool.join();

    Ok(())
}
