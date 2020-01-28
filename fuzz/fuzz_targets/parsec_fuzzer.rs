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
#![no_main]

use parsec::utils::{ServiceBuilder, ServiceConfig};
use parsec::authenticators::ApplicationName;
use parsec::fuzz_utils::requests::Request;
use parsec::front::front_end::FrontEndHandler;
use std::path::PathBuf;
use libfuzzer_sys::fuzz_target;
use lazy_static::lazy_static;

lazy_static! {
    static ref FRONT_END_HANDLER: FrontEndHandler = {
        log_setup();
        let config_file = String::from("./run_config.toml");
        let mut config_file =
            ::std::fs::read_to_string(config_file).expect("Failed to read configuration file");
        let mut config: ServiceConfig =
            toml::from_str(&config_file).expect("Failed to parse service configuration");
        ServiceBuilder::build_service(&config).expect("Failed to initialize service")
    };
}

fuzz_target!(|params: (Request, ApplicationName)| {
    FRONT_END_HANDLER.bypass_to_dispatcher(params.0, params.1);
});


fn log_setup() {
    use flexi_logger::{LogSpecBuilder, Logger, LevelFilter, LogTarget};
    use flexi_logger::writers::FileLogWriter;

    let flw = FileLogWriter::builder()
        .suppress_timestamp()
        .directory("./")
        .try_build().expect("Failed to build FileLogWriter");

    let log_spec = LogSpecBuilder::new()
        .default(LevelFilter::Info)
        .build();

    Logger::with(log_spec)
        .log_target(LogTarget::Writer(Box::from(flw)))
        .start().unwrap();
}
