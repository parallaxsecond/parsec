// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use parsec::utils::{ServiceBuilder, ServiceConfig};
use parsec::front::front_end::FrontEndHandler;
use std::path::PathBuf;
use libfuzzer_sys::fuzz_target;
use lazy_static::lazy_static;
use std::io::{Read, Write, Result, Error, ErrorKind};
use std::cmp;
use arbitrary::Arbitrary;

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

#[derive(Arbitrary, Debug)]
struct MockStream(Vec<u8>);

impl Read for MockStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.0.is_empty() {
            return Ok(0);
        }
        let n = cmp::min(buf.len(), self.0.len());
        for (idx, val) in self.0.drain(0..n).enumerate() {
            buf[idx] = val;
        }

        Ok(n)
    }
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

fuzz_target!(|stream: MockStream| {
    FRONT_END_HANDLER.handle_request(stream);
});


fn log_setup() {
    use flexi_logger::{LogSpecBuilder, Logger, LevelFilter, LogTarget};
    use flexi_logger::writers::FileLogWriter;

    let flw = FileLogWriter::builder()
        .suppress_timestamp()
        .directory("./")
        .try_build().expect("Failed to build FileLogWriter");

    let log_spec = LogSpecBuilder::new()
        .default(LevelFilter::Warn)
        .build();

    Logger::with(log_spec)
        .log_target(LogTarget::Writer(Box::from(flw)))
        .start().unwrap();
}
