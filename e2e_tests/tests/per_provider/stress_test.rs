// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::stress::{StressClient, StressTestConfig};
use std::time::Duration;

#[test]
fn stress_test() {
    let config = StressTestConfig {
        no_threads: num_cpus::get(),
        req_per_thread: 250,
        req_interval: Some(Duration::from_millis(10)),
        req_interval_deviation_millis: Some(4),
        check_interval: Some(Duration::from_millis(500)),
    };

    StressClient::execute(config);
}
