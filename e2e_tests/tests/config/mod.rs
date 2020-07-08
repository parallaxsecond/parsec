// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use log::{error, info};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

const CONFIG_TOMLS_FOLDER: &str = "tests/config/tomls";
const SERVICE_CONFIG_PATH: &str = "provider_cfg/tmp_config.toml";

fn set_config(filename: &str) {
    info!("Changing service configuration file to {}", filename);
    let config_path = PathBuf::from(SERVICE_CONFIG_PATH);
    let mut new_config = env::current_dir() // this is the root of the crate for tests
        .unwrap();
    new_config.push(CONFIG_TOMLS_FOLDER);
    new_config.push(filename);
    if !new_config.exists() {
        error!("Configuration file {} does not exist", filename);
        panic!();
    }

    let _ = fs::copy(new_config, config_path).unwrap();
}

fn reload_service() {
    info!("Reloading Parsec service");

    let _ = Command::new("pkill")
        .arg("-SIGHUP")
        .arg("parsec")
        .output()
        .expect("Reloading service failed");

    // wait for the service to restart
    thread::sleep(Duration::from_secs(2));
}

#[test]
fn list_providers() {
    set_config("list_providers_1.toml");
    reload_service();

    let mut client = TestClient::new();
    let providers = client.list_providers().unwrap();
    let uuids: Vec<Uuid> = providers.iter().map(|p| p.uuid).collect();
    assert_eq!(
        uuids,
        vec![
            Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(), // Mbed crypto provider
            Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap(), // Tpm provider
            Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(), // Pkcs11 provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );

    set_config("list_providers_2.toml");
    reload_service();

    let providers = client.list_providers().unwrap();
    let uuids: Vec<Uuid> = providers.iter().map(|p| p.uuid).collect();
    assert_eq!(
        uuids,
        vec![
            Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(), // Pkcs11 provider
            Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(), // Mbed crypto provider
            Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap(), // Tpm provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );
}
