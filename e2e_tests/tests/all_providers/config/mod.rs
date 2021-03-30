// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use log::{error, info};
use parsec_client::core::interface::operations::list_providers::Uuid;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

const CONFIG_TOMLS_FOLDER: &str = "tests/all_providers/config/tomls";
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
            // Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap(), // CryptoAuthLib provider
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
            // Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap(), // CryptoAuthLib provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_verify_software() {
    use sha2::{Digest, Sha256};
    set_config("pkcs11_software.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = String::from("pkcs11_verify_software");

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone()).unwrap();

    let signature = client
        .sign_with_rsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client
        .verify_with_rsa_sha256(key_name, hash, signature)
        .unwrap();
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_encrypt_software() {
    set_config("pkcs11_software.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = String::from("pkcs11_verify_software");
    let plaintext_msg = [
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0x37, 0x78,
    ];
    client
        .generate_rsa_encryption_keys_rsaoaep_sha1(key_name.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsaoaep_sha1(
            key_name.clone(),
            plaintext_msg.to_vec(),
            vec![],
        )
        .unwrap();
    let plaintext = client
        .asymmetric_decrypt_message_with_rsaoaep_sha1(key_name, ciphertext, vec![])
        .unwrap();
    assert_eq!(&plaintext_msg[..], &plaintext[..]);
}
