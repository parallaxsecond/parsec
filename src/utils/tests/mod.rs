// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Static config tests to see if the service starts with different configurations.

use crate::utils::config::ServiceConfig;
use crate::utils::ServiceBuilder;
use anyhow::anyhow;
use log::error;
use std::env;
use std::io::Error;
use std::io::ErrorKind;

const CONFIG_TOMLS_FOLDER: &str = "src/utils/tests/config";

fn config_to_toml(file_name: String) -> ServiceConfig {
    let mut new_config_path = env::current_dir() // this is the root of the crate for tests
        .unwrap();
    new_config_path.push(CONFIG_TOMLS_FOLDER);
    new_config_path.push(file_name.clone());
    if !new_config_path.exists() {
        error!("Configuration file {} does not exist", file_name);
        panic!();
    }

    let config_file = std::fs::read_to_string(new_config_path.clone())
        .map_err(|e| {
            error!(
                "Failed to read config file from path: {:#?}\nError: {:#?}",
                new_config_path, e
            );
            panic!();
        })
        .unwrap();
    toml::from_str(&config_file)
        .map_err(|e| {
            error!("Failed to parse service configuration ({})", e);
            panic!();
        })
        .unwrap()
}

/// Check that the service throws an error when two providers of the same type are started,
/// without setting a name (therefore they have the same default name).
#[test]
fn providers_same_type_default_name() {
    let config_path: String = "providers_same_type_default_name.toml".to_string();
    let config = config_to_toml(config_path);

    let expected_error = anyhow!(Error::new(
        ErrorKind::InvalidData,
        "duplicate provider names found"
    ));

    let err = ServiceBuilder::build_service(&config).unwrap_err();
    assert_eq!(format!("{:#?}", err), format!("{:#?}", expected_error));
}

/// Check that the service starts when two providers of the same type have different names.
#[test]
fn providers_same_type_different_name() {
    let config_path: String = "providers_same_type_different_name.toml".to_string();
    let config = config_to_toml(config_path);

    let _ = ServiceBuilder::build_service(&config).unwrap();
}

/// Check that the service throws an error when two providers of the same type explicitly
/// set the same name.
#[test]
fn providers_same_type_same_name() {
    let config_path: String = "providers_same_type_same_name.toml".to_string();
    let config = config_to_toml(config_path);

    let expected_error = anyhow!(Error::new(
        ErrorKind::InvalidData,
        "duplicate provider names found"
    ));

    let err = ServiceBuilder::build_service(&config).unwrap_err();
    assert_eq!(format!("{:#?}", err), format!("{:#?}", expected_error));
}

/// Check that the service throws an error when two providers of different types explicitly
/// set the same name.
#[test]
fn providers_different_type_same_name() {
    let config_path: String = "providers_different_type_same_name.toml".to_string();
    let config = config_to_toml(config_path);

    let expected_error = anyhow!(Error::new(
        ErrorKind::InvalidData,
        "duplicate provider names found"
    ));

    let err = ServiceBuilder::build_service(&config).unwrap_err();
    assert_eq!(format!("{:#?}", err), format!("{:#?}", expected_error));
}

/// Check that the service starts when two providers of different types are declared.
/// (Different default provider names)
#[test]
fn providers_different_type() {
    let config_path: String = "providers_different_type.toml".to_string();
    let config = config_to_toml(config_path);

    let _ = ServiceBuilder::build_service(&config).unwrap();
}
