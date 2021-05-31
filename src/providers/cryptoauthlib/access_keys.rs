// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use log::{error, warn};
use serde::Deserialize;
use std::fs::read_to_string;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct AccessKeyContainer {
    access_keys: Vec<AccessKey>,
}

#[derive(Debug, Deserialize)]
struct AccessKey {
    slot: u8,
    key: [u8; 32],
}

impl Provider {
    /// Read access keys from a configuration file and setup the CALib to use them.
    pub fn set_access_keys(
        &self,
        access_keys_file_name: Option<String>,
    ) -> Option<rust_cryptoauthlib::AtcaStatus> {
        let access_keys_string = match access_keys_file_name.clone() {
            None => {
                warn!("Missing 'access_key_file_name' entry in configuration toml file");
                return None;
            }
            Some(file_name) => match read_to_string(Path::new(&file_name)) {
                Err(err) => {
                    warn!("Cannot read from {} file because: {}.", file_name, err);
                    return None;
                }
                Ok(config_string) => config_string,
            },
        };
        let access_keys_container: AccessKeyContainer = match toml::from_str(&access_keys_string) {
            Ok(keys) => keys,
            Err(err) => {
                error!(
                    "Error parsing access key config file {}. {}",
                    access_keys_file_name.unwrap(),
                    err
                );
                return None;
            }
        };
        for access_key in access_keys_container.access_keys.iter() {
            if rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT > access_key.slot {
                let err = self.device.add_access_key(access_key.slot, &access_key.key);
                match err {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => (),
                    _ => error!(
                        "add_access_key() for slot {} failed, because {}",
                        access_key.slot, err
                    ),
                }
            } else {
                error!(
                    "add_access_key() for slot {} failed, because it exceeded total slots count {}",
                    access_key.slot,
                    rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT
                )
            }
        }

        Some(rust_cryptoauthlib::AtcaStatus::AtcaSuccess)
    }
}
