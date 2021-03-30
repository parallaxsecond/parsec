// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Microchip CryptoAuthentication Library provider
//!
//! This provider implements Parsec operations using CryptoAuthentication
//! Library backed by the ATECCx08 cryptochip.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::{KeyInfoManagerClient, KeyTriple};
use crate::providers::cryptoauthlib::key_slot_storage::KeySlotStorage;
use derivative::Derivative;
use log::{error, trace, warn};
use parsec_interface::operations::list_keys::KeyInfo;
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{list_clients, list_keys};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use uuid::Uuid;

use parsec_interface::operations::{
    psa_destroy_key, psa_generate_key, psa_generate_random, psa_hash_compare, psa_hash_compute,
};

mod generate_random;
mod hash;
mod key_management;
mod key_operations;
mod key_slot;
mod key_slot_storage;

const SUPPORTED_OPCODES: [Opcode; 5] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaHashCompute,
    Opcode::PsaHashCompare,
    Opcode::PsaGenerateRandom,
];

/// CryptoAuthLib provider structure
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    device: rust_cryptoauthlib::AteccDevice,
    provider_id: ProviderID,
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
    key_slots: KeySlotStorage,
}

impl Provider {
    /// Creates and initialises an instance of CryptoAuthLibProvider
    fn new(
        key_info_store: KeyInfoManagerClient,
        atca_iface: rust_cryptoauthlib::AtcaIfaceCfg,
    ) -> Option<Provider> {
        // First get the device, initialise it and communication channel with it
        let device = rust_cryptoauthlib::AteccDevice::new(atca_iface).ok()?;
        let provider_id = ProviderID::CryptoAuthLib;
        // ATECC is useful for non-trivial usage only when its configuration is locked
        let mut is_locked = false;
        let err = device.configuration_is_locked(&mut is_locked);
        match err {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                if !is_locked {
                    error!("Error, configuration is not locked.");
                    return None;
                }
            }
            _ => {
                error!("Configuration error: {}", err);
                return None;
            }
        }

        // This will be returned when everything succeedes
        let cryptoauthlib_provider = Provider {
            device,
            provider_id,
            key_info_store,
            key_slots: KeySlotStorage::new(),
        };

        // Get the configuration from ATECC...
        let mut atecc_config_vec = Vec::<rust_cryptoauthlib::AtcaSlot>::new();
        let err = cryptoauthlib_provider
            .device
            .get_config(&mut atecc_config_vec);
        if rust_cryptoauthlib::AtcaStatus::AtcaSuccess != err {
            error!("atecc_get_config failed: {}", err);
            return None;
        }

        // ... and set the key slots configuration as read from hardware
        if let Err(err) = cryptoauthlib_provider
            .key_slots
            .set_hw_config(&atecc_config_vec)
        {
            error!("Applying hardware configuration failed: {}", err);
            return None;
        }

        // Validate KeyInfo data store against hardware configuration.
        // Delete invalid entries or invalid mappings.
        // Mark the slots free/busy appropriately.
        let mut to_remove: Vec<KeyTriple> = Vec::new();
        match cryptoauthlib_provider.key_info_store.get_all() {
            Ok(key_triples) => {
                for key_triple in key_triples.iter().cloned() {
                    let key_id = match cryptoauthlib_provider
                        .key_info_store
                        .get_key_id(&key_triple)
                    {
                        Ok(x) => x,
                        Err(err) => {
                            error!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...",
                                key_triple,
                                err
                            );
                            to_remove.push(key_triple.clone());
                            continue;
                        }
                    };
                    let key_attr = cryptoauthlib_provider
                        .key_info_store
                        .get_key_attributes(&key_triple)
                        .ok()?;
                    match cryptoauthlib_provider
                        .key_slots
                        .key_validate_and_mark_busy(key_id, &key_attr)
                    {
                        Ok(None) => (),
                        Ok(Some(warning)) => warn!("{} for key triple {:?}", warning, key_triple),
                        Err(err) => {
                            error!("{} for key triple {:?}", err, key_triple);
                            to_remove.push(key_triple.clone());
                            continue;
                        }
                    }
                }
            }
            Err(err) => {
                error!("Key Info Manager error: {}", err);
                return None;
            }
        };
        for key_triple in to_remove.iter() {
            if let Err(err) = cryptoauthlib_provider
                .key_info_store
                .remove_key_info(key_triple)
            {
                error!("Key Info Manager error: {}", err);
                return None;
            }
        }

        Some(cryptoauthlib_provider)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: b8ba81e2-e9f7-4bdd-b096-a29d0019960c
            uuid: Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("User space hardware provider, utilizing MicrochipTech CryptoAuthentication Library for ATECCx08 chips"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::CryptoAuthLib,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }

    fn list_keys(
        &self,
        _app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");
        let keys: Vec<KeyInfo> = Vec::new();

        Ok(list_keys::Result { keys })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");
        let clients: Vec<String> = Vec::new();

        Ok(list_clients::Result { clients })
    }

    fn psa_hash_compute(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        trace!("psa_hash_compute ingress");
        self.psa_hash_compute_internal(op)
    }

    fn psa_hash_compare(
        &self,
        op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        trace!("psa_hash_compare ingress");
        self.psa_hash_compare_internal(op)
    }

    fn psa_generate_random(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        self.psa_generate_random_internal(op)
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(app_name, op)
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(app_name, op)
    }
}

/// CryptoAuthentication Library Provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
    device_type: Option<String>,
    iface_type: Option<String>,
    wake_delay: Option<u16>,
    rx_retries: Option<i32>,
    slave_address: Option<u8>,
    bus: Option<u8>,
    baud: Option<u32>,
}

impl ProviderBuilder {
    /// Create a new CryptoAuthLib builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
            device_type: None,
            iface_type: None,
            wake_delay: None,
            rx_retries: None,
            slave_address: None,
            bus: None,
            baud: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(mut self, key_info_store: KeyInfoManagerClient) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the ATECC device to be used
    pub fn with_device_type(mut self, device_type: String) -> ProviderBuilder {
        self.device_type = match device_type.as_str() {
            "atecc508a" | "atecc608a" => Some(device_type),
            _ => None,
        };

        self
    }

    /// Specify an interface type (expected: "i2c")
    pub fn with_iface_type(mut self, iface_type: String) -> ProviderBuilder {
        self.iface_type = match iface_type.as_str() {
            "i2c" => Some(iface_type),
            _ => None,
        };

        self
    }

    /// Specify a wake delay
    pub fn with_wake_delay(mut self, wake_delay: u16) -> ProviderBuilder {
        self.wake_delay = Some(wake_delay);

        self
    }

    /// Specify number of rx retries
    pub fn with_rx_retries(mut self, rx_retries: i32) -> ProviderBuilder {
        self.rx_retries = Some(rx_retries);

        self
    }

    /// Specify i2c slave address of ATECC device
    pub fn with_slave_address(mut self, slave_address: u8) -> ProviderBuilder {
        self.slave_address = Some(slave_address);

        self
    }

    /// Specify i2c bus for ATECC device
    pub fn with_bus(mut self, bus: u8) -> ProviderBuilder {
        self.bus = Some(bus);

        self
    }

    /// Specify i2c baudrate
    pub fn with_baud(mut self, baud: u32) -> ProviderBuilder {
        self.baud = Some(baud);

        self
    }

    /// Attempt to build CryptoAuthLib Provider
    pub fn build(self) -> std::io::Result<Provider> {
        let iface_type = match self.iface_type {
            Some(x) => match x.as_str() {
                "i2c" => rust_cryptoauthlib::atca_iface_setup_i2c(
                    self.device_type.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc device type")
                    })?,
                    self.wake_delay.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc wake delay")
                    })?,
                    self.rx_retries.ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "missing rx retries number for atecc",
                        )
                    })?,
                    Some(self.slave_address.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc i2c slave address")
                    })?),
                    Some(self.bus.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc i2c bus")
                    })?),
                    Some(self.baud.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc i2c baud rate")
                    })?),
                ),
                _ => return Err(Error::new(ErrorKind::InvalidData, "Unknown inteface type")),
            },
            None => return Err(Error::new(ErrorKind::InvalidData, "Missing inteface type")),
        };

        Provider::new(
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            match iface_type {
                Ok(x) => x,
                Err(_x) => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "CryptoAuthLib inteface setup failed",
                    ))
                }
            },
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "CryptoAuthLib Provider initialization failed",
            )
        })
    }
}
