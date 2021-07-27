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
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{list_clients, list_keys};
use parsec_interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use uuid::Uuid;

use parsec_interface::operations::{
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_generate_random,
    psa_hash_compare, psa_hash_compute, psa_import_key, psa_sign_hash, psa_sign_message,
    psa_verify_hash, psa_verify_message,
};

mod access_keys;
mod asym_sign;
mod generate_random;
mod hash;
mod key_management;
mod key_slot;
mod key_slot_storage;

/// CryptoAuthLib provider structure
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    #[derivative(Debug = "ignore")]
    device: rust_cryptoauthlib::AteccDevice,
    provider_id: ProviderId,
    // The name of the provider set in the config.
    provider_name: String,
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
    key_slots: KeySlotStorage,
    supported_opcodes: HashSet<Opcode>,
}

impl Provider {
    /// The default provider name for cryptoauthlib provider
    pub const DEFAULT_PROVIDER_NAME: &'static str = "cryptoauthlib-provider";

    /// The UUID for this provider
    pub const PROVIDER_UUID: &'static str = "b8ba81e2-e9f7-4bdd-b096-a29d0019960c";

    /// Creates and initialises an instance of CryptoAuthLibProvider
    fn new(
        provider_name: String,
        key_info_store: KeyInfoManagerClient,
        atca_iface: rust_cryptoauthlib::AtcaIfaceCfg,
        access_key_file_name: Option<String>,
    ) -> Option<Provider> {
        // This will be returned when everything succeedes
        let mut cryptoauthlib_provider: Provider;

        // First define communication channel with the device then set it up
        let device = match rust_cryptoauthlib::setup_atecc_device(atca_iface) {
            Ok(dev) => dev,
            Err(err) => {
                error!("ATECC device initialization failed: {}", err);
                return None;
            }
        };

        // ATECC is useful for non-trivial usage only when its configuration is locked
        if !device.is_configuration_locked() {
            error!("Error: configuration is not locked.");
            return None;
        }

        cryptoauthlib_provider = Provider {
            device,
            provider_id: ProviderId::CryptoAuthLib,
            provider_name,
            key_info_store,
            key_slots: KeySlotStorage::new(),
            supported_opcodes: HashSet::new(),
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

        // Validate key info store against hardware configuration.
        // Delete invalid entries or invalid mappings.
        // Mark the slots free/busy appropriately.
        let mut to_remove: Vec<KeyTriple> = Vec::new();
        match cryptoauthlib_provider.key_info_store.get_all() {
            Ok(key_triples) => {
                for key_triple in key_triples.iter().cloned() {
                    match cryptoauthlib_provider
                        .key_info_store
                        .does_not_exist(&key_triple)
                    {
                        Ok(x) => x,
                        Err(err) => {
                            warn!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...",
                                key_triple,
                                err
                            );
                            to_remove.push(key_triple.clone());
                            continue;
                        }
                    };
                    let key_info_id = match cryptoauthlib_provider
                        .key_info_store
                        .get_key_id::<u8>(&key_triple)
                    {
                        Ok(x) => x,
                        Err(err) => {
                            warn!(
                                "Could not get key info id for key triple {:?} because {}",
                                key_triple, err
                            );
                            to_remove.push(key_triple.clone());
                            continue;
                        }
                    };
                    let key_info_attributes = match cryptoauthlib_provider
                        .key_info_store
                        .get_key_attributes(&key_triple)
                    {
                        Ok(x) => x,
                        Err(err) => {
                            warn!(
                                "Could not get key attributes for key triple {:?} because {}",
                                key_triple, err
                            );
                            to_remove.push(key_triple.clone());
                            continue;
                        }
                    };
                    match cryptoauthlib_provider
                        .key_slots
                        .key_validate_and_mark_busy(key_info_id, &key_info_attributes)
                    {
                        Ok(None) => (),
                        Ok(Some(warning)) => warn!("{} for key triple {:?}", warning, key_triple),
                        Err(err) => {
                            warn!("{} for key triple {:?}", err, key_triple);
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

        if None == cryptoauthlib_provider.set_opcodes() {
            warn!("Failed to setup opcodes for cryptoauthlib_provider");
        }

        let err = cryptoauthlib_provider.set_access_keys(access_key_file_name);
        match err {
            Some(rust_cryptoauthlib::AtcaStatus::AtcaSuccess) => (),
            _ => {
                warn!("Unable to set access keys. This is dangerous for a hardware interface.");
            }
        }

        Some(cryptoauthlib_provider)
    }

    fn set_opcodes(&mut self) -> Option<()> {
        match self.device.get_device_type() {
            rust_cryptoauthlib::AtcaDeviceType::ATECC508A
            | rust_cryptoauthlib::AtcaDeviceType::ATECC608A
            | rust_cryptoauthlib::AtcaDeviceType::ATECC108A => {
                if self.supported_opcodes.insert(Opcode::PsaGenerateKey)
                    && self.supported_opcodes.insert(Opcode::PsaDestroyKey)
                    && self.supported_opcodes.insert(Opcode::PsaHashCompute)
                    && self.supported_opcodes.insert(Opcode::PsaHashCompare)
                    && self.supported_opcodes.insert(Opcode::PsaGenerateRandom)
                    && self.supported_opcodes.insert(Opcode::PsaImportKey)
                    && self.supported_opcodes.insert(Opcode::PsaSignHash)
                    && self.supported_opcodes.insert(Opcode::PsaVerifyHash)
                    && self.supported_opcodes.insert(Opcode::PsaSignMessage)
                    && self.supported_opcodes.insert(Opcode::PsaVerifyMessage)
                    && self.supported_opcodes.insert(Opcode::PsaExportPublicKey)
                    && self.supported_opcodes.insert(Opcode::PsaExportKey)
                {
                    Some(())
                } else {
                    None
                }
            }
            rust_cryptoauthlib::AtcaDeviceType::AtcaTestDevSuccess
            | rust_cryptoauthlib::AtcaDeviceType::AtcaTestDevFail
            | rust_cryptoauthlib::AtcaDeviceType::AtcaTestDevFailUnimplemented => {
                let _ = self.supported_opcodes.insert(Opcode::PsaGenerateRandom);
                Some(())
            }
            _ => None,
        }
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: b8ba81e2-e9f7-4bdd-b096-a29d0019960c
            uuid: Uuid::parse_str(Provider::PROVIDER_UUID).or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("User space hardware provider, utilizing MicrochipTech CryptoAuthentication Library for ATECCx08 chips"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderId::CryptoAuthLib,
        }, self.supported_opcodes.iter().copied().collect()))
    }

    fn list_keys(
        &self,
        app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        Ok(list_keys::Result {
            keys: self.key_info_store.list_keys(&app_name)?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        Ok(list_clients::Result {
            clients: self
                .key_info_store
                .list_clients()?
                .into_iter()
                .map(|app_name| app_name.to_string())
                .collect(),
        })
    }

    fn psa_hash_compute(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        trace!("psa_hash_compute ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaHashCompute) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_hash_compute_internal(op)
        }
    }

    fn psa_hash_compare(
        &self,
        op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        trace!("psa_hash_compare ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaHashCompare) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_hash_compare_internal(op)
        }
    }

    fn psa_generate_random(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaGenerateRandom) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_generate_random_internal(op)
        }
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaGenerateKey) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_generate_key_internal(app_name, op)
        }
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaDestroyKey) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_destroy_key_internal(app_name, op)
        }
    }

    fn psa_import_key(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaImportKey) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_import_key_internal(app_name, op)
        }
    }

    fn psa_sign_hash(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaSignHash) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_sign_hash_internal(app_name, op)
        }
    }

    fn psa_verify_hash(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        trace!("psa_verify_hash ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaVerifyHash) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_verify_hash_internal(app_name, op)
        }
    }

    fn psa_sign_message(
        &self,
        app_name: ApplicationName,
        op: psa_sign_message::Operation,
    ) -> Result<psa_sign_message::Result> {
        trace!("psa_sign_message ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaSignMessage) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_sign_message_internal(app_name, op)
        }
    }

    fn psa_verify_message(
        &self,
        app_name: ApplicationName,
        op: psa_verify_message::Operation,
    ) -> Result<psa_verify_message::Result> {
        trace!("psa_verify_message ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaVerifyMessage) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_verify_message_internal(app_name, op)
        }
    }

    fn psa_export_public_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaExportPublicKey) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_export_public_key_internal(app_name, op)
        }
    }

    fn psa_export_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        trace!("psa_export_key ingress");
        if !self.supported_opcodes.contains(&Opcode::PsaExportKey) {
            Err(ResponseStatus::PsaErrorNotSupported)
        } else {
            self.psa_export_key_internal(app_name, op)
        }
    }
}

/// CryptoAuthentication Library Provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    provider_name: Option<String>,
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
    device_type: Option<String>,
    iface_type: Option<String>,
    wake_delay: Option<u16>,
    rx_retries: Option<i32>,
    slave_address: Option<u8>,
    bus: Option<u8>,
    baud: Option<u32>,
    access_key_file_name: Option<String>,
}

impl ProviderBuilder {
    /// Create a new CryptoAuthLib builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            provider_name: None,
            key_info_store: None,
            device_type: None,
            iface_type: None,
            wake_delay: None,
            rx_retries: None,
            slave_address: None,
            bus: None,
            baud: None,
            access_key_file_name: None,
        }
    }

    /// Add a provider name
    pub fn with_provider_name(mut self, provider_name: String) -> ProviderBuilder {
        self.provider_name = Some(provider_name);

        self
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(mut self, key_info_store: KeyInfoManagerClient) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the ATECC device to be used
    pub fn with_device_type(mut self, device_type: String) -> ProviderBuilder {
        self.device_type = Some(device_type);

        self
    }

    /// Specify an interface type (expected: "i2c")
    pub fn with_iface_type(mut self, iface_type: String) -> ProviderBuilder {
        self.iface_type = Some(iface_type);

        self
    }

    /// Specify a wake delay
    pub fn with_wake_delay(mut self, wake_delay: Option<u16>) -> ProviderBuilder {
        self.wake_delay = wake_delay;

        self
    }

    /// Specify number of rx retries
    pub fn with_rx_retries(mut self, rx_retries: Option<i32>) -> ProviderBuilder {
        self.rx_retries = rx_retries;

        self
    }

    /// Specify i2c slave address of ATECC device
    pub fn with_slave_address(mut self, slave_address: Option<u8>) -> ProviderBuilder {
        self.slave_address = slave_address;

        self
    }

    /// Specify i2c bus for ATECC device
    pub fn with_bus(mut self, bus: Option<u8>) -> ProviderBuilder {
        self.bus = bus;

        self
    }

    /// Specify i2c baudrate
    pub fn with_baud(mut self, baud: Option<u32>) -> ProviderBuilder {
        self.baud = baud;

        self
    }

    /// Specify access key file name
    pub fn with_access_key_file(mut self, access_key_file_name: Option<String>) -> ProviderBuilder {
        self.access_key_file_name = access_key_file_name;

        self
    }

    /// Attempt to build CryptoAuthLib Provider
    pub fn build(self) -> std::io::Result<Provider> {
        let iface_cfg = match self.iface_type {
            Some(x) => match x.as_str() {
                "i2c" => {
                    let atcai2c_iface_cfg = rust_cryptoauthlib::AtcaIfaceI2c::default()
                        .set_slave_address(self.slave_address.ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "missing atecc i2c slave address")
                        })?)
                        .set_bus(self.bus.ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "missing atecc i2c bus")
                        })?)
                        .set_baud(self.baud.ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "missing atecc i2c baud rate")
                        })?);
                    rust_cryptoauthlib::AtcaIfaceCfg::default()
                        .set_iface_type("i2c".to_owned())
                        .set_devtype(self.device_type.ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "missing atecc device type")
                        })?)
                        .set_wake_delay(self.wake_delay.ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "missing atecc wake delay")
                        })?)
                        .set_rx_retries(self.rx_retries.ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "missing rx retries number for atecc",
                            )
                        })?)
                        .set_iface(
                            rust_cryptoauthlib::AtcaIface::default().set_atcai2c(atcai2c_iface_cfg),
                        )
                }
                "test-interface" => rust_cryptoauthlib::AtcaIfaceCfg::default()
                    .set_iface_type("test-interface".to_owned())
                    .set_devtype(self.device_type.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "missing atecc device type")
                    })?),
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Unsupported inteface type",
                    ))
                }
            },
            None => return Err(Error::new(ErrorKind::InvalidData, "Missing inteface type")),
        };
        Provider::new(
            self.provider_name.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing provider name")
            })?,
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            iface_cfg,
            self.access_key_file_name,
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "CryptoAuthLib Provider initialization failed",
            )
        })
    }
}
