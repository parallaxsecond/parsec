// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core inter-op with underlying hardware
//!
//! [Providers](https://parallaxsecond.github.io/parsec-book/parsec_service/providers.html)
//! are the real implementors of the operations that Parsec claims to support. They map to
//! functionality in the underlying hardware which allows the PSA Crypto operations to be
//! backed by a hardware root of trust.
use log::trace;
use parsec_interface::requests::{Opcode, ProviderID};
use serde::Deserialize;
use std::collections::HashSet;
use zeroize::Zeroize;

pub mod core;

#[cfg(feature = "pkcs11-provider")]
pub mod pkcs11;

#[cfg(feature = "mbed-crypto-provider")]
pub mod mbed_crypto;

#[cfg(feature = "tpm-provider")]
pub mod tpm;

#[cfg(feature = "cryptoauthlib-provider")]
pub mod cryptoauthlib;

/// Provider configuration structure
/// For providers configs in Parsec config.toml we use a format similar
/// to the one described in the Internally Tagged Enum representation
/// where "provider_type" is the tag field. For details see:
/// https://serde.rs/enum-representations.html
#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
#[serde(tag = "provider_type")]
pub enum ProviderConfig {
    /// Mbed Crypto provider configuration
    MbedCrypto {
        /// Name of the Key Info Manager to use
        key_info_manager: String,
    },
    /// PKCS 11 provider configuration
    Pkcs11 {
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// Path of the PKCS 11 library
        library_path: String,
        /// Slot number to use
        slot_number: usize,
        /// User Pin
        user_pin: Option<String>,
        /// Control whether public key operations are performed in software
        software_public_operations: Option<bool>,
    },
    /// TPM provider configuration
    Tpm {
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// TCTI to use with the provider
        tcti: String,
        /// Owner Hierarchy Authentication
        owner_hierarchy_auth: String,
    },
    /// Microchip CryptoAuthentication Library provider configuration
    CryptoAuthLib {
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// ATECC Device type
        device_type: String,
        /// Interface type
        iface_type: String,
        /// Wake delay
        wake_delay: u16,
        /// Number of rx retries
        rx_retries: i32,
        /// I2C slave address
        slave_address: Option<u8>,
        /// I2C bus
        bus: Option<u8>,
        /// I2C baud rate
        baud: Option<u32>,
    },
}

impl ProviderConfig {
    /// Get the name of the Key Info Manager in the provider configuration
    pub fn key_info_manager(&self) -> &String {
        match *self {
            ProviderConfig::MbedCrypto {
                ref key_info_manager,
                ..
            } => key_info_manager,
            ProviderConfig::Pkcs11 {
                ref key_info_manager,
                ..
            } => key_info_manager,
            ProviderConfig::Tpm {
                ref key_info_manager,
                ..
            } => key_info_manager,
            ProviderConfig::CryptoAuthLib {
                ref key_info_manager,
                ..
            } => key_info_manager,
        }
    }
    /// Get the Provider ID of the provider
    pub fn provider_id(&self) -> ProviderID {
        match *self {
            ProviderConfig::MbedCrypto { .. } => ProviderID::MbedCrypto,
            ProviderConfig::Pkcs11 { .. } => ProviderID::Pkcs11,
            ProviderConfig::Tpm { .. } => ProviderID::Tpm,
            ProviderConfig::CryptoAuthLib { .. } => ProviderID::CryptoAuthLib,
        }
    }
}

use crate::authenticators::ApplicationName;
use parsec_interface::operations::{
    delete_client, list_authenticators, list_clients, list_keys, list_opcodes, list_providers,
    ping, psa_aead_decrypt, psa_aead_encrypt, psa_asymmetric_decrypt, psa_asymmetric_encrypt,
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_generate_random,
    psa_hash_compare, psa_hash_compute, psa_import_key, psa_raw_key_agreement, psa_sign_hash,
    psa_verify_hash,
};
use parsec_interface::requests::{ResponseStatus, Result};

/// Provider interface for servicing client operations
///
/// Definition of the interface that a provider must implement to
/// be linked into the service through a backend handler.
///
/// The methods with no default are used on a service-level by the
/// core provider and so must be supported by all providers.
pub trait Provide {
    /// Return a description of the current provider.
    ///
    /// The descriptions are gathered in the Core Provider and returned for a ListProviders operation.
    fn describe(&self) -> Result<(list_providers::ProviderInfo, HashSet<Opcode>)>;

    /// List the providers running in the service.
    fn list_providers(&self, _op: list_providers::Operation) -> Result<list_providers::Result> {
        trace!("list_providers ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// List the opcodes supported by the given provider.
    fn list_opcodes(&self, _op: list_opcodes::Operation) -> Result<list_opcodes::Result> {
        trace!("list_opcodes ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// List the authenticators supported by the given provider.
    fn list_authenticators(
        &self,
        _op: list_authenticators::Operation,
    ) -> Result<list_authenticators::Result> {
        trace!("list_authenticators ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Lists all keys belonging to the application.
    fn list_keys(
        &self,
        _app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result>;

    /// Lists all clients currently having data in the service.
    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result>;

    /// Delete all data a client has in the service..
    fn delete_client(&self, _op: delete_client::Operation) -> Result<delete_client::Result> {
        trace!("delete_client ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a Ping operation to get the wire protocol version major and minor information.
    ///
    /// # Errors
    ///
    /// This operation will only fail if not implemented. It will never fail when being called on
    /// the `CoreProvider`.
    fn ping(&self, _op: ping::Operation) -> Result<ping::Result> {
        trace!("ping ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a GenerateKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to create a key with the same name later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. generate unique key ID
    /// 2. try key creation with it. If successfull go to 3 else return an error.
    /// 3. store the mappings between key name and key ID. If successfull return success, else go to 4.
    /// 4. try to delete the key created. If failed, log it and return the error from 3.
    fn psa_generate_key(
        &self,
        _app_name: ApplicationName,
        _op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ImportKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to import a key with the same name later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. generate unique key ID
    /// 2. try key import with it. If successfull go to 3 else return an error.
    /// 3. store the mappings between key name and key ID. If successfull return success, else go to 4.
    /// 4. try to delete the key imported. If failed, log it and return the error from 3.
    fn psa_import_key(
        &self,
        _app_name: ApplicationName,
        _op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ExportPublicKey operation.
    fn psa_export_public_key(
        &self,
        _app_name: ApplicationName,
        _op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ExportKey operation.
    fn psa_export_key(
        &self,
        _app_name: ApplicationName,
        _op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        trace!("psa_export_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a DestroyKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to generate or create a key with the same name than the one destroyed later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. get the key ID from the key name using the KIM
    /// 2. destroy the key mappings
    /// 3. try to destroy the key
    fn psa_destroy_key(
        &self,
        _app_name: ApplicationName,
        _op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a SignHash operation. This operation only signs the short digest given but does not
    /// hash it.
    fn psa_sign_hash(
        &self,
        _app_name: ApplicationName,
        _op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a VerifyHash operation.
    fn psa_verify_hash(
        &self,
        _app_name: ApplicationName,
        _op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        trace!("psa_verify_hash ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AsymmetricEncrypt operation.
    fn psa_asymmetric_encrypt(
        &self,
        _app_name: ApplicationName,
        _op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        trace!("psa_asymmetric_encrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AsymmetricDecrypt operation.
    fn psa_asymmetric_decrypt(
        &self,
        _app_name: ApplicationName,
        _op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AeadEncrypt operation.
    fn psa_aead_encrypt(
        &self,
        _app_name: ApplicationName,
        _op: psa_aead_encrypt::Operation,
    ) -> Result<psa_aead_encrypt::Result> {
        trace!("psa_aead_encrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AeadDecrypt operation.
    fn psa_aead_decrypt(
        &self,
        _app_name: ApplicationName,
        _op: psa_aead_decrypt::Operation,
    ) -> Result<psa_aead_decrypt::Result> {
        trace!("psa_aead_decrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a HashCompute operation.
    fn psa_hash_compute(
        &self,
        _op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        trace!("psa_hash_compute ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a HashCompare operation.
    fn psa_hash_compare(
        &self,
        _op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        trace!("psa_hash_compare ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a RawKeyAgreement operation.
    fn psa_raw_key_agreement(
        &self,
        _app_name: ApplicationName,
        _op: psa_raw_key_agreement::Operation,
    ) -> Result<psa_raw_key_agreement::Result> {
        trace!("psa_raw_key_agreement ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a GenerateRandom operation.
    fn psa_generate_random(
        &self,
        _op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }
}
