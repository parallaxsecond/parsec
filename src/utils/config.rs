// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Structures for the Parsec configuration file

#[cfg(feature = "cryptoauthlib-provider")]
use crate::providers::cryptoauthlib::Provider as CryptoAuthLibProvider;
#[cfg(feature = "mbed-crypto-provider")]
use crate::providers::mbed_crypto::Provider as MbedCryptoProvider;
#[cfg(feature = "pkcs11-provider")]
use crate::providers::pkcs11::Provider as Pkcs11Provider;
#[cfg(feature = "tpm-provider")]
use crate::providers::tpm::Provider as TpmProvider;
#[cfg(feature = "trusted-service-provider")]
use crate::providers::trusted_service::Provider as TrustedServiceProvider;
#[cfg(not(all(
    feature = "mbed-crypto-provider",
    feature = "pkcs11-provider",
    feature = "tpm-provider",
    feature = "cryptoauthlib-provider",
    feature = "trusted-service-provider"
)))]
use log::error;
use log::LevelFilter;
use parsec_interface::requests::ProviderId;
use serde::Deserialize;
use std::io::Error;
#[cfg(not(all(
    feature = "mbed-crypto-provider",
    feature = "pkcs11-provider",
    feature = "tpm-provider",
    feature = "cryptoauthlib-provider",
    feature = "trusted-service-provider"
)))]
use std::io::ErrorKind;
use zeroize::Zeroize;

/// Core settings
///
/// See the config.toml file for a description of each field.
#[derive(Copy, Clone, Deserialize, Debug)]
#[allow(missing_docs)]
pub struct CoreSettings {
    pub thread_pool_size: Option<usize>,
    pub idle_listener_sleep_duration: Option<u64>,
    pub log_level: Option<LevelFilter>,
    pub log_timestamp: Option<bool>,
    pub body_len_limit: Option<usize>,
    pub log_error_details: Option<bool>,
    pub allow_root: Option<bool>,
    pub buffer_size_limit: Option<usize>,
}

/// Type of the Listener used
#[derive(Copy, Clone, Deserialize, Debug)]
pub enum ListenerType {
    /// Listener using Unix Domain Socket
    DomainSocket,
}

/// Configuration of the Listener
#[derive(Clone, Deserialize, Debug)]
pub struct ListenerConfig {
    /// Type of the Listener
    pub listener_type: ListenerType,
    /// Timeout of the Listener before the connection errors out (in milliseconds)
    pub timeout: u64,
    /// Path of the Unix Domain socket
    pub socket_path: Option<String>,
}

/// Authenticator configuration structure
#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
#[serde(tag = "auth_type")]
pub enum AuthenticatorConfig {
    /// Direct authentication
    Direct {
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
    /// Unix Peer Credentials authentication
    UnixPeerCredentials {
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
    /// JWT-SVID
    JwtSvid {
        /// Path to the Workload API socket
        workload_endpoint: String,
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
}

/// Structure defining the properties of a service admin
#[derive(Deserialize, Debug, Zeroize, Clone)]
#[zeroize(drop)]
pub struct Admin {
    name: String,
}

impl Admin {
    /// Give the application name of the admin
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Type of the KeyInfoManager
#[derive(Copy, Clone, Deserialize, Debug)]
pub enum KeyInfoManagerType {
    /// KeyInfoManager storing the mappings on disk
    OnDisk,
}

/// KeyInfoManager configuration
#[derive(Deserialize, Debug)]
pub struct KeyInfoManagerConfig {
    /// Name of the KeyInfoManager
    pub name: String,
    /// Type of the KeyInfoManager
    pub manager_type: KeyInfoManagerType,
    /// Path used to store the mappings
    pub store_path: Option<String>,
}

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
        /// The name of the provider
        name: Option<String>,
        /// Name of the Key Info Manager to use
        key_info_manager: String,
    },
    /// PKCS 11 provider configuration
    Pkcs11 {
        /// The name of the provider
        name: Option<String>,
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// Path of the PKCS 11 library
        library_path: String,
        /// Slot number to use
        slot_number: Option<u64>,
        /// User Pin
        user_pin: Option<String>,
        /// Control whether public key operations are performed in software
        software_public_operations: Option<bool>,
        /// Control whether it is allowed for a key to be exportable
        allow_export: Option<bool>,
    },
    /// TPM provider configuration
    Tpm {
        /// The name of the provider
        name: Option<String>,
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// TCTI to use with the provider
        tcti: String,
        /// Owner Hierarchy Authentication
        owner_hierarchy_auth: String,
        /// Allows the service to still start without this provider if there is no TPM on the
        /// system. The priority list of providers will be as if this provider was commented out.
        skip_if_no_tpm: Option<bool>,
    },
    /// Microchip CryptoAuthentication Library provider configuration
    CryptoAuthLib {
        /// The name of the provider
        name: Option<String>,
        /// Name of the Key Info Manager to use
        key_info_manager: String,
        /// ATECC Device type
        device_type: String,
        /// Interface type
        iface_type: String,
        /// Wake delay
        wake_delay: Option<u16>,
        /// Number of rx retries
        rx_retries: Option<i32>,
        /// I2C slave address
        slave_address: Option<u8>,
        /// I2C bus
        bus: Option<u8>,
        /// I2C baud rate
        baud: Option<u32>,
        /// Access key configuration file name
        access_key_file_name: Option<String>,
    },
    /// Trusted Service provider configuration
    TrustedService {
        /// The name of the provider
        name: Option<String>,
        /// Name of Key Info Manager to use
        key_info_manager: String,
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
            ProviderConfig::TrustedService {
                ref key_info_manager,
                ..
            } => key_info_manager,
        }
    }
    /// Get the Provider ID of the provider
    pub fn provider_id(&self) -> ProviderId {
        match *self {
            ProviderConfig::MbedCrypto { .. } => ProviderId::MbedCrypto,
            ProviderConfig::Pkcs11 { .. } => ProviderId::Pkcs11,
            ProviderConfig::Tpm { .. } => ProviderId::Tpm,
            ProviderConfig::CryptoAuthLib { .. } => ProviderId::CryptoAuthLib,
            ProviderConfig::TrustedService { .. } => ProviderId::TrustedService,
        }
    }
    /// Get the name of the Provider
    /// If there is not one set, use the default.
    pub fn provider_name(&self) -> Result<String, Error> {
        match *self {
            #[cfg(feature = "mbed-crypto-provider")]
            ProviderConfig::MbedCrypto { ref name, .. } => Ok(name
                .clone()
                .unwrap_or_else(|| String::from(MbedCryptoProvider::DEFAULT_PROVIDER_NAME))),
            #[cfg(feature = "pkcs11-provider")]
            ProviderConfig::Pkcs11 { ref name, .. } => Ok(name
                .clone()
                .unwrap_or_else(|| String::from(Pkcs11Provider::DEFAULT_PROVIDER_NAME))),
            #[cfg(feature = "tpm-provider")]
            ProviderConfig::Tpm { ref name, .. } => Ok(name
                .clone()
                .unwrap_or_else(|| String::from(TpmProvider::DEFAULT_PROVIDER_NAME))),
            #[cfg(feature = "cryptoauthlib-provider")]
            ProviderConfig::CryptoAuthLib { ref name, .. } => Ok(name
                .clone()
                .unwrap_or_else(|| String::from(CryptoAuthLibProvider::DEFAULT_PROVIDER_NAME))),
            #[cfg(feature = "trusted-service-provider")]
            ProviderConfig::TrustedService { ref name, .. } => Ok(name
                .clone()
                .unwrap_or_else(|| String::from(TrustedServiceProvider::DEFAULT_PROVIDER_NAME))),
            #[cfg(not(all(
                feature = "mbed-crypto-provider",
                feature = "pkcs11-provider",
                feature = "tpm-provider",
                feature = "cryptoauthlib-provider",
                feature = "trusted-service-provider"
            )))]
            _ => {
                error!("Provider chosen in the configuration was not compiled in Parsec binary.");
                Err(Error::new(ErrorKind::InvalidData, "provider not compiled"))
            }
        }
    }
}

/// Configuration of Parsec
///
/// See the config.toml file for a description of each field.
#[derive(Deserialize, Debug)]
#[allow(missing_docs)]
pub struct ServiceConfig {
    pub core_settings: CoreSettings,
    pub listener: ListenerConfig,
    pub authenticator: AuthenticatorConfig,
    pub key_manager: Option<Vec<KeyInfoManagerConfig>>,
    pub provider: Option<Vec<ProviderConfig>>,
}
