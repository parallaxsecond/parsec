// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Structures for the Parsec configuration file

use log::LevelFilter;
use parsec_interface::requests::ProviderId;
use serde::Deserialize;
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
        wake_delay: Option<u16>,
        /// Number of rx retries
        rx_retries: Option<i32>,
        /// I2C slave address
        slave_address: Option<u8>,
        /// I2C bus
        bus: Option<u8>,
        /// I2C baud rate
        baud: Option<u32>,
    },
    /// Trusted Service provider configuration
    TrustedService {
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
