// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS 11 provider
//!
//! This provider allows clients to access any PKCS 11 compliant device
//! through the Parsec interface.
use super::Provide;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::{KeyIdentity, KeyInfoManagerClient};
use crate::providers::crypto_capability::CanDoCrypto;
use crate::providers::ProviderIdentity;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use derivative::Derivative;
use log::{error, info, trace, warn};
use parsec_interface::operations::list_providers::Uuid;
use parsec_interface::operations::{
    can_do_crypto, psa_asymmetric_decrypt, psa_asymmetric_encrypt, psa_destroy_key,
    psa_export_public_key, psa_generate_key, psa_generate_random, psa_import_key, psa_sign_hash,
    psa_verify_hash,
};
use parsec_interface::operations::{list_clients, list_keys, list_providers::ProviderInfo};
use parsec_interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use parsec_interface::secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::RwLock;
use utils::{to_response_status, KeyPairType};
use zeroize::{Zeroize, Zeroizing};

type LocalIdStore = HashSet<u32>;

mod asym_encryption;
mod asym_sign;
mod capability_discovery;
mod generate_random;
mod key_management;
mod key_metadata;
mod utils;

const SUPPORTED_OPCODES: [Opcode; 10] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaAsymmetricDecrypt,
    Opcode::PsaAsymmetricEncrypt,
    Opcode::CanDoCrypto,
    Opcode::PsaGenerateRandom,
];

const PIN_STRING_PREFIX: &str = "str:";
const PIN_HEX_PREFIX: &str = "hex:";

/// Provider for Public Key Cryptography Standard #11
///
/// Operations for this provider are serviced through a PKCS11 interface,
/// allowing any libraries exposing said interface to be loaded and used
/// at runtime.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    // The identity of the provider including uuid & name.
    provider_identity: ProviderIdentity,
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
    local_ids: RwLock<LocalIdStore>,
    #[derivative(Debug = "ignore")]
    backend: Pkcs11,
    slot_number: Slot,
    software_public_operations: bool,
    allow_export: bool,
    user_pin: Option<SecretString>,
}

impl Provider {
    /// The default provider name for pkcs11 provider
    pub const DEFAULT_PROVIDER_NAME: &'static str = "pkcs11-provider";

    /// The UUID for this provider
    pub const PROVIDER_UUID: &'static str = "30e39502-eba6-4d60-a4af-c518b7f5e38f";

    /// Creates and initialise a new instance of Pkcs11Provider.
    /// Checks if there are not more keys stored in the Key Info Manager than in the PKCS 11 library
    /// and if there are, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    fn new(
        provider_name: String,
        key_info_store: KeyInfoManagerClient,
        backend: Pkcs11,
        slot_number: Slot,
        user_pin: Option<SecretString>,
        software_public_operations: bool,
        allow_export: bool,
    ) -> Option<Provider> {
        #[allow(clippy::mutex_atomic)]
        let pkcs11_provider = Provider {
            provider_identity: ProviderIdentity {
                name: provider_name,
                uuid: String::from(Self::PROVIDER_UUID),
            },
            key_info_store,
            local_ids: RwLock::new(HashSet::new()),
            backend,
            slot_number,
            software_public_operations,
            allow_export,
            user_pin,
        };
        {
            let mut local_ids_handle = pkcs11_provider
                .local_ids
                .write()
                .expect("Local ID lock poisoned");
            let mut to_remove: Vec<KeyIdentity> = Vec::new();
            // Go through all PKCS 11 key identities to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match pkcs11_provider.key_info_store.get_all() {
                Ok(key_identities) => {
                    let session = pkcs11_provider.new_session().ok()?;

                    for key_identity in key_identities.iter().cloned() {
                        let key_id = match pkcs11_provider.key_info_store.get_key_id(&key_identity)
                        {
                            Ok(id) => id,
                            Err(ResponseStatus::PsaErrorDoesNotExist) => {
                                error!("Stored key info missing for KeyIdentity {}.", key_identity);
                                continue;
                            }
                            Err(e) => {
                                format_error!(
                                    format!(
                                        "Stored key info invalid for KeyIdentity {}.",
                                        key_identity
                                    ),
                                    e
                                );

                                to_remove.push(key_identity.clone());
                                continue;
                            }
                        };

                        match pkcs11_provider.find_key(&session, key_id, KeyPairType::Any) {
                            Ok(_) => {
                                if crate::utils::GlobalConfig::log_error_details() {
                                    warn!(
                                        "Key {} found in the PKCS 11 library, adding it.",
                                        key_identity
                                    );
                                } else {
                                    warn!("Key found in the PKCS 11 library, adding it.");
                                }
                                let _ = local_ids_handle.insert(key_id);
                            }
                            Err(ResponseStatus::PsaErrorDoesNotExist) => {
                                if crate::utils::GlobalConfig::log_error_details() {
                                    warn!(
                                        "Key {} not found in the PKCS 11 library, deleting it.",
                                        key_identity
                                    );
                                } else {
                                    warn!("Key not found in the PKCS 11 library, deleting it.");
                                }
                                to_remove.push(key_identity.clone());
                            }
                            Err(e) => {
                                format_error!("Error finding key objects", e);
                                return None;
                            }
                        }
                    }
                }
                Err(string) => {
                    format_error!("Key Info Manager error", string);
                    return None;
                }
            };
            for key_identity in to_remove.iter() {
                if pkcs11_provider
                    .key_info_store
                    .remove_key_info(&key_identity)
                    .is_err()
                {
                    return None;
                }
            }
        }

        if pkcs11_provider.software_public_operations {
            psa_crypto::init().expect(
                "Failed to initialize PSA Crypto for public key operation software support",
            );
        }

        Some(pkcs11_provider)
    }

    // Create a new session with the following properties:
    // * without callback
    // * read/write session
    // * serial session
    // * logged in if the pin is set
    // * set on the slot in the provider
    fn new_session(&self) -> Result<Session> {
        let session = self
            .backend
            .open_rw_session(self.slot_number)
            .map_err(to_response_status)?;

        if self.user_pin.is_some() {
            let mut pin = Zeroizing::new(self.user_pin.as_ref().unwrap().expose_secret().clone());
            if pin.starts_with(PIN_HEX_PREFIX) {
                if let Ok(mut raw_pin) = hex::decode(pin.split_off(PIN_HEX_PREFIX.len())) {
                    pin = Zeroizing::new(String::from_utf8_lossy(&raw_pin.as_slice()).to_string());
                    raw_pin.zeroize();
                }
            } else if pin.starts_with(PIN_STRING_PREFIX) {
                pin = pin.split_off(PIN_STRING_PREFIX.len()).into();
            }

            session
                .login(UserType::User, Some(&AuthPin::new(pin.to_string())))
                .or_else(|e| {
                    if let Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn) = e {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(to_response_status)?;
        }

        Ok(session)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((
            ProviderInfo {
                // Assigned UUID for this provider: 30e39502-eba6-4d60-a4af-c518b7f5e38f
                uuid: Uuid::parse_str(Provider::PROVIDER_UUID)
                    .or(Err(ResponseStatus::InvalidEncoding))?,
                description: String::from(
                    "PKCS #11 provider, interfacing with a PKCS #11 library.",
                ),
                vendor: String::from("OASIS Standard."),
                version_maj: 0,
                version_min: 1,
                version_rev: 0,
                id: ProviderId::Pkcs11,
            },
            SUPPORTED_OPCODES.iter().copied().collect(),
        ))
    }

    fn list_keys(
        &self,
        application_identity: &ApplicationIdentity,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");
        Ok(list_keys::Result {
            keys: self.key_info_store.list_keys(application_identity)?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");
        Ok(list_clients::Result {
            clients: self
                .key_info_store
                .list_clients()?
                .into_iter()
                .map(|application_identity| application_identity.name().clone())
                .collect(),
        })
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
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(application_identity, op)
    }

    fn psa_import_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        self.psa_import_key_internal(application_identity, op)
    }

    fn psa_export_public_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        self.psa_export_public_key_internal(application_identity, op)
    }

    fn psa_destroy_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(application_identity, op)
    }

    fn psa_sign_hash(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        self.psa_sign_hash_internal(application_identity, op)
    }

    fn psa_verify_hash(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        if self.software_public_operations {
            trace!("software_psa_verify_hash ingress");
            self.software_psa_verify_hash_internal(application_identity, op)
        } else {
            trace!("pkcs11_psa_verify_hash ingress");
            self.psa_verify_hash_internal(application_identity, op)
        }
    }

    fn psa_asymmetric_encrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        if self.software_public_operations {
            trace!("software_psa_asymmetric_encrypt ingress");
            self.software_psa_asymmetric_encrypt_internal(application_identity, op)
        } else {
            trace!("psa_asymmetric_encrypt ingress");
            self.psa_asymmetric_encrypt_internal(application_identity, op)
        }
    }

    fn psa_asymmetric_decrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(application_identity, op)
    }

    /// Check if the crypto operation is supported by PKCS11 provider
    /// by using CanDoCrypto trait.
    fn can_do_crypto(
        &self,
        application_identity: &ApplicationIdentity,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto ingress");
        self.can_do_crypto_main(application_identity, op)
    }
}

/// Builder for Pkcs11Provider
///
/// This builder contains some confidential information that is passed to the Pkcs11Provider. The
/// Pkcs11Provider will zeroize this data when dropping. This data will not be cloned when
/// building.
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    provider_name: Option<String>,
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
    pkcs11_library_path: Option<String>,
    slot_number: Option<u64>,
    serial_number: Option<String>,
    user_pin: Option<SecretString>,
    software_public_operations: Option<bool>,
    allow_export: Option<bool>,
}

impl ProviderBuilder {
    /// Create a new Pkcs11Provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            provider_name: None,
            key_info_store: None,
            pkcs11_library_path: None,
            slot_number: None,
            serial_number: None,
            user_pin: None,
            software_public_operations: None,
            allow_export: None,
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

    /// Specify the path of the PKCS11 library
    pub fn with_pkcs11_library_path(mut self, pkcs11_library_path: String) -> ProviderBuilder {
        self.pkcs11_library_path = Some(pkcs11_library_path);

        self
    }

    /// Specify the slot number used
    pub fn with_slot_number(mut self, slot_number: Option<u64>) -> ProviderBuilder {
        self.slot_number = slot_number;

        self
    }

    /// Specify the token serial number used
    pub fn with_serial_number(mut self, serial_number: Option<String>) -> ProviderBuilder {
        self.serial_number = serial_number;
        self
    }

    /// Specify the user pin
    pub fn with_user_pin(mut self, mut user_pin: Option<String>) -> ProviderBuilder {
        self.user_pin = match user_pin {
            // The conversion form a String is infallible.
            Some(ref pin) => Some(SecretString::from_str(&pin).unwrap()),
            None => None,
        };
        user_pin.zeroize();

        self
    }

    /// Specify the `software_public_operations` flag
    pub fn with_software_public_operations(
        mut self,
        software_public_operations: Option<bool>,
    ) -> ProviderBuilder {
        self.software_public_operations = software_public_operations;

        self
    }

    /// Specify the `allow_export` flag
    pub fn with_allow_export(mut self, allow_export: Option<bool>) -> ProviderBuilder {
        self.allow_export = allow_export;

        self
    }

    /// Attempt to build a PKCS11 provider
    pub fn build(self) -> std::io::Result<Provider> {
        let library_path = self
            .pkcs11_library_path
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing library path"))?;
        info!(
            "Building a PKCS 11 provider with library \'{}\'",
            library_path
        );

        let backend = Pkcs11::new(library_path).map_err(|e| {
            format_error!("Error creating a PKCS 11 context", e);
            Error::new(ErrorKind::InvalidData, "error creating PKCS 11 context")
        })?;
        trace!("Initialize command");
        backend
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| {
                format_error!("Error initializing PKCS 11 context", e);
                Error::new(ErrorKind::InvalidData, "error initializing PKCS 11 context")
            })?;

        let slots = backend.get_slots_with_initialized_token().map_err(|e| {
            format_error!(
                "Failed retrieving a valid slot with an initialized token",
                e
            );
            Error::new(
                ErrorKind::InvalidData,
                "Failed retrieving a valid slot with an initialized token",
            )
        })?;
        let slot_number = match (self.serial_number, self.slot_number) {
            (Some(serial_number), given_slot) => {
                let mut slot = None;
                for current_slot in slots {
                    let current_token = backend.get_token_info(current_slot).map_err(|e| {
                        format_error!("Failed parsing token info", e);
                        Error::new(ErrorKind::InvalidData, "Failed parsing token info")
                    })?;
                    let sn = String::from_utf8(current_token.serial_number().as_bytes().to_vec())
                        .map_err(|e| {
                        format_error!("Failed parsing token serial number", e);
                        Error::new(ErrorKind::InvalidData, "Failed parsing token serial number")
                    })?;
                    if sn.trim() == serial_number.trim() {
                        slot = Some(current_slot);
                        break;
                    }
                }
                match slot {
                    Some(slot) => {
                        if let Some(slot_number) = given_slot {
                            if slot.id() != slot_number {
                                warn!("Provided slot number mismatch!");
                                warn!("Token is attached to slot {}", slot.id())
                            }
                        }
                        slot
                    }
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "No token with the provided serial number",
                        ))
                    }
                }
            }
            (None, Some(slot_number)) => {
                let slot = Slot::try_from(slot_number).or_else(|_| {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "cannot convert slot value",
                    ))
                })?;
                if !slots.contains(&slot) {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "No available slot with the given number",
                    ));
                }
                warn!(
                    "Slot number {} will be used. However, It is preferred to use serial_number as the slot number might change during replug or OS reboot.",
                    slot_number
                );
                slot
            }
            (None, None) => {
                if slots.len() == 1 {
                    slots[0]
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "missing slot number or more than one initialized",
                    ));
                }
            }
        };

        Ok(Provider::new(
            self.provider_name
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing provider name"))?,
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            backend,
            slot_number,
            self.user_pin,
            self.software_public_operations.unwrap_or(false),
            self.allow_export.unwrap_or(true),
        )
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "PKCS 11 initialization failed"))?)
    }
}
