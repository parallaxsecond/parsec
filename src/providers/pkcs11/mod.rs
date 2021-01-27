// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS 11 provider
//!
//! This provider allows clients to access any PKCS 11 compliant device
//! through the Parsec interface.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use derivative::Derivative;
use log::{error, info, trace, warn};
use parsec_interface::operations::{list_clients, list_keys, list_providers::ProviderInfo};
use parsec_interface::operations::{
    psa_asymmetric_decrypt, psa_asymmetric_encrypt, psa_destroy_key, psa_export_public_key,
    psa_generate_key, psa_import_key, psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use parsec_interface::secrecy::SecretString;
use pkcs11::types::{CKF_OS_LOCKING_OK, CK_C_INITIALIZE_ARGS, CK_SLOT_ID};
use pkcs11::Ctx;
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use utils::{KeyPairType, ReadWriteSession, Session};
use uuid::Uuid;
use zeroize::Zeroize;

type LocalIdStore = HashSet<[u8; 4]>;

mod asym_encryption;
mod asym_sign;
mod key_management;
mod key_metadata;
mod utils;

const SUPPORTED_OPCODES: [Opcode; 8] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaAsymmetricDecrypt,
    Opcode::PsaAsymmetricEncrypt,
];

/// Provider for Public Key Cryptography Standard #11
///
/// Operations for this provider are serviced through a PKCS11 interface,
/// allowing any libraries exposing said interface to be loaded and used
/// at runtime.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    #[derivative(Debug = "ignore")]
    key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    local_ids: RwLock<LocalIdStore>,
    // The authentication state is common to all sessions. A counter of logged in sessions is used
    // to keep track of current logged in sessions, ignore logging in if the user is already
    // logged in and only log out when no other session is.
    // The mutex is both used to have interior mutability on the counter and to create a critical
    // section inside login/logout functions. The clippy warning is ignored here to not have one
    // Mutex<()> and an AtomicUsize which would make the code more complicated. Maybe a better
    // way exists.
    #[allow(clippy::mutex_atomic)]
    logged_sessions_counter: Mutex<usize>,
    backend: Ctx,
    slot_number: CK_SLOT_ID,
    // Some PKCS 11 devices do not need a pin, the None variant means that.
    user_pin: Option<SecretString>,
    software_public_operations: bool,
}

impl Provider {
    /// Creates and initialise a new instance of Pkcs11Provider.
    /// Checks if there are not more keys stored in the Key Info Manager than in the PKCS 11 library
    /// and if there are, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
        backend: Ctx,
        slot_number: usize,
        user_pin: Option<SecretString>,
        software_public_operations: bool,
    ) -> Option<Provider> {
        #[allow(clippy::mutex_atomic)]
        let pkcs11_provider = Provider {
            key_info_store,
            local_ids: RwLock::new(HashSet::new()),
            logged_sessions_counter: Mutex::new(0),
            backend,
            slot_number: slot_number as CK_SLOT_ID,
            user_pin,
            software_public_operations,
        };
        {
            // The local scope allows to drop store_handle and local_ids_handle in order to return
            // the pkcs11_provider.
            let locks = pkcs11_provider.get_ordered_locks();
            let mut store_handle = locks.0.write().expect("Key store lock poisoned");
            let mut local_ids_handle = locks.1.write().expect("Local ID lock poisoned");
            let mut to_remove: Vec<KeyTriple> = Vec::new();
            // Go through all PKCS 11 key triple to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match store_handle.get_all(ProviderID::Pkcs11) {
                Ok(key_triples) => {
                    let session =
                        Session::new(&pkcs11_provider, ReadWriteSession::ReadOnly).ok()?;

                    for key_triple in key_triples.iter().cloned() {
                        let key_info = if let Ok(Some(info)) = store_handle.get(key_triple) {
                            info
                        } else {
                            error!("Key triple unexpectedly missing from store.");
                            continue;
                        };
                        let mut key_id = [0; 4];
                        if key_info.id.len() == 4 {
                            key_id.copy_from_slice(&key_info.id);
                        } else {
                            if crate::utils::GlobalConfig::log_error_details() {
                                error!(
                                    "Invalid key ID (value: {:?}) for triple:\n{}\n, continuing...",
                                    key_info.id, key_triple
                                );
                            } else {
                                error!("Found invalid key ID, continuing...");
                            }
                            continue;
                        }

                        match pkcs11_provider.find_key(
                            session.session_handle(),
                            key_id,
                            KeyPairType::Any,
                        ) {
                            Ok(_) => {
                                if crate::utils::GlobalConfig::log_error_details() {
                                    warn!(
                                        "Key {} found in the PKCS 11 library, adding it.",
                                        key_triple
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
                                        key_triple
                                    );
                                } else {
                                    warn!("Key not found in the PKCS 11 library, adding it.");
                                }
                                to_remove.push(key_triple.clone());
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
            for key_triple in to_remove.iter() {
                if let Err(string) = store_handle.remove(key_triple) {
                    format_error!("Key Info Manager error", string);
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
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((
            ProviderInfo {
                // Assigned UUID for this provider: 30e39502-eba6-4d60-a4af-c518b7f5e38f
                uuid: Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f")
                    .or(Err(ResponseStatus::InvalidEncoding))?,
                description: String::from(
                    "PKCS #11 provider, interfacing with a PKCS #11 library.",
                ),
                vendor: String::from("OASIS Standard."),
                version_maj: 0,
                version_min: 1,
                version_rev: 0,
                id: ProviderID::Pkcs11,
            },
            SUPPORTED_OPCODES.iter().copied().collect(),
        ))
    }

    fn list_keys(
        &self,
        app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        Ok(list_keys::Result {
            keys: store_handle
                .list_keys(&app_name, ProviderID::Pkcs11)
                .map_err(|e| {
                    format_error!("Error occurred when fetching key information", e);
                    ResponseStatus::KeyInfoManagerError
                })?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        Ok(list_clients::Result {
            clients: store_handle
                .list_clients(ProviderID::Pkcs11)
                .map_err(|e| {
                    format_error!("Error occurred when fetching key information", e);
                    ResponseStatus::KeyInfoManagerError
                })?
                .into_iter()
                .map(|app_name| app_name.to_string())
                .collect(),
        })
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(app_name, op)
    }

    fn psa_import_key(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        self.psa_import_key_internal(app_name, op)
    }

    fn psa_export_public_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        self.psa_export_public_key_internal(app_name, op)
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(app_name, op)
    }

    fn psa_sign_hash(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        self.psa_sign_hash_internal(app_name, op)
    }

    fn psa_verify_hash(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        if self.software_public_operations {
            trace!("software_psa_verify_hash ingress");
            self.software_psa_verify_hash_internal(app_name, op)
        } else {
            trace!("pkcs11_psa_verify_hash ingress");
            self.psa_verify_hash_internal(app_name, op)
        }
    }

    fn psa_asymmetric_encrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        if self.software_public_operations {
            trace!("software_psa_asymmetric_encrypt ingress");
            self.software_psa_asymmetric_encrypt_internal(app_name, op)
        } else {
            trace!("psa_asymmetric_encrypt ingress");
            self.psa_asymmetric_encrypt_internal(app_name, op)
        }
    }

    fn psa_asymmetric_decrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(app_name, op)
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        trace!("Finalize command");
        if let Err(e) = self.backend.finalize() {
            format_error!("Error when dropping the PKCS 11 provider", e);
        }
        // The other fields containing confidential information should implement zeroizing on drop.
        self.slot_number.zeroize();
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
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
    pkcs11_library_path: Option<String>,
    slot_number: Option<usize>,
    user_pin: Option<SecretString>,
    software_public_operations: Option<bool>,
}

impl ProviderBuilder {
    /// Create a new Pkcs11Provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
            pkcs11_library_path: None,
            slot_number: None,
            user_pin: None,
            software_public_operations: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(
        mut self,
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the path of the PKCS11 library
    pub fn with_pkcs11_library_path(mut self, pkcs11_library_path: String) -> ProviderBuilder {
        self.pkcs11_library_path = Some(pkcs11_library_path);

        self
    }

    /// Specify the slot number used
    pub fn with_slot_number(mut self, slot_number: usize) -> ProviderBuilder {
        self.slot_number = Some(slot_number);

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

    /// Attempt to build a PKCS11 provider
    pub fn build(self) -> std::io::Result<Provider> {
        let library_path = self
            .pkcs11_library_path
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing library path"))?;
        info!(
            "Building a PKCS 11 provider with library \'{}\'",
            library_path
        );
        let slot_number = self
            .slot_number
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing slot number"))?;
        let mut backend = Ctx::new(library_path).map_err(|e| {
            format_error!("Error creating a PKCS 11 context", e);
            Error::new(ErrorKind::InvalidData, "error creating PKCS 11 context")
        })?;
        let mut args = CK_C_INITIALIZE_ARGS::new();
        // Allow the PKCS 11 library to use OS native locking mechanism.
        args.CreateMutex = None;
        args.DestroyMutex = None;
        args.LockMutex = None;
        args.UnlockMutex = None;
        args.flags = CKF_OS_LOCKING_OK;
        trace!("Initialize command");
        backend.initialize(Some(args)).map_err(|e| {
            format_error!("Error initializing the PKCS 11 backend", e);
            Error::new(
                ErrorKind::InvalidData,
                "PKCS 11 backend initializing failed",
            )
        })?;
        Ok(Provider::new(
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            backend,
            slot_number,
            self.user_pin,
            self.software_public_operations.unwrap_or(false),
        )
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "PKCS 11 initialization failed"))?)
    }
}
