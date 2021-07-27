// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Mbed Crypto provider
//!
//! This provider is a software based implementation of PSA Crypto, Mbed Crypto.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::{KeyInfoManagerClient, KeyTriple};
use derivative::Derivative;
use log::{error, trace};
use parsec_interface::operations::{list_clients, list_keys, list_providers::ProviderInfo};
use parsec_interface::operations::{
    psa_aead_decrypt, psa_aead_encrypt, psa_asymmetric_decrypt, psa_asymmetric_encrypt,
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_generate_random,
    psa_hash_compare, psa_hash_compute, psa_import_key, psa_raw_key_agreement, psa_sign_hash,
    psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use psa_crypto::types::{key, status};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::sync::{
    atomic::{AtomicU32, Ordering::Relaxed},
    Mutex,
};
use uuid::Uuid;

mod aead;
mod asym_encryption;
mod asym_sign;
mod generate_random;
mod hash;
mod key_agreement;
pub(super) mod key_management;

const SUPPORTED_OPCODES: [Opcode; 15] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaAsymmetricDecrypt,
    Opcode::PsaAsymmetricEncrypt,
    Opcode::PsaAeadEncrypt,
    Opcode::PsaAeadDecrypt,
    Opcode::PsaHashCompare,
    Opcode::PsaHashCompute,
    Opcode::PsaRawKeyAgreement,
    Opcode::PsaGenerateRandom,
];

/// Mbed Crypto provider structure
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    // The name of the provider set in the config.
    provider_name: String,

    // When calling write on a reference of key_info_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyInfo + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyInfo + Send + Sync and then
    // reference it to match with the method prototypes.
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
    // Calls to `psa_open_key`, `psa_generate_key` and `psa_destroy_key` are not thread safe - the slot
    // allocation mechanism in Mbed Crypto can return the same key slot for overlapping calls.
    // `key_handle_mutex` is use as a way of securing access to said operations among the threads.
    // This issue tracks progress on fixing the original problem in Mbed Crypto:
    // https://github.com/ARMmbed/mbed-crypto/issues/266
    key_handle_mutex: Mutex<()>,

    // Holds the highest ID of all keys (including destroyed keys). New keys will receive an ID of
    // id_counter + 1. Once id_counter reaches the highest allowed ID, no more keys can be created.
    id_counter: AtomicU32,
}

impl Provider {
    /// The default provider name for mbed-crypto provider
    pub const DEFAULT_PROVIDER_NAME: &'static str = "mbed-crypto-provider";

    /// The UUID for this provider
    pub const PROVIDER_UUID: &'static str = "1c1139dc-ad7c-47dc-ad6b-db6fdb466552";

    /// Creates and initialise a new instance of MbedCryptoProvider.
    /// Checks if there are not more keys stored in the Key Info Manager than in the MbedCryptoProvider and
    /// if there, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    fn new(provider_name: String, key_info_store: KeyInfoManagerClient) -> Option<Provider> {
        // Safety: this function should be called before any of the other Mbed Crypto functions
        // are.
        if let Err(error) = psa_crypto::init() {
            format_error!("Error when initialising Mbed Crypto", error);
            return None;
        }
        let mbed_crypto_provider = Provider {
            provider_name,
            key_info_store,
            key_handle_mutex: Mutex::new(()),
            id_counter: AtomicU32::new(key::PSA_KEY_ID_USER_MIN),
        };
        let mut max_key_id: key::psa_key_id_t = key::PSA_KEY_ID_USER_MIN;
        {
            let mut to_remove: Vec<KeyTriple> = Vec::new();
            // Go through all MbedCryptoProvider key triple to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match mbed_crypto_provider.key_info_store.get_all() {
                Ok(key_triples) => {
                    for key_triple in key_triples.iter().cloned() {
                        let key_id = match mbed_crypto_provider
                            .key_info_store
                            .get_key_id(&key_triple)
                        {
                            Ok(key_id) => key_id,
                            Err(response_status) => {
                                error!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...", key_triple, response_status);
                                to_remove.push(key_triple.clone());
                                continue;
                            }
                        };

                        match key::Id::from_persistent_key_id(key_id) {
                            Ok(_) => {
                                if key_id > max_key_id {
                                    max_key_id = key_id;
                                }
                            }
                            Err(status::Error::DoesNotExist) => to_remove.push(key_triple.clone()),
                            Err(e) => {
                                format_error!("Failed to open persistent Mbed Crypto key", e);
                                return None;
                            }
                        };
                    }
                }
                Err(_) => {
                    return None;
                }
            };
            for key_triple in to_remove.iter() {
                if mbed_crypto_provider
                    .key_info_store
                    .remove_key_info(key_triple)
                    .is_err()
                {
                    return None;
                }
            }
        }
        mbed_crypto_provider.id_counter.store(max_key_id, Relaxed);
        Some(mbed_crypto_provider)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: 1c1139dc-ad7c-47dc-ad6b-db6fdb466552
            uuid: Uuid::parse_str(Provider::PROVIDER_UUID).or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("User space software provider, based on Mbed Crypto - the reference implementation of the PSA crypto API"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderId::MbedCrypto,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }

    fn list_keys(
        &self,
        app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");
        Ok(list_keys::Result {
            keys: self.key_info_store.list_keys(&app_name)?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");
        Ok(list_clients::Result {
            clients: self
                .key_info_store
                .list_clients()?
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

    fn psa_export_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        trace!("psa_export_key ingress");
        self.psa_export_key_internal(app_name, op)
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
        trace!("psa_verify_hash ingress");
        self.psa_verify_hash_internal(app_name, op)
    }

    fn psa_asymmetric_encrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        trace!("psa_asymmetric_encrypt ingress");
        self.psa_asymmetric_encrypt_internal(app_name, op)
    }

    fn psa_asymmetric_decrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(app_name, op)
    }

    fn psa_aead_encrypt(
        &self,
        app_name: ApplicationName,
        op: psa_aead_encrypt::Operation,
    ) -> Result<psa_aead_encrypt::Result> {
        trace!("psa_aead_encrypt ingress");
        self.psa_aead_encrypt_internal(app_name, op)
    }

    fn psa_aead_decrypt(
        &self,
        app_name: ApplicationName,
        op: psa_aead_decrypt::Operation,
    ) -> Result<psa_aead_decrypt::Result> {
        trace!("psa_aead_decrypt ingress");
        self.psa_aead_decrypt_internal(app_name, op)
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

    fn psa_raw_key_agreement(
        &self,
        app_name: ApplicationName,
        op: psa_raw_key_agreement::Operation,
    ) -> Result<psa_raw_key_agreement::Result> {
        trace!("psa_raw_key_agreement ingress");
        self.psa_raw_key_agreement(app_name, op)
    }

    fn psa_generate_random(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        self.psa_generate_random_internal(op)
    }
}

/// Mbed Crypto provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    provider_name: Option<String>,
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
}

impl ProviderBuilder {
    /// Create a new provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            provider_name: None,
            key_info_store: None,
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

    /// Build into a MbedProvider
    pub fn build(self) -> std::io::Result<Provider> {
        Provider::new(
            self.provider_name.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing provider name")
            })?,
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "MbedCrypto Provider initialization failed",
            )
        })
    }
}
