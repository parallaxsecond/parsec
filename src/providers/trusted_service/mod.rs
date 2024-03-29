// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Trusted Service provider
//!
//! This provider is backed by a crypto Trusted Service deployed in TrustZone
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::{KeyIdentity, KeyInfoManagerClient};
use crate::providers::crypto_capability::CanDoCrypto;
use crate::providers::{Provide, ProviderIdentity};
use context::Context;
use derivative::Derivative;
use log::{error, trace};
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::list_providers::Uuid;
use parsec_interface::operations::{
    can_do_crypto, list_clients, list_keys, psa_asymmetric_decrypt, psa_asymmetric_encrypt,
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_generate_random,
    psa_import_key, psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderId, Result};
use psa_crypto::types::key;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};

mod asym_encryption;
mod asym_sign;
mod capability_discovery;
mod context;
mod error;
mod generate_random;
mod key_management;

const SUPPORTED_OPCODES: [Opcode; 11] = [
    Opcode::PsaDestroyKey,
    Opcode::PsaGenerateKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaExportKey,
    Opcode::PsaGenerateRandom,
    Opcode::CanDoCrypto,
    Opcode::PsaAsymmetricEncrypt,
    Opcode::PsaAsymmetricDecrypt,
];
/// Trusted Service provider structure
///
/// Operations for this provider are serviced through an IPC interface that leads
/// to a Secure World implementation of PSA Crypto.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    // The identity of the provider including uuid & name.
    provider_identity: ProviderIdentity,

    context: Context,
    // When calling write on a reference of key_info_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyInfo + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyInfo + Send + Sync and then
    // reference it to match with the method prototypes.
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,

    // Holds the highest ID of all keys (including destroyed keys). New keys will receive an ID of
    // id_counter + 1. Once id_counter reaches the highest allowed ID, no more keys can be created.
    id_counter: AtomicU32,
}

impl Provider {
    /// The default provider name for trusted service provider
    pub const DEFAULT_PROVIDER_NAME: &'static str = "trusted-service-provider";

    /// The UUID for this provider
    pub const PROVIDER_UUID: &'static str = "71129441-508a-4da6-b6e8-7b98a777e4c0";

    /// Creates and initialises a new instance of Provider.
    fn new(
        provider_name: String,
        key_info_store: KeyInfoManagerClient,
    ) -> anyhow::Result<Provider> {
        let ts_provider = Provider {
            provider_identity: ProviderIdentity {
                name: provider_name,
                uuid: String::from(Self::PROVIDER_UUID),
            },
            key_info_store,
            context: Context::connect()?,
            id_counter: AtomicU32::new(key::PSA_KEY_ID_USER_MIN),
        };
        let mut max_key_id: key::psa_key_id_t = key::PSA_KEY_ID_USER_MIN;
        {
            let mut to_remove: Vec<KeyIdentity> = Vec::new();
            // Go through all TrustedServiceProvider key identities to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match ts_provider.key_info_store.get_all() {
                Ok(key_identities) => {
                    for key_identity in key_identities.iter() {
                        let key_id = match ts_provider.key_info_store.get_key_id(key_identity) {
                            Ok(key_id) => key_id,
                            Err(response_status) => {
                                error!("Error getting the Key ID for KeyIdentity:\n{}\n(error: {}), continuing...", key_identity, response_status);
                                to_remove.push(key_identity.clone());
                                continue;
                            }
                        };

                        if key_id > max_key_id {
                            max_key_id = key_id;
                        }
                    }
                }
                Err(string) => {
                    error!("Key Info Manager error when obtaining handles: {}", string);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, string).into());
                }
            };
            for key_identity in to_remove.iter() {
                if let Err(string) = ts_provider.key_info_store.remove_key_info(key_identity) {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, string).into());
                }
            }
        }
        ts_provider.id_counter.store(max_key_id, Ordering::Relaxed);
        Ok(ts_provider)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: 71129441-508a-4da6-b6e8-7b98a777e4c0
            uuid: Uuid::parse_str(Provider::PROVIDER_UUID)?,
            description: String::from("Provider exposing functionality provided by the Crypto Trusted Service running in a Trusted Execution Environment"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderId::TrustedService,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
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

    fn psa_generate_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(application_identity, op)
    }

    fn psa_destroy_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(application_identity, op)
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

    fn psa_export_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        trace!("psa_export_key ingress");
        self.psa_export_key_internal(application_identity, op)
    }

    fn psa_generate_random(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        self.psa_generate_random_internal(op)
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
        trace!("psa_verify_hash ingress");
        self.psa_verify_hash_internal(application_identity, op)
    }

    fn can_do_crypto(
        &self,
        application_identity: &ApplicationIdentity,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto ingress");
        self.can_do_crypto_main(application_identity, op)
    }

    fn psa_asymmetric_encrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        trace!("psa_asymmetric_encrypt ingress");
        self.psa_asymmetric_encrypt_internal(application_identity, op)
    }

    fn psa_asymmetric_decrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(application_identity, op)
    }
}

/// Trusted Service provider builder
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

    /// Build into a TrustedService
    pub fn build(self) -> anyhow::Result<Provider> {
        Provider::new(
            self.provider_name.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing provider name")
            })?,
            self.key_info_store.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing key info store")
            })?,
        )
    }
}
