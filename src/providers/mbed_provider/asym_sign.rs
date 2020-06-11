// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils;
use super::{key_management, MbedProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{error, info};
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use psa_crypto::operations::key_management as new_key_management;
use psa_crypto::operations::asym_signature;
use psa_crypto::types::key;

#[allow(unused)]
impl MbedProvider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        info!("Mbed Provider - Asym Sign");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots

        let id = key::Id::from_persistent_key_id(key_id);
        let key_attributes = new_key_management::get_key_attributes(id)?;
        let buffer_size = utils::psa_asymmetric_sign_output_size(&key_attributes)?;
        let mut signature = vec![0u8; buffer_size];
        let mut signature_size = 0;

        match asym_signature::sign_hash(id, alg, &hash, &mut signature)
            {
            Ok(size) => {
                let mut res = psa_sign_hash::Result {
                    signature: Vec::new(),
                };
                res.signature.resize(size, 0);
                res.signature
                    .copy_from_slice(&signature[0..size]);
                Ok(res)
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                error!("Sign status: {}", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        info!("Mbed Provider - Asym Verify");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let signature = op.signature;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let id = key::Id::from_persistent_key_id(key_id);
        match asym_signature::verify_hash(id, alg, &hash, &signature) {
            Ok(()) => Ok(psa_verify_hash::Result {}),
            Err(error) => {
                let error = ResponseStatus::from(error);
                error!("Verify status: {}", error);
                Err(error)
            }
        }
    }
}
