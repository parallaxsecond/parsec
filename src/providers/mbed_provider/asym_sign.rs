// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::constants::PSA_SUCCESS;
use super::utils::{self, KeyHandle};
use super::{key_management, psa_crypto_binding, MbedProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{error, info};
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, Result};

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

        let mut key_handle;
        let mut key_attrs;
        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        unsafe {
            key_handle = KeyHandle::open(key_id)?;
            key_attrs = key_handle.attributes()?;
        }

        let buffer_size = utils::psa_asymmetric_sign_output_size(key_attrs.as_ref())?;
        let mut signature = vec![0u8; buffer_size];
        let mut signature_size = 0;

        let sign_status;
        // Safety: same conditions than above.
        unsafe {
            sign_status = psa_crypto_binding::psa_asymmetric_sign(
                key_handle.raw(),
                utils::convert_algorithm(&alg.into())?,
                hash.as_ptr(),
                hash.len() as u64,
                signature.as_mut_ptr(),
                buffer_size as u64,
                &mut signature_size,
            );
            key_attrs.reset();
            key_handle.close()?;
        };

        if sign_status == PSA_SUCCESS {
            let mut res = psa_sign_hash::Result {
                signature: Vec::new(),
            };
            res.signature.resize(signature_size as usize, 0);
            res.signature
                .copy_from_slice(&signature[0..signature_size as usize]);

            Ok(res)
        } else {
            error!("Sign status: {}", sign_status);
            Err(utils::convert_status(sign_status))
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

        let mut key_handle;
        let mut key_attrs;
        let verify_status;
        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        unsafe {
            key_handle = KeyHandle::open(key_id)?;
            key_attrs = key_handle.attributes()?;
            verify_status = psa_crypto_binding::psa_asymmetric_verify(
                key_handle.raw(),
                utils::convert_algorithm(&alg.into())?,
                hash.as_ptr(),
                hash.len() as u64,
                signature.as_ptr(),
                signature.len() as u64,
            );
            key_attrs.reset();
            key_handle.close()?;
        }

        if verify_status == PSA_SUCCESS {
            Ok(psa_verify_hash::Result {})
        } else {
            Err(utils::convert_status(verify_status))
        }
    }
}
