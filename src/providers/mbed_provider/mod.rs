// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_id_managers::{KeyTriple, ManageKeyIDs};
use constants::PSA_SUCCESS;
use derivative::Derivative;
use log::{error, info, warn};
use parsec_interface::operations::ProviderInfo;
use parsec_interface::operations::{OpAsymSign, ResultAsymSign};
use parsec_interface::operations::{OpAsymVerify, ResultAsymVerify};
use parsec_interface::operations::{OpCreateKey, ResultCreateKey};
use parsec_interface::operations::{OpDestroyKey, ResultDestroyKey};
use parsec_interface::operations::{OpExportPublicKey, ResultExportPublicKey};
use parsec_interface::operations::{OpImportKey, ResultImportKey};
use parsec_interface::operations::{OpListOpcodes, ResultListOpcodes};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use psa_crypto_binding::psa_key_id_t;
use std::collections::HashSet;
use std::convert::TryInto;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, RwLock};
use std_semaphore::Semaphore;
use utils::KeyHandle;
use uuid::Uuid;

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    trivial_casts
)]
#[allow(clippy::all)]
mod psa_crypto_binding {
    include!(concat!(env!("OUT_DIR"), "/psa_crypto_bindings.rs"));
}

#[allow(dead_code)]
mod constants;
mod utils;

type LocalIdStore = HashSet<psa_key_id_t>;

const SUPPORTED_OPCODES: [Opcode; 7] = [
    Opcode::CreateKey,
    Opcode::DestroyKey,
    Opcode::AsymSign,
    Opcode::AsymVerify,
    Opcode::ImportKey,
    Opcode::ExportPublicKey,
    Opcode::ListOpcodes,
];

#[derive(Derivative)]
#[derivative(Debug)]
pub struct MbedProvider {
    // When calling write on a reference of key_id_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyIDs + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyIDs + Send + Sync and then
    // reference it to match with the method prototypes.
    #[derivative(Debug = "ignore")]
    key_id_store: Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>,
    local_ids: RwLock<LocalIdStore>,
    // Calls to `psa_open_key`, `psa_create_key` and `psa_close_key` are not thread safe - the slot
    // allocation mechanism in Mbed Crypto can return the same key slot for overlapping calls.
    // `key_handle_mutex` is use as a way of securing access to said operations among the threads.
    // This issue tracks progress on fixing the original problem in Mbed Crypto:
    // https://github.com/ARMmbed/mbed-crypto/issues/266
    key_handle_mutex: Mutex<()>,
    // As mentioned above, calls dealing with key slot allocation are not secured for concurrency.
    // `key_slot_semaphore` is used to ensure that only `PSA_KEY_SLOT_COUNT` threads can have slots
    // assigned at any time.
    #[derivative(Debug = "ignore")]
    key_slot_semaphore: Semaphore,
}

/// Gets a PSA Key ID from the Key ID Manager.
/// Wrapper around the get method of the Key ID Manager to convert the key ID to the psa_key_id_t
/// type.
fn get_key_id(key_triple: &KeyTriple, store_handle: &dyn ManageKeyIDs) -> Result<psa_key_id_t> {
    match store_handle.get(key_triple) {
        Ok(Some(key_id)) => {
            if let Ok(key_id_bytes) = key_id.try_into() {
                Ok(u32::from_ne_bytes(key_id_bytes))
            } else {
                error!("Stored Key ID is not valid.");
                Err(ResponseStatus::KeyIDManagerError)
            }
        }
        Ok(None) => Err(ResponseStatus::KeyDoesNotExist),
        Err(string) => {
            error!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

/// Creates a new PSA Key ID and stores it in the Key ID Manager.
fn create_key_id(
    key_triple: KeyTriple,
    store_handle: &mut dyn ManageKeyIDs,
    local_ids_handle: &mut LocalIdStore,
) -> Result<psa_key_id_t> {
    let mut key_id = rand::random::<psa_key_id_t>();
    while local_ids_handle.contains(&key_id)
        || key_id == 0
        || key_id > constants::PSA_MAX_PERSISTENT_KEY_IDENTIFIER
    {
        key_id = rand::random::<psa_key_id_t>();
    }
    match store_handle.insert(key_triple.clone(), key_id.to_ne_bytes().to_vec()) {
        Ok(insert_option) => {
            if insert_option.is_some() {
                warn!("Overwriting Key triple mapping ({})", key_triple);
            }
            let _ = local_ids_handle.insert(key_id);

            Ok(key_id)
        }
        Err(string) => {
            error!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

fn remove_key_id(
    key_triple: &KeyTriple,
    key_id: psa_key_id_t,
    store_handle: &mut dyn ManageKeyIDs,
    local_ids_handle: &mut LocalIdStore,
) -> Result<()> {
    match store_handle.remove(key_triple) {
        Ok(_) => {
            let _ = local_ids_handle.remove(&key_id);
            Ok(())
        }
        Err(string) => {
            error!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

fn key_id_exists(key_triple: &KeyTriple, store_handle: &dyn ManageKeyIDs) -> Result<bool> {
    match store_handle.exists(key_triple) {
        Ok(val) => Ok(val),
        Err(string) => {
            error!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

impl MbedProvider {
    /// Creates and initialise a new instance of MbedProvider.
    /// Checks if there are not more keys stored in the Key ID Manager than in the MbedProvider and
    /// if there, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    fn new(key_id_store: Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>) -> Option<MbedProvider> {
        // Safety: this function should be called before any of the other Mbed Crypto functions
        // are.
        if unsafe { psa_crypto_binding::psa_crypto_init() } != PSA_SUCCESS {
            error!("Error when initialising Mbed Crypto");
            return None;
        }
        let mbed_provider = MbedProvider {
            key_id_store,
            local_ids: RwLock::new(HashSet::new()),
            key_handle_mutex: Mutex::new(()),
            key_slot_semaphore: Semaphore::new(constants::PSA_KEY_SLOT_COUNT),
        };
        {
            // The local scope allows to drop store_handle and local_ids_handle in order to return
            // the mbed_provider.
            let mut store_handle = mbed_provider
                .key_id_store
                .write()
                .expect("Key store lock poisoned");
            let mut local_ids_handle = mbed_provider
                .local_ids
                .write()
                .expect("Local ID lock poisoned");
            let mut to_remove: Vec<KeyTriple> = Vec::new();
            // Go through all MbedProvider key triple to key ID mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match store_handle.get_all(ProviderID::MbedProvider) {
                Ok(key_triples) => {
                    for key_triple in key_triples.iter().cloned() {
                        let key_id = match get_key_id(key_triple, &*store_handle) {
                            Ok(key_id) => key_id,
                            Err(response_status) => {
                                error!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...", key_triple, response_status);
                                to_remove.push(key_triple.clone());
                                continue;
                            }
                        };

                        // Safety: safe because:
                        // * the Mbed Crypto library has been initialized
                        // * this code is executed only by the main thread
                        match unsafe { KeyHandle::open(key_id) } {
                            Ok(_) => {
                                let _ = local_ids_handle.insert(key_id);
                            }
                            Err(ResponseStatus::PsaErrorDoesNotExist) => {
                                to_remove.push(key_triple.clone())
                            }
                            Err(e) => {
                                error!("Error {} when opening a persistent Mbed Crypto key.", e);
                                return None;
                            }
                        };
                    }
                }
                Err(string) => {
                    error!("Key ID Manager error: {}", string);
                    return None;
                }
            };
            for key_triple in to_remove.iter() {
                if let Err(string) = store_handle.remove(key_triple) {
                    error!("Key ID Manager error: {}", string);
                    return None;
                }
            }
        }

        Some(mbed_provider)
    }
}

impl Provide for MbedProvider {
    fn list_opcodes(&self, _op: OpListOpcodes) -> Result<ResultListOpcodes> {
        Ok(ResultListOpcodes {
            opcodes: SUPPORTED_OPCODES.iter().copied().collect(),
        })
    }

    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            // Assigned UUID for this provider: 1c1139dc-ad7c-47dc-ad6b-db6fdb466552
            uuid: Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(),
            description: String::from("User space software provider, based on Mbed Crypto - the reference implementation of the PSA crypto API"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::MbedProvider,
        }
    }

    fn create_key(&self, app_name: ApplicationName, op: OpCreateKey) -> Result<ResultCreateKey> {
        info!("Mbed Provider - Create Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_attributes = op.key_attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_id_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::KeyAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let key_attrs = utils::convert_key_attributes(&key_attributes, key_id)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let mut key_handle = unsafe { KeyHandle::generate(&key_attrs) }.or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Generate key status: {}", e);
            Err(e)
        })?;

        // Safety: same conditions than above.
        unsafe {
            key_handle.close()?;
        }

        Ok(ResultCreateKey {})
    }

    fn import_key(&self, app_name: ApplicationName, op: OpImportKey) -> Result<ResultImportKey> {
        info!("Mbed Provider - Import Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_attributes = op.key_attributes;
        let key_data = op.key_data;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_id_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::KeyAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let key_attrs = utils::convert_key_attributes(&key_attributes, key_id)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let mut key_handle = unsafe { KeyHandle::import(&key_attrs, key_data) }.or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Import key status: {}", e);
            Err(e)
        })?;

        // Safety: same conditions than above.
        unsafe {
            key_handle.close()?;
        }

        Ok(ResultImportKey {})
    }

    fn export_public_key(
        &self,
        app_name: ApplicationName,
        op: OpExportPublicKey,
    ) -> Result<ResultExportPublicKey> {
        info!("Mbed Provider - Export Public Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

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

        let buffer_size = utils::psa_export_public_key_size(key_attrs.as_ref())?;
        let mut buffer = vec![0u8; buffer_size];
        let mut actual_size = 0;

        let export_status;
        // Safety: same conditions than above.
        unsafe {
            export_status = psa_crypto_binding::psa_export_public_key(
                key_handle.raw(),
                buffer.as_mut_ptr(),
                buffer_size,
                &mut actual_size,
            );
            key_attrs.reset();
            key_handle.close()?;
        };

        if export_status != PSA_SUCCESS {
            error!("Export status: {}", export_status);
            // Safety: same conditions than above.
            return Err(utils::convert_status(export_status).ok_or_else(|| {
                error!("Failed to convert error status.");
                ResponseStatus::PsaErrorGenericError
            })?);
        }

        buffer.resize(actual_size, 0);
        Ok(ResultExportPublicKey { key_data: buffer })
    }

    fn destroy_key(&self, app_name: ApplicationName, op: OpDestroyKey) -> Result<ResultDestroyKey> {
        info!("Mbed Provider - Destroy Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let key_handle;
        let destroy_key_status;

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        unsafe {
            key_handle = KeyHandle::open(key_id)?;
            destroy_key_status = psa_crypto_binding::psa_destroy_key(key_handle.raw());
        }

        if destroy_key_status == PSA_SUCCESS {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            Ok(ResultDestroyKey {})
        } else {
            error!("Destroy key status: {}", destroy_key_status);
            Err(utils::convert_status(destroy_key_status).ok_or_else(|| {
                error!("Failed to convert error status.");
                ResponseStatus::PsaErrorGenericError
            })?)
        }
    }

    fn asym_sign(&self, app_name: ApplicationName, op: OpAsymSign) -> Result<ResultAsymSign> {
        info!("Mbed Provider - Asym Sign");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let hash = op.hash;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

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
        let mut signature_size: usize = 0;

        let sign_status;
        // Safety: same conditions than above.
        unsafe {
            sign_status = psa_crypto_binding::psa_asymmetric_sign(
                key_handle.raw(),
                key_attrs.raw().core.policy.alg,
                hash.as_ptr(),
                hash.len(),
                signature.as_mut_ptr(),
                buffer_size,
                &mut signature_size,
            );
            key_attrs.reset();
            key_handle.close()?;
        };

        if sign_status == PSA_SUCCESS {
            let mut res = ResultAsymSign {
                signature: Vec::new(),
            };
            res.signature.resize(signature_size, 0);
            res.signature.copy_from_slice(&signature[0..signature_size]);

            Ok(res)
        } else {
            error!("Sign status: {}", sign_status);
            Err(utils::convert_status(sign_status).ok_or_else(|| {
                error!("Failed to convert error status.");
                ResponseStatus::PsaErrorGenericError
            })?)
        }
    }

    fn asym_verify(&self, app_name: ApplicationName, op: OpAsymVerify) -> Result<ResultAsymVerify> {
        info!("Mbed Provider - Asym Verify");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let hash = op.hash;
        let signature = op.signature;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

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
                key_attrs.raw().core.policy.alg,
                hash.as_ptr(),
                hash.len(),
                signature.as_ptr(),
                signature.len(),
            );
            key_attrs.reset();
            key_handle.close()?;
        }

        if verify_status == PSA_SUCCESS {
            Ok(ResultAsymVerify {})
        } else {
            Err(utils::convert_status(verify_status).ok_or_else(|| {
                error!("Failed to convert error status.");
                ResponseStatus::PsaErrorGenericError
            })?)
        }
    }
}

impl Drop for MbedProvider {
    fn drop(&mut self) {
        // Safety: the Provider was initialized with psa_crypto_init
        unsafe {
            psa_crypto_binding::mbedtls_psa_crypto_free();
        }
    }
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct MbedProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_id_store: Option<Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>>,
}

impl MbedProviderBuilder {
    pub fn new() -> MbedProviderBuilder {
        MbedProviderBuilder { key_id_store: None }
    }

    pub fn with_key_id_store(
        mut self,
        key_id_store: Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>,
    ) -> MbedProviderBuilder {
        self.key_id_store = Some(key_id_store);

        self
    }

    pub fn build(self) -> std::io::Result<MbedProvider> {
        MbedProvider::new(
            self.key_id_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key ID store"))?,
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "Mbed Provider initialization failed",
            )
        })
    }
}
