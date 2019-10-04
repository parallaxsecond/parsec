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
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::{Arc, RwLock};

use parsec_interface::operations::key_attributes::KeyLifetime;
use parsec_interface::operations::ProviderInfo;
use parsec_interface::operations::{OpAsymSign, ResultAsymSign};
use parsec_interface::operations::{OpAsymVerify, ResultAsymVerify};
use parsec_interface::operations::{OpCreateKey, ResultCreateKey};
use parsec_interface::operations::{OpDestroyKey, ResultDestroyKey};
use parsec_interface::operations::{OpExportPublicKey, ResultExportPublicKey};
use parsec_interface::operations::{OpImportKey, ResultImportKey};
use parsec_interface::operations::{OpListOpcodes, ResultListOpcodes};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use uuid::Uuid;

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
#[allow(clippy::all)]
mod psa_crypto_binding;

#[allow(dead_code)]
mod constants;
mod conversion_utils;

type LocalIdStore = HashSet<psa_crypto_binding::psa_key_id_t>;

const SUPPORTED_OPCODES: [Opcode; 7] = [
    Opcode::CreateKey,
    Opcode::DestroyKey,
    Opcode::AsymSign,
    Opcode::AsymVerify,
    Opcode::ImportKey,
    Opcode::ExportPublicKey,
    Opcode::ListOpcodes,
];

pub struct MbedProvider {
    // When calling write on a reference of key_id_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyIDs + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyIDs + Send + Sync and then
    // reference it to match with the method prototypes.
    key_id_store: Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>,
    local_ids: RwLock<LocalIdStore>,
}

/// Gets a PSA Key ID from the Key ID Manager.
/// Wrapper around the get method of the Key ID Manager to convert the key ID to the psa_key_id_t
/// type.
fn get_key_id(
    key_triple: &KeyTriple,
    store_handle: &dyn ManageKeyIDs,
) -> Result<psa_crypto_binding::psa_key_id_t> {
    match store_handle.get(key_triple) {
        Ok(Some(key_id)) => {
            if let Ok(key_id_bytes) = key_id.try_into() {
                Ok(u32::from_ne_bytes(key_id_bytes))
            } else {
                println!("Stored Key ID is not valid.");
                Err(ResponseStatus::KeyIDManagerError)
            }
        }
        Ok(None) => Err(ResponseStatus::KeyDoesNotExist),
        Err(string) => {
            println!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

/// Creates a new PSA Key ID and stores it in the Key ID Manager.
fn create_key_id(
    key_triple: KeyTriple,
    store_handle: &mut dyn ManageKeyIDs,
    local_ids_handle: &mut LocalIdStore,
) -> Result<psa_crypto_binding::psa_key_id_t> {
    let mut key_id = rand::random::<psa_crypto_binding::psa_key_id_t>();
    while local_ids_handle.contains(&key_id) {
        key_id = rand::random::<psa_crypto_binding::psa_key_id_t>();
    }
    match store_handle.insert(key_triple.clone(), key_id.to_ne_bytes().to_vec()) {
        Ok(insert_option) => {
            if insert_option.is_some() {
                println!("Overwriting Key triple mapping ({})", key_triple);
            }
            local_ids_handle.insert(key_id);

            Ok(key_id)
        }
        Err(string) => {
            println!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

fn remove_key_id(
    key_triple: &KeyTriple,
    key_id: psa_crypto_binding::psa_key_id_t,
    store_handle: &mut dyn ManageKeyIDs,
    local_ids_handle: &mut LocalIdStore,
) -> Result<()> {
    match store_handle.remove(key_triple) {
        Ok(_) => {
            local_ids_handle.remove(&key_id);
            Ok(())
        }
        Err(string) => {
            println!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

fn key_id_exists(key_triple: &KeyTriple, store_handle: &dyn ManageKeyIDs) -> Result<bool> {
    match store_handle.exists(key_triple) {
        Ok(val) => Ok(val),
        Err(string) => {
            println!("Key ID Manager error: {}", string);
            Err(ResponseStatus::KeyIDManagerError)
        }
    }
}

impl MbedProvider {
    /// Creates and initialise a new instance of MbedProvider.
    /// Checks if there are not more keys stored in the Key ID Manager than in the MbedProvider and
    /// if there, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    pub fn new(key_id_store: Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>) -> Option<MbedProvider> {
        if unsafe { psa_crypto_binding::psa_crypto_init() } != constants::PSA_SUCCESS {
            println!("Error when initialising Mbed Crypto");
            return None;
        }
        let mbed_provider = MbedProvider {
            key_id_store,
            local_ids: RwLock::new(HashSet::new()),
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
                                println!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...", key_triple, response_status);
                                to_remove.push(key_triple.clone());
                                continue;
                            }
                        };
                        // Use psa_open_key to check if the key ID actually exists or not.
                        let lifetime =
                            conversion_utils::convert_key_lifetime(KeyLifetime::Persistent);
                        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;
                        let open_key_status = unsafe {
                            psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle)
                        };
                        if open_key_status == constants::PSA_ERROR_DOES_NOT_EXIST {
                            to_remove.push(key_triple.clone());
                        } else if open_key_status != constants::PSA_SUCCESS {
                            println!(
                                "Error {} when opening a persistent Mbed Crypto key.",
                                open_key_status
                            );
                            return None;
                        } else {
                            local_ids_handle.insert(key_id);
                            unsafe {
                                psa_crypto_binding::psa_close_key(key_handle);
                            }
                        }
                    }
                }
                Err(string) => {
                    println!("Key ID Manager error: {}", string);
                    return None;
                }
            };
            for key_triple in to_remove.iter() {
                if let Err(string) = store_handle.remove(key_triple) {
                    println!("Key ID Manager error: {}", string);
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
        println!("Mbed Provider - Create Key");
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

        let key_attrs = conversion_utils::convert_key_attributes(&key_attributes);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let create_key_status = unsafe {
            psa_crypto_binding::psa_create_key(key_attrs.key_lifetime, key_id, &mut key_handle)
        };

        let ret_val: Result<ResultCreateKey>;

        if create_key_status == constants::PSA_SUCCESS {
            let mut policy = psa_crypto_binding::psa_key_policy_t {
                alg: 0,
                alg2: 0,
                usage: 0,
            };

            let set_policy_status = unsafe {
                psa_crypto_binding::psa_key_policy_set_usage(
                    &mut policy,
                    key_attrs.key_usage,
                    key_attrs.algorithm,
                );
                psa_crypto_binding::psa_set_key_policy(key_handle, &policy)
            };

            if set_policy_status == constants::PSA_SUCCESS {
                let generate_key_status = unsafe {
                    psa_crypto_binding::psa_generate_key(
                        key_handle,
                        key_attrs.key_type,
                        key_attrs.key_size,
                        std::ptr::null(),
                        0,
                    )
                };

                if generate_key_status == constants::PSA_SUCCESS {
                    ret_val = Ok(ResultCreateKey {});
                } else {
                    ret_val = Err(conversion_utils::convert_status(generate_key_status));
                    println!("Generate key status: {}", generate_key_status);
                }
            } else {
                ret_val = Err(conversion_utils::convert_status(set_policy_status));
                println!("Set policy status: {}", set_policy_status);
            }

            unsafe {
                psa_crypto_binding::psa_close_key(key_handle);
            }
        } else {
            ret_val = Err(conversion_utils::convert_status(create_key_status));
            println!("Create key status: {}", create_key_status);
        }

        if ret_val.is_err() {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
        }

        ret_val
    }

    fn import_key(&self, app_name: ApplicationName, op: OpImportKey) -> Result<ResultImportKey> {
        println!("Mbed Provider - Import Key");
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

        let key_attrs = conversion_utils::convert_key_attributes(&key_attributes);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let create_key_status = unsafe {
            psa_crypto_binding::psa_create_key(key_attrs.key_lifetime, key_id, &mut key_handle)
        };

        let ret_val: Result<ResultImportKey>;

        if create_key_status == constants::PSA_SUCCESS {
            let mut policy = psa_crypto_binding::psa_key_policy_t {
                alg: 0,
                alg2: 0,
                usage: 0,
            };

            let set_policy_status = unsafe {
                psa_crypto_binding::psa_key_policy_set_usage(
                    &mut policy,
                    key_attrs.key_usage,
                    key_attrs.algorithm,
                );
                psa_crypto_binding::psa_set_key_policy(key_handle, &policy)
            };

            if set_policy_status == constants::PSA_SUCCESS {
                let import_key_status = unsafe {
                    psa_crypto_binding::psa_import_key(
                        key_handle,
                        key_attrs.key_type,
                        key_data.as_ptr(),
                        key_attrs.key_size,
                    )
                };

                if import_key_status == constants::PSA_SUCCESS {
                    ret_val = Ok(ResultImportKey {});
                } else {
                    ret_val = Err(conversion_utils::convert_status(import_key_status));
                    println!("Import key status: {}", import_key_status);
                }
            } else {
                ret_val = Err(conversion_utils::convert_status(set_policy_status));
                println!("Set policy status: {}", set_policy_status);
            }

            unsafe {
                psa_crypto_binding::psa_close_key(key_handle);
            }
        } else {
            ret_val = Err(conversion_utils::convert_status(create_key_status));
            println!("Create key status: {}", create_key_status);
        }

        if ret_val.is_err() {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
        }

        ret_val
    }

    fn export_public_key(
        &self,
        app_name: ApplicationName,
        op: OpExportPublicKey,
    ) -> Result<ResultExportPublicKey> {
        println!("Mbed Provider - Export Public Key");
        let key_name = op.key_name;
        let key_lifetime = op.key_lifetime;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let ret_val: Result<ResultExportPublicKey>;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == constants::PSA_SUCCESS {
            // TODO: There's no calculation of the buffer size here, nor is there any handling of the
            // PSA_ERROR_BUFFER_TOO_SMALL condition. Just allocating a "big" buffer and assuming/hoping it is
            // enough.

            let mut buffer = vec![0u8; 1024];
            let mut actual_size = 0;

            let export_status = unsafe {
                psa_crypto_binding::psa_export_public_key(
                    key_handle,
                    buffer.as_mut_ptr(),
                    1024,
                    &mut actual_size,
                )
            };

            if export_status == constants::PSA_SUCCESS {
                buffer.resize(actual_size, 0);
                ret_val = Ok(ResultExportPublicKey { key_data: buffer });
            } else {
                println!("Export status: {}", export_status);
                ret_val = Err(conversion_utils::convert_status(export_status));
            }

            unsafe {
                psa_crypto_binding::psa_close_key(key_handle);
            }
        } else {
            println!("Open key status: {}", open_key_status);
            ret_val = Err(conversion_utils::convert_status(open_key_status));
        }

        ret_val
    }

    fn destroy_key(&self, app_name: ApplicationName, op: OpDestroyKey) -> Result<ResultDestroyKey> {
        println!("Mbed Provider - Destroy Key");
        let key_name = op.key_name;
        let key_lifetime = op.key_lifetime;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == constants::PSA_SUCCESS {
            let destroy_key_status = unsafe { psa_crypto_binding::psa_destroy_key(key_handle) };

            if destroy_key_status == constants::PSA_SUCCESS {
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                Ok(ResultDestroyKey {})
            } else {
                Err(conversion_utils::convert_status(destroy_key_status))
            }
        } else {
            Err(conversion_utils::convert_status(open_key_status))
        }
    }

    fn asym_sign(&self, app_name: ApplicationName, op: OpAsymSign) -> Result<ResultAsymSign> {
        println!("Mbed Provider - Asym Sign");
        let key_name = op.key_name;
        let key_lifetime = op.key_lifetime;
        let hash = op.hash;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == constants::PSA_SUCCESS {
            let mut policy = psa_crypto_binding::psa_key_policy_t {
                alg: 0,
                alg2: 0,
                usage: 0,
            };

            // Allocate a "big enough" buffer. (No handling of PSA_STATUS_BUFFER_TOO_SMALL here.)
            let mut signature = [0u8; 1024];
            let mut signature_size: usize = 0;

            let sign_status = unsafe {
                // Determine the algorithm by getting the key policy, and then getting
                // the algorithm from the policy. No handling of failing status here. The key is open,
                // and the policy is just data, so this shouldn't really fail.
                psa_crypto_binding::psa_get_key_policy(key_handle, &mut policy);

                psa_crypto_binding::psa_asymmetric_sign(
                    key_handle,
                    psa_crypto_binding::psa_key_policy_get_algorithm(&policy),
                    hash.as_ptr(),
                    hash.len(),
                    signature.as_mut_ptr(),
                    1024,
                    &mut signature_size,
                )
            };

            unsafe {
                psa_crypto_binding::psa_close_key(key_handle);
            }

            if sign_status == constants::PSA_SUCCESS {
                let mut res = ResultAsymSign {
                    signature: Vec::new(),
                };
                res.signature.resize(signature_size, 0);
                res.signature.copy_from_slice(&signature[0..signature_size]);

                Ok(res)
            } else {
                Err(conversion_utils::convert_status(sign_status))
            }
        } else {
            Err(conversion_utils::convert_status(open_key_status))
        }
    }

    fn asym_verify(&self, app_name: ApplicationName, op: OpAsymVerify) -> Result<ResultAsymVerify> {
        println!("Mbed Provider - Asym Verify");
        let key_name = op.key_name;
        let key_lifetime = op.key_lifetime;
        let hash = op.hash;
        let signature = op.signature;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedProvider, key_name);
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == constants::PSA_SUCCESS {
            let mut policy = psa_crypto_binding::psa_key_policy_t {
                alg: 0,
                alg2: 0,
                usage: 0,
            };

            let algorithm: psa_crypto_binding::psa_algorithm_t;

            let verify_status = unsafe {
                // Determine the algorithm by getting the key policy, and then getting
                // the algorithm from the policy. No handling of failing status here. The key is open,
                // and the policy is just data, so this shouldn't really fail.
                psa_crypto_binding::psa_get_key_policy(key_handle, &mut policy);
                algorithm = psa_crypto_binding::psa_key_policy_get_algorithm(&policy);

                psa_crypto_binding::psa_asymmetric_verify(
                    key_handle,
                    algorithm,
                    hash.as_ptr(),
                    hash.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };

            unsafe {
                psa_crypto_binding::psa_close_key(key_handle);
            }

            if verify_status == constants::PSA_SUCCESS {
                Ok(ResultAsymVerify {})
            } else {
                Err(conversion_utils::convert_status(verify_status))
            }
        } else {
            Err(conversion_utils::convert_status(open_key_status))
        }
    }
}
