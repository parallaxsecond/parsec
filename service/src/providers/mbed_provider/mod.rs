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
use crate::key_id_managers::ManageKeyIDs;
use interface::requests::ProviderID;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::{Arc, RwLock};

use interface::operations::{OpCreateKey, ResultCreateKey};
use interface::operations::{OpDestroyKey, ResultDestroyKey};
use interface::operations::{OpExportPublicKey, ResultExportPublicKey};
use interface::operations::{OpImportKey, ResultImportKey};
use interface::requests::response::ResponseStatus;

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

type KeyIdManager = Box<dyn ManageKeyIDs + Send + Sync>;
type LocalIdStore = HashSet<psa_crypto_binding::psa_key_id_t>;

pub struct MbedProvider {
    pub key_id_store: Arc<RwLock<KeyIdManager>>,
    pub local_ids: RwLock<LocalIdStore>,
}

impl MbedProvider {
    fn get_key_id(
        &self,
        app_name: &ApplicationName,
        key_name: &str,
        store_handle: &KeyIdManager,
    ) -> Result<psa_crypto_binding::psa_key_id_t, ResponseStatus> {
        Ok(u32::from_ne_bytes(
            store_handle
                .get(app_name, ProviderID::MbedProvider, key_name)?
                .try_into()
                .expect("Stored key ID was not valid"),
        ))
    }

    fn create_key_id(
        &self,
        app_name: &ApplicationName,
        key_name: &str,
        store_handle: &mut KeyIdManager,
        local_ids_handle: &mut LocalIdStore,
    ) -> psa_crypto_binding::psa_key_id_t {
        let mut key_id = rand::random::<psa_crypto_binding::psa_key_id_t>();
        while !local_ids_handle.insert(key_id) {
            key_id = rand::random::<psa_crypto_binding::psa_key_id_t>();
        }
        store_handle.insert(
            app_name,
            ProviderID::MbedProvider,
            key_name,
            key_id.to_ne_bytes().to_vec(),
        );

        key_id
    }

    fn remove_key_id(
        &self,
        app_name: &ApplicationName,
        key_name: &str,
        key_id: psa_crypto_binding::psa_key_id_t,
        store_handle: &mut KeyIdManager,
        local_ids_handle: &mut LocalIdStore,
    ) {
        local_ids_handle.remove(&key_id);
        store_handle.remove(app_name, ProviderID::MbedProvider, key_name);
    }

    fn key_id_exists(
        &self,
        app_name: &ApplicationName,
        key_name: &str,
        store_handle: &KeyIdManager,
    ) -> bool {
        store_handle.exists(app_name, ProviderID::MbedProvider, key_name)
    }
}

impl Provide for MbedProvider {
    fn init(&self) -> bool {
        let init_status = unsafe { psa_crypto_binding::psa_crypto_init() };

        init_status == 0
    }

    fn create_key(
        &self,
        app_name: ApplicationName,
        op: OpCreateKey,
    ) -> Result<ResultCreateKey, ResponseStatus> {
        println!("Mbed Provider - Create Key");
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if self.key_id_exists(&app_name, &op.key_name, &store_handle) {
            return Err(ResponseStatus::KeyAlreadyExists);
        }
        let key_id = self.create_key_id(
            &app_name,
            &op.key_name,
            &mut store_handle,
            &mut local_ids_handle,
        );

        let key_attrs = conversion_utils::convert_key_attributes(&op.key_attributes);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let create_key_status = unsafe {
            psa_crypto_binding::psa_create_key(key_attrs.key_lifetime, key_id, &mut key_handle)
        };

        let ret_val: Result<ResultCreateKey, ResponseStatus>;

        if create_key_status == 0 {
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

            if set_policy_status == 0 {
                let generate_key_status = unsafe {
                    psa_crypto_binding::psa_generate_key(
                        key_handle,
                        key_attrs.key_type,
                        key_attrs.key_size,
                        std::ptr::null(),
                        0,
                    )
                };

                if generate_key_status == 0 {
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
            self.remove_key_id(
                &app_name,
                &op.key_name,
                key_id,
                &mut store_handle,
                &mut local_ids_handle,
            );
        }

        ret_val
    }

    fn import_key(
        &self,
        app_name: ApplicationName,
        op: OpImportKey,
    ) -> Result<ResultImportKey, ResponseStatus> {
        println!("Mbed Provider - Import Key");
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if self.key_id_exists(&app_name, &op.key_name, &store_handle) {
            return Err(ResponseStatus::KeyAlreadyExists);
        }
        let key_id = self.create_key_id(
            &app_name,
            &op.key_name,
            &mut store_handle,
            &mut local_ids_handle,
        );

        let key_attrs = conversion_utils::convert_key_attributes(&op.key_attributes);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let create_key_status = unsafe {
            psa_crypto_binding::psa_create_key(key_attrs.key_lifetime, key_id, &mut key_handle)
        };

        let ret_val: Result<ResultImportKey, ResponseStatus>;

        if create_key_status == 0 {
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

            if set_policy_status == 0 {
                let import_key_status = unsafe {
                    psa_crypto_binding::psa_import_key(
                        key_handle,
                        key_attrs.key_type,
                        op.key_data.as_ptr(),
                        key_attrs.key_size,
                    )
                };

                if import_key_status == 0 {
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
            self.remove_key_id(
                &app_name,
                &op.key_name,
                key_id,
                &mut store_handle,
                &mut local_ids_handle,
            );
        }

        ret_val
    }

    fn export_public_key(
        &self,
        app_name: ApplicationName,
        op: OpExportPublicKey,
    ) -> Result<ResultExportPublicKey, ResponseStatus> {
        println!("Mbed Provider - Export Public Key");
        let store_handle = self.key_id_store.read().expect("Key store lock poisoned");
        let key_id = self.get_key_id(&app_name, &op.key_name, &store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(op.key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let ret_val: Result<ResultExportPublicKey, ResponseStatus>;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == 0 {
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

            if export_status == 0 {
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

    fn destroy_key(
        &self,
        app_name: ApplicationName,
        op: OpDestroyKey,
    ) -> Result<ResultDestroyKey, ResponseStatus> {
        println!("Mbed Provider - Destroy Key");
        let mut store_handle = self.key_id_store.write().expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let key_id = self.get_key_id(&app_name, &op.key_name, &store_handle)?;

        let lifetime = conversion_utils::convert_key_lifetime(op.key_lifetime);
        let mut key_handle: psa_crypto_binding::psa_key_handle_t = 0;

        let open_key_status =
            unsafe { psa_crypto_binding::psa_open_key(lifetime, key_id, &mut key_handle) };

        if open_key_status == 0 {
            let destroy_key_status = unsafe { psa_crypto_binding::psa_destroy_key(key_handle) };

            if destroy_key_status == 0 {
                self.remove_key_id(
                    &app_name,
                    &op.key_name,
                    key_id,
                    &mut store_handle,
                    &mut local_ids_handle,
                );
                Ok(ResultDestroyKey {})
            } else {
                Err(conversion_utils::convert_status(destroy_key_status))
            }
        } else {
            Err(conversion_utils::convert_status(open_key_status))
        }
    }
}
