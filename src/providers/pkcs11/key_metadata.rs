// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;

impl Provider {
    pub(super) fn create_key_id(&self) -> [u8; 4] {
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let mut key_id = rand::random::<[u8; 4]>();
        while local_ids_handle.contains(&key_id) {
            key_id = rand::random::<[u8; 4]>();
        }
        let _ = local_ids_handle.insert(key_id);
        key_id
    }
}
