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
//! A simple non-persistant key ID manager
//!
//! This implementation of key ID manager is just an example for easier future integration of a
//! more complex manager that uses a persistant storage to store the mapping. This implementation
//! only uses a `HashMap`.

use super::ManageKeyIDs;
use crate::authenticators::ApplicationName;
use interface::requests::response::ResponseStatus;
use interface::requests::ProviderID;
use std::collections::HashMap;

pub struct SimpleKeyIDManager {
    pub key_store: HashMap<String, Vec<u8>>,
}

impl ManageKeyIDs for SimpleKeyIDManager {
    fn get(
        &self,
        app_name: &ApplicationName,
        provider_id: ProviderID,
        key_name: &str,
    ) -> Result<&[u8], ResponseStatus> {
        if let Some(key_id) = self
            .key_store
            .get(&format!("{}/{}/{}", app_name, provider_id, key_name))
        {
            Ok(key_id)
        } else {
            Err(ResponseStatus::KeyDoesNotExist)
        }
    }

    fn insert(
        &mut self,
        app_name: &ApplicationName,
        provider_id: ProviderID,
        key_name: &str,
        key_id: Vec<u8>,
    ) {
        self.key_store
            .insert(format!("{}/{}/{}", app_name, provider_id, key_name), key_id);
    }

    fn remove(&mut self, app_name: &ApplicationName, provider_id: ProviderID, key_name: &str) {
        self.key_store
            .remove(&format!("{}/{}/{}", app_name, provider_id, key_name))
            .expect("Key to remove was not present");
    }

    fn exists(&self, app_name: &ApplicationName, provider_id: ProviderID, key_name: &str) -> bool {
        self.key_store
            .contains_key(&format!("{}/{}/{}", app_name, provider_id, key_name))
    }
}

#[cfg(test)]
mod test {
    use super::super::ManageKeyIDs;
    use super::SimpleKeyIDManager;
    use crate::authenticators::ApplicationName;
    use interface::requests::ProviderID;
    use std::collections::HashMap;

    #[test]
    fn insert_get_key_id() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(manager.get(&app_name, prov, &key_name).is_err());

        manager.insert(&app_name, prov, &key_name, key_id.clone());

        let stored_key_id = Vec::from(
            manager
                .get(&app_name, prov, &key_name)
                .expect("Failed to get key id"),
        );

        assert_eq!(stored_key_id, key_id);
    }

    #[test]
    fn insert_remove_key() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_id = vec![0x11, 0x22, 0x33];

        manager.insert(&app_name, prov, &key_name, key_id.clone());

        manager.remove(&app_name, prov, &key_name);
    }

    #[test]
    #[should_panic(expected = "Key to remove was not present")]
    fn remove_panicking() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        manager.remove(&app_name, prov, &key_name);
    }

    #[test]
    fn exists() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(!manager.exists(&app_name, prov, &key_name));

        manager.insert(&app_name, prov, &key_name, key_id.clone());
        assert!(manager.exists(&app_name, prov, &key_name));

        manager.remove(&app_name, prov, &key_name);
        assert!(!manager.exists(&app_name, prov, &key_name));
    }

    #[test]
    fn insert_overwrites() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_id_1 = vec![0x11, 0x22, 0x33];
        let key_id_2 = vec![0xaa, 0xbb, 0xcc];

        manager.insert(&app_name, prov, &key_name, key_id_1.clone());
        manager.insert(&app_name, prov, &key_name, key_id_2.clone());

        let stored_key_id = Vec::from(
            manager
                .get(&app_name, prov, &key_name)
                .expect("Failed to get key id"),
        );

        assert_eq!(stored_key_id, key_id_2);
    }

    fn get_names() -> (ApplicationName, ProviderID) {
        (
            ApplicationName::new("app name".to_string()),
            ProviderID::CoreProvider,
        )
    }
}
