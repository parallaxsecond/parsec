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

use super::{KeyTriple, ManageKeyIDs};
use std::collections::HashMap;

#[derive(Default)]
pub struct SimpleKeyIDManager {
    key_store: HashMap<String, Vec<u8>>,
}

impl SimpleKeyIDManager {
    pub fn new() -> SimpleKeyIDManager {
        SimpleKeyIDManager {
            key_store: HashMap::new(),
        }
    }
}

impl ManageKeyIDs for SimpleKeyIDManager {
    fn get(&self, key_triple: KeyTriple) -> Option<&[u8]> {
        // An Option<&Vec<u8>> can not automatically coerce to an Option<&[u8]>, it needs to be
        // done by hand.
        if let Some(key_id) = self.key_store.get(&key_triple.to_string()) {
            Some(key_id)
        } else {
            None
        }
    }

    fn insert(&mut self, key_triple: KeyTriple, key_id: Vec<u8>) -> Option<Vec<u8>> {
        self.key_store.insert(key_triple.to_string(), key_id)
    }

    fn remove(&mut self, key_triple: KeyTriple) -> Option<Vec<u8>> {
        self.key_store.remove(&key_triple.to_string())
    }

    fn exists(&self, key_triple: KeyTriple) -> bool {
        self.key_store.contains_key(&key_triple.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::super::{KeyTriple, ManageKeyIDs};
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
        let key_triple = KeyTriple::new(&app_name, prov, &key_name);
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(manager.get(key_triple).is_none());

        manager.insert(key_triple, key_id.clone());

        let stored_key_id = Vec::from(manager.get(key_triple).expect("Failed to get key id"));

        assert_eq!(stored_key_id, key_id);
    }

    #[test]
    fn insert_remove_key() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_triple = KeyTriple::new(&app_name, prov, &key_name);
        let key_id = vec![0x11, 0x22, 0x33];

        manager.insert(key_triple, key_id.clone());

        manager.remove(key_triple);
    }

    #[test]
    fn remove_unexisting_key() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_triple = KeyTriple::new(&app_name, prov, &key_name);
        assert_eq!(manager.remove(key_triple), None);
    }

    #[test]
    fn exists() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_triple = KeyTriple::new(&app_name, prov, &key_name);
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(!manager.exists(key_triple));

        manager.insert(key_triple, key_id.clone());
        assert!(manager.exists(key_triple));

        manager.remove(key_triple);
        assert!(!manager.exists(key_triple));
    }

    #[test]
    fn insert_overwrites() {
        let mut manager = SimpleKeyIDManager {
            key_store: HashMap::new(),
        };

        let (app_name, prov) = get_names();
        let key_name = "test_key".to_string();
        let key_triple = KeyTriple::new(&app_name, prov, &key_name);
        let key_id_1 = vec![0x11, 0x22, 0x33];
        let key_id_2 = vec![0xaa, 0xbb, 0xcc];

        manager.insert(key_triple, key_id_1.clone());
        manager.insert(key_triple, key_id_2.clone());

        let stored_key_id = Vec::from(manager.get(key_triple).expect("Failed to get key id"));

        assert_eq!(stored_key_id, key_id_2);
    }

    fn get_names() -> (ApplicationName, ProviderID) {
        (
            ApplicationName::new("app name".to_string()),
            ProviderID::CoreProvider,
        )
    }
}
