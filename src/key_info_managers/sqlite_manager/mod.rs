// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! A key info manager storing key identity to key info mappings using a SQLite database.
//!
//! For security reasons, only the PARSEC service should have the ability to modify these files.
use super::{KeyIdentity, KeyInfo, ManageKeyInfo};
use crate::authenticators::ApplicationIdentity;
use crate::providers::ProviderIdentity;
use anyhow::Result;
use log::info;
use num_traits::FromPrimitive;
use parsec_interface::requests::AuthType;
use rusqlite::types::Type::{Blob, Integer};
use rusqlite::{params, Connection, Error as RusqliteError};
use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

/// Default path where the database will be stored on disk
pub const DEFAULT_DB_PATH: &str =
    "/var/lib/parsec/kim-mappings/sqlite/sqlite-key-info-manager.sqlite3";

/// The current serialization version of the KeyInfo object.
pub const CURRENT_KEY_INFO_VERSION: u8 = 1;

/// The current database schema version of the SQLiteKeyInfoManager.
pub const CURRENT_SCHEMA_VERSION: u8 = 1;

/// A key info manager storing key identity to key info mapping on files on disk
#[derive(Debug)]
pub struct SQLiteKeyInfoManager {
    /// Internal mapping, used for non-modifying operations.
    key_store: HashMap<KeyIdentity, KeyInfo>,
    /// The file path where the SQLite database exists. This database holds
    /// key identity to key info mappings.
    database_path: PathBuf,
}

struct KeyInfoRecord {
    key_identity: KeyIdentity,
    key_info: KeyInfo,
}

/// TODO: Implement this until the interface TryFrom u8 to AuthType is implemented.
fn i64_to_auth_type(auth_type: i64) -> Result<AuthType, String> {
    match FromPrimitive::from_i64(auth_type) {
        Some(auth_type) => Ok(auth_type),
        None => Err(format!(
            "Failed to get AuthType from authenticator_id.\nAuthenticator \"{}\" does not exist.",
            auth_type
        )),
    }
}

/// SQLite-based `KeyInfoManager`
///
/// The `SQLiteKeyInfoManager` relies on access control mechanisms provided by the OS for
/// the filesystem to ensure security of the database.
impl SQLiteKeyInfoManager {
    /// Creates an instance of the sqlite key info manager.
    /// The SQLiteKeyInfoManager stores key info in the provided database_path file.
    /// Uses rusqlite.
    fn new(database_path: PathBuf) -> Result<SQLiteKeyInfoManager> {
        // Create directory if it does not already exist
        let mut directory_path = database_path.clone();
        let _ = directory_path.pop();
        fs::create_dir_all(&directory_path)?;
        // Connect to or create database at set path
        let conn = Connection::open(&database_path)?;
        let mut key_store = HashMap::new();

        // TODO: Implement kim_metadata table creation here using CURRENT_SCHEMA_VERSION value if
        // key_mapping & kim_metadata tables do not exist.

        // Create table key_mapping table if it does not already exist
        let _ = conn.execute(
            "
            CREATE TABLE IF NOT EXISTS key_mapping (
                authenticator_id      INTEGER NOT NULL,
                application_name      TEXT NOT NULL,
                key_name              TEXT NOT NULL,
                provider_uuid         TEXT NOT NULL,
                provider_name         TEXT NOT NULL,
                key_info              BLOB NOT NULL,
                key_info_version      INTEGER NOT NULL,
                PRIMARY KEY (authenticator_id, application_name, key_name)
            )
            ",
            [],
        )?;

        let mut stmt = conn.prepare("SELECT * FROM key_mapping")?;
        let key_iter = stmt.query_map([], |row| {
            let key_identity = KeyIdentity::new(
                ApplicationIdentity::new(
                    row.get("application_name")?,
                    i64_to_auth_type(row.get("authenticator_id")?).map_err(|e| {
                        format_error!("Failed to get AuthType from authenticator_id.", e);
                        let error = Box::new(Error::new(ErrorKind::InvalidData, e));
                        RusqliteError::FromSqlConversionFailure(64, Integer, error)
                    })?,
                ),
                ProviderIdentity::new(row.get("provider_uuid")?, row.get("provider_name")?),
                row.get("key_name")?,
            );
            let key_info_blob: Vec<u8> = row.get("key_info")?;

            // TODO: Change this to (protobuf?) version once format has been decided.
            let key_info = bincode::deserialize(&key_info_blob[..]).map_err(|e| {
                format_error!("Error deserializing key info", e);
                RusqliteError::FromSqlConversionFailure(key_info_blob.len(), Blob, e)
            })?;

            Ok(KeyInfoRecord {
                key_identity,
                key_info,
            })
        })?;

        // Add keys to key_store cache
        for key_info_record in key_iter {
            let key_info_record = key_info_record?;
            let _ = key_store.insert(key_info_record.key_identity, key_info_record.key_info);
        }

        if !crate::utils::GlobalConfig::log_error_details() {
            info!(
                "SQLiteKeyInfoManager - Found {} key info mapping records",
                key_store.len()
            );
        }

        Ok(SQLiteKeyInfoManager {
            key_store,
            database_path,
        })
    }

    /// Saves the KeyIdentity and KeyInfo to the database.
    /// Inserts a new record to the database `key_mapping` table.
    fn save_mapping(
        &self,
        key_identity: &KeyIdentity,
        key_info: &KeyInfo,
    ) -> rusqlite::Result<(), RusqliteError> {
        let conn = Connection::open(&self.database_path)?;

        // TODO: Change this to (protobuf?) version once format has been decided.
        let key_info_blob = bincode::serialize(&key_info).map_err(|e| {
            format_error!("Error serializing key info", e);
            RusqliteError::ToSqlConversionFailure(e)
        })?;

        // Insert the new key mapping, if a record does not exist.
        // If one does exist, replace the existing record.
        let _ = conn.execute(
            "
            REPLACE INTO
                `key_mapping`
                (`authenticator_id`, `application_name`, `provider_uuid`, `provider_name`, `key_name`, `key_info`, `key_info_version`)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7);
            ",
            params![
                *key_identity.application().authenticator_id() as u8,
                key_identity.application().name(),
                key_identity.provider().uuid(),
                key_identity.provider().name(),
                key_identity.key_name(),
                key_info_blob,
                CURRENT_KEY_INFO_VERSION,
            ],
        )?;
        Ok(())
    }

    /// Removes the mapping record.
    /// Will do nothing if the mapping record does not exist.
    fn delete_mapping(&self, key_identity: &KeyIdentity) -> rusqlite::Result<(), RusqliteError> {
        let conn = Connection::open(&self.database_path)?;

        let _ = conn.execute(
            "
            DELETE FROM
                `key_mapping`
            WHERE
                `authenticator_id` = ?1
                AND `application_name` = ?2
                AND `key_name` = ?3
            ",
            params![
                *key_identity.application().authenticator_id() as u8,
                key_identity.application().name(),
                key_identity.key_name(),
            ],
        )?;
        Ok(())
    }
}

impl ManageKeyInfo for SQLiteKeyInfoManager {
    fn get(&self, key_identity: &KeyIdentity) -> Result<Option<&KeyInfo>, String> {
        if let Some(key_info) = self.key_store.get(key_identity) {
            Ok(Some(key_info))
        } else {
            Ok(None)
        }
    }

    fn get_all(&self, provider_identity: ProviderIdentity) -> Result<Vec<KeyIdentity>, String> {
        Ok(self
            .key_store
            .keys()
            .filter(|key_identity| key_identity.belongs_to_provider(&provider_identity))
            .cloned()
            .collect())
    }

    fn insert(
        &mut self,
        key_identity: KeyIdentity,
        key_info: KeyInfo,
    ) -> Result<Option<KeyInfo>, String> {
        if let Err(err) = self.save_mapping(&key_identity, &key_info) {
            Err(err.to_string())
        } else {
            Ok(self.key_store.insert(key_identity, key_info))
        }
    }

    fn remove(&mut self, key_identity: &KeyIdentity) -> Result<Option<KeyInfo>, String> {
        if let Err(err) = self.delete_mapping(key_identity) {
            Err(err.to_string())
        } else if let Some(key_info) = self.key_store.remove(key_identity) {
            Ok(Some(key_info))
        } else {
            Ok(None)
        }
    }

    fn exists(&self, key_identity: &KeyIdentity) -> Result<bool, String> {
        Ok(self.key_store.contains_key(key_identity))
    }
}

/// SQLiteKeyInfoManager builder
#[derive(Debug, Default)]
pub struct SQLiteKeyInfoManagerBuilder {
    database_path: Option<PathBuf>,
}

impl SQLiteKeyInfoManagerBuilder {
    /// Create a new SQLiteKeyInfoManagerBuilder
    pub fn new() -> SQLiteKeyInfoManagerBuilder {
        SQLiteKeyInfoManagerBuilder {
            database_path: None,
        }
    }

    /// Add a mappings directory path to the builder
    pub fn with_db_path(mut self, path: PathBuf) -> SQLiteKeyInfoManagerBuilder {
        self.database_path = Some(path);
        self
    }

    /// Build into a SQLiteKeyInfoManager
    pub fn build(self) -> Result<SQLiteKeyInfoManager> {
        SQLiteKeyInfoManager::new(
            self.database_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH)),
        )
    }
}

#[cfg(test)]
mod test {
    use super::super::{KeyIdentity, KeyInfo, ManageKeyInfo};
    use super::SQLiteKeyInfoManager;
    use crate::key_info_managers::{ApplicationIdentity, ProviderIdentity};
    use crate::providers::core::Provider as CoreProvider;
    #[cfg(feature = "mbed-crypto-provider")]
    use crate::providers::mbed_crypto::Provider as MbedCryptoProvider;
    use parsec_interface::operations::psa_algorithm::{
        Algorithm, AsymmetricSignature, Hash, SignHash,
    };
    use parsec_interface::operations::psa_key_attributes::{
        Attributes, Lifetime, Policy, Type, UsageFlags,
    };
    use parsec_interface::requests::AuthType;
    use std::fs;
    use std::path::PathBuf;

    fn test_key_attributes() -> Attributes {
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::Derive,
            bits: 1024,
            policy: Policy {
                usage_flags: UsageFlags {
                    sign_hash: true,
                    verify_hash: false,
                    sign_message: false,
                    verify_message: false,
                    export: false,
                    encrypt: false,
                    decrypt: false,
                    cache: false,
                    copy: false,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: SignHash::Specific(Hash::Sha256),
                    },
                ),
            },
        }
    }

    fn test_key_info() -> KeyInfo {
        KeyInfo {
            id: vec![0x11, 0x22, 0x33],
            attributes: test_key_attributes(),
        }
    }

    #[test]
    fn insert_get_key_info() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/insert_get_key_info_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_identity = new_key_identity("insert_get_key_info".to_string());
        let key_info = test_key_info();

        assert!(manager.get(&key_identity).unwrap().is_none());

        assert!(manager
            .insert(key_identity.clone(), key_info.clone())
            .unwrap()
            .is_none());

        let stored_key_info = manager
            .get(&key_identity)
            .unwrap()
            .expect("Failed to get key info")
            .clone();

        assert_eq!(stored_key_info, key_info);
        assert!(manager.remove(&key_identity).unwrap().is_some());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn insert_remove_key() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/insert_remove_key_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_identity = new_key_identity("insert_remove_key".to_string());
        let key_info = test_key_info();

        let _ = manager.insert(key_identity.clone(), key_info).unwrap();

        assert!(manager.remove(&key_identity).unwrap().is_some());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn remove_unexisting_key() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/remove_unexisting_key_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_identity = new_key_identity("remove_unexisting_key".to_string());
        assert_eq!(manager.remove(&key_identity).unwrap(), None);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn exists() {
        let path =
            PathBuf::from(env!("OUT_DIR").to_owned() + "/kim/sqlite/exists_mappings.sqlite3");
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_identity = new_key_identity("exists".to_string());
        let key_info = test_key_info();

        assert!(!manager.exists(&key_identity).unwrap());

        let _ = manager.insert(key_identity.clone(), key_info).unwrap();
        assert!(manager.exists(&key_identity).unwrap());

        let _ = manager.remove(&key_identity).unwrap();
        assert!(!manager.exists(&key_identity).unwrap());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn insert_overwrites() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/insert_overwrites_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_identity = new_key_identity("insert_overwrites".to_string());
        let key_info_1 = test_key_info();
        let key_info_2 = KeyInfo {
            id: vec![0xaa, 0xbb, 0xcc],
            attributes: test_key_attributes(),
        };

        let _ = manager.insert(key_identity.clone(), key_info_1).unwrap();
        let _ = manager
            .insert(key_identity.clone(), key_info_2.clone())
            .unwrap();

        let stored_key_info = manager
            .get(&key_identity)
            .unwrap()
            .expect("Failed to get key info")
            .clone();

        assert_eq!(stored_key_info, key_info_2);
        assert!(manager.remove(&key_identity).unwrap().is_some());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn big_names_ascii() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/big_names_ascii_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let big_app_name_ascii = "  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string();
        let big_key_name_ascii = "  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string();

        let key_identity = KeyIdentity::new(
            ApplicationIdentity::new(big_app_name_ascii, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            big_key_name_ascii,
        );
        let key_info = test_key_info();

        let _ = manager
            .insert(key_identity.clone(), key_info.clone())
            .unwrap();
        assert_eq!(manager.remove(&key_identity).unwrap().unwrap(), key_info);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn big_names_emoticons() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/big_names_emoticons_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let big_app_name_emoticons = "😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string();
        let big_key_name_emoticons = "😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string();

        let key_identity = KeyIdentity::new(
            ApplicationIdentity::new(big_app_name_emoticons, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            big_key_name_emoticons,
        );
        let key_info = test_key_info();

        let _ = manager
            .insert(key_identity.clone(), key_info.clone())
            .unwrap();
        assert_eq!(manager.remove(&key_identity).unwrap().unwrap(), key_info);
        fs::remove_file(&path).unwrap();
    }

    // TODO:
    // Add tests:
    // - Add tests for namespaces (check keys are separated by):
    //   - Application Name
    //   - Authenticator
    //   - Key Name
    // - Check keys are not separated by:
    //   - Provider Name
    //   - Provider UUID

    #[cfg(feature = "mbed-crypto-provider")]
    #[test]
    fn create_and_load() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/create_and_load_mappings.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();

        let app_name1 = "😀 Application One 😀".to_string();
        let key_name1 = "😀 Key One 😀".to_string();
        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name1, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name1,
        );
        let key_info1 = test_key_info();

        let app_name2 = "😇 Application Two 😇".to_string();
        let key_name2 = "😇 Key Two 😇".to_string();
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name2, AuthType::NoAuth),
            ProviderIdentity::new(
                MbedCryptoProvider::PROVIDER_UUID.to_string(),
                MbedCryptoProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name2,
        );
        let key_info2 = KeyInfo {
            id: vec![0x12, 0x22, 0x32],
            attributes: test_key_attributes(),
        };

        let app_name3 = "😈 Application Three 😈".to_string();
        let key_name3 = "😈 Key Three 😈".to_string();
        let key_identity_3 = KeyIdentity::new(
            ApplicationIdentity::new(app_name3, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name3,
        );
        let key_info3 = KeyInfo {
            id: vec![0x13, 0x23, 0x33],
            attributes: test_key_attributes(),
        };
        {
            let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

            let _ = manager
                .insert(key_identity_1.clone(), key_info1.clone())
                .unwrap();
            let _ = manager
                .insert(key_identity_2.clone(), key_info2.clone())
                .unwrap();
            let _ = manager
                .insert(key_identity_3.clone(), key_info3.clone())
                .unwrap();
        }
        // The local hashmap is dropped when leaving the inner scope.
        {
            let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

            assert_eq!(manager.remove(&key_identity_1).unwrap().unwrap(), key_info1);
            assert_eq!(manager.remove(&key_identity_2).unwrap().unwrap(), key_info2);
            assert_eq!(manager.remove(&key_identity_3).unwrap().unwrap(), key_info3);
        }

        fs::remove_file(&path).unwrap();
    }

    fn new_key_identity(key_name: String) -> KeyIdentity {
        KeyIdentity::new(
            ApplicationIdentity::new("Testing Application 😎".to_string(), AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name,
        )
    }
}
