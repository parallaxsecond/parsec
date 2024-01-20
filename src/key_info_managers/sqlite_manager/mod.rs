// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! A key info manager storing key identity to key info mappings using a SQLite database.
//!
//! For security reasons, only the PARSEC service should have the ability to modify these files.
use super::{KeyIdentity, KeyInfo, ManageKeyInfo};
use crate::authenticators::{ApplicationIdentity, Auth, INTERNAL_AUTH_ID};
use crate::providers::ProviderIdentity;
use crate::utils::config::KeyInfoManagerType;
use anyhow::{Context, Result};
use log::{error, info};
use num_traits::FromPrimitive;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::AuthType;
use rusqlite::types::Type::{Blob, Integer};
use rusqlite::{params, Connection, Error as RusqliteError};
use std::collections::HashMap;
use std::fs;
use std::fs::Permissions;
use std::io::{Error, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Default path where the database will be stored on disk
pub const DEFAULT_DB_PATH: &str =
    "/var/lib/parsec/kim-mappings/sqlite/sqlite-key-info-manager.sqlite3";

///File permissions for sqlite database
///Should only be visible to parsec user
pub const FILE_PERMISSION: u32 = 0o600;

/// The current serialization version of the Attributes object.
pub const CURRENT_KEY_ATTRIBUTES_VERSION: u8 = 1;

/// Placeholder global key_id_version until a new key id version for
/// one of the providers is needed.
pub const CURRENT_KEY_ID_VERSION: u8 = 1;

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

/// Converts a 64 bit integer to an AuthType
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
        fs::create_dir_all(&directory_path)
            .with_context(|| format!("create directory {:?}", directory_path))?;
        // Connect to or create database at set path
        let conn = Connection::open(&database_path)?;
        let mut key_store = HashMap::new();

        // Check if the tables we require exist
        let mut check_for_tables_stmt = conn.prepare(
            "
            SELECT
                *
            FROM
                sqlite_master
            WHERE
                type='table'
                AND (
                    name='key_mapping'
                    OR name='kim_metadata'
                )
        ",
        )?;
        let key_iter = check_for_tables_stmt.query_map([], |_row| Ok(()))?;
        let num_of_tables = key_iter.count();
        match num_of_tables {
            // Create tables as they do not exist.
            0 => {
                let _ = conn.execute(
                    "
                    CREATE TABLE kim_metadata (
                        id                    TEXT NOT NULL,
                        int_value             INTEGER NOT NULL,
                        PRIMARY KEY (id)
                    )
                    ",
                    [],
                )?;
                let _ = conn.execute(
                    "
                    INSERT INTO
                        kim_metadata
                        (id, int_value)
                    VALUES
                        ('schema_version', ?1)
                    ",
                    params![CURRENT_SCHEMA_VERSION],
                )?;
                let _ = conn.execute(
                    "
                    CREATE TABLE IF NOT EXISTS key_mapping (
                        authenticator_id            INTEGER NOT NULL,
                        application_name            TEXT NOT NULL,
                        key_name                    TEXT NOT NULL,
                        provider_uuid               TEXT NOT NULL,
                        provider_name               TEXT NOT NULL,
                        key_id                      BLOB NOT NULL,
                        key_id_version              INTEGER NOT NULL,
                        key_attributes              BLOB NOT NULL,
                        key_attributes_version      INTEGER NOT NULL,
                        PRIMARY KEY (authenticator_id, application_name, key_name)
                    )
                    ",
                    [],
                )?;
            }
            // The correct number of tables are present, no-op
            2 => {}
            // The KIM expects both the kim_metadata and key_mapping table to be present, throw an error
            _ => {
                let error_message = format!(
                    "SQLiteKeyInfoManager database schema is not in a recognised format.
                    There is an unrecognised number of tables in the database.
                    Database found at {}",
                    database_path
                        .into_os_string()
                        .into_string()
                        .unwrap_or_else(|_| "DB_FILE_PATH_UNKNOWN".to_string()),
                );
                error!("{}", error_message);
                return Err(Error::new(ErrorKind::Other, error_message).into());
            }
        }

        // The tables we require exist, check schema version matches
        let mut schema_version_stmt = conn.prepare(
            "
            SELECT
                *
            FROM
                kim_metadata
            WHERE
                id = 'schema_version'
        ",
        )?;
        let mut rows = schema_version_stmt.query(params![])?;
        while let Some(row) = rows.next()? {
            let version_number: u8 = row.get("int_value")?;
            if version_number != CURRENT_SCHEMA_VERSION {
                let error_message = format!(
                    "
                    SQLiteKeyInfoManager database schema version is incompatible.
                    Parsec Service is using version [{}].
                    Database at [{}] is using version [{}].
                    ",
                    CURRENT_SCHEMA_VERSION,
                    database_path
                        .into_os_string()
                        .into_string()
                        .unwrap_or_else(|_| "DB_FILE_PATH_UNKNOWN".to_string()),
                    version_number
                );
                error!("{}", error_message);
                return Err(Error::new(ErrorKind::Other, error_message).into());
            }
        }

        // The tables we require exist and the schema version is the correct.
        // Check that the key_info_version for every key is correct.
        let mut key_info_version_stmt = conn.prepare(
            "
            SELECT
                *
            FROM
                key_mapping
            WHERE
                key_id_version != ?1
                OR key_attributes_version != ?2
            ",
        )?;
        let mut rows = key_info_version_stmt.query(params![
            CURRENT_KEY_ID_VERSION,
            CURRENT_KEY_ATTRIBUTES_VERSION
        ])?;
        // If a mapping exists with the wrong key_id_version or key_attributes_version, throw an error.
        if let Some(row) = rows.next()? {
            let key_id_version: u8 = row.get("key_id_version")?;
            let key_attributes_version: u8 = row.get("key_attributes_version")?;
            let error_message = format!(
                "
                Some records within the SQLiteKeyInfoManager are using an incompatible key_id_version or key_attributes_version.
                Parsec Service SQLiteKeyInfoManager is using [key_id_version={}, key_attributes_version={}].
                Database at [{}] contains mapping(s) using [key_id_version={}, key_attributes_version={}].
                ",
                CURRENT_KEY_ID_VERSION,
                CURRENT_KEY_ATTRIBUTES_VERSION,
                database_path
                    .into_os_string()
                    .into_string()
                    .unwrap_or_else(|_| "DB_FILE_PATH".to_string()),
                key_id_version,
                key_attributes_version,
            );
            error!("{}", error_message);
            return Err(Error::new(ErrorKind::Other, error_message).into());
        }

        // All checks have passed, load key mappings
        let mut key_mapping_stmt = conn.prepare(
            "
            SELECT
                *
            FROM
                key_mapping
            ",
        )?;
        // Deserialize key mappings and store within local key_store HashMap.
        let mut rows = key_mapping_stmt.query(params![])?;
        while let Some(row) = rows.next()? {
            let auth = match row.get("authenticator_id")? {
                INTERNAL_AUTH_ID => Auth::Internal,
                auth_type => Auth::Client(i64_to_auth_type(auth_type).map_err(|e| {
                    format_error!("Failed to get AuthType from authenticator_id.", e);
                    let error = Box::new(Error::new(ErrorKind::InvalidData, e));
                    RusqliteError::FromSqlConversionFailure(64, Integer, error)
                })?),
            };
            let key_identity = KeyIdentity::new(
                ApplicationIdentity::new_with_auth(row.get("application_name")?, auth),
                ProviderIdentity::new(row.get("provider_uuid")?, row.get("provider_name")?),
                row.get("key_name")?,
            );

            let key_id: Vec<u8> = row.get("key_id")?;
            let key_attributes_blob: Vec<u8> = row.get("key_attributes")?;
            let key_attributes: Attributes = bincode::deserialize(&key_attributes_blob[..])
                .map_err(|e| {
                    format_error!("Error deserializing key attributes", e);
                    RusqliteError::FromSqlConversionFailure(key_attributes_blob.len(), Blob, e)
                })?;

            let key_info = KeyInfo {
                id: key_id,
                attributes: key_attributes,
            };

            let _ = key_store.insert(key_identity, key_info);
        }

        if !crate::utils::GlobalConfig::log_error_details() {
            info!(
                "SQLiteKeyInfoManager - Found {} key info mapping records",
                key_store.len()
            );
        }

        let permissions = Permissions::from_mode(FILE_PERMISSION);
        fs::set_permissions(database_path.clone(), permissions)?;

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

        // The key_info.id should already be serialized using bincode at this stage by the
        // KIM client insert_key_info() function.
        let key_id_blob = key_info.id.clone();
        // TODO: Change this to (protobuf?) version once format has been decided.
        // https://github.com/parallaxsecond/parsec/issues/424#issuecomment-883608164
        let key_attributes_blob = bincode::serialize(&key_info.attributes).map_err(|e| {
            format_error!("Error serializing key info", e);
            RusqliteError::ToSqlConversionFailure(e)
        })?;

        // Insert the new key mapping, if a record does not exist.
        // If one does exist, replace the existing record.
        let _ = conn.execute(
            "
            REPLACE INTO
                `key_mapping`
                (`authenticator_id`, `application_name`, `provider_uuid`, `provider_name`, `key_name`, `key_id`, `key_id_version`, `key_attributes`, `key_attributes_version`)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);
            ",
            params![
                key_identity.application().authenticator_id(),
                key_identity.application().name(),
                key_identity.provider().uuid(),
                key_identity.provider().name(),
                key_identity.key_name(),
                key_id_blob,
                // Key ID versioning will eventually need passing down from individual providers
                // if the serialization structure of one of them changes.
                CURRENT_KEY_ID_VERSION,
                key_attributes_blob,
                CURRENT_KEY_ATTRIBUTES_VERSION,
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
                key_identity.application().authenticator_id(),
                key_identity.application().name(),
                key_identity.key_name(),
            ],
        )?;
        Ok(())
    }
}

impl ManageKeyInfo for SQLiteKeyInfoManager {
    fn key_info_manager_type(&self) -> KeyInfoManagerType {
        KeyInfoManagerType::SQLite
    }

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
    use crate::key_info_managers::sqlite_manager::FILE_PERMISSION;
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
    use rand::Rng;
    use std::fs;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn test_key_attributes() -> Attributes {
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::Derive,
            bits: 1024,
            policy: Policy {
                usage_flags: {
                    let mut usage_flags = UsageFlags::default();
                    let _ = usage_flags.set_sign_hash();
                    usage_flags
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

    fn test_key_info_with_random_id() -> KeyInfo {
        let mut rng = rand::thread_rng();
        KeyInfo {
            id: vec![rng.gen(), rng.gen(), rng.gen()],
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

    /// Test that keys with identical identities (aside from authenticator id)
    /// produce separate entries.
    #[test]
    fn namespace_authenticator_id() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/namespace_authenticator_id.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_name = "key_name".to_string();
        let app_name = "the_application".to_string();

        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name.clone(), AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name.clone(),
        );
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name, AuthType::Direct),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name,
        );

        let key_info_1 = test_key_info_with_random_id();
        let key_info_2 = test_key_info_with_random_id();

        let _ = manager
            .insert(key_identity_1.clone(), key_info_1.clone())
            .unwrap();
        let _ = manager
            .insert(key_identity_2.clone(), key_info_2.clone())
            .unwrap();

        assert_eq!(
            manager.remove(&key_identity_1).unwrap().unwrap(),
            key_info_1
        );
        assert_eq!(
            manager.remove(&key_identity_2).unwrap().unwrap(),
            key_info_2
        );

        fs::remove_file(&path).unwrap();
    }

    /// Test that keys with identical identities (aside from application name)
    /// produce separate entries.
    #[test]
    fn namespace_application_name() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/namespace_application_name.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_name = "key_name".to_string();
        let app_name_1 = "application_1".to_string();
        let app_name_2 = "application_2".to_string();

        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name_1, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name.clone(),
        );
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name_2, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name,
        );

        let key_info_1 = test_key_info_with_random_id();
        let key_info_2 = test_key_info_with_random_id();

        let _ = manager
            .insert(key_identity_1.clone(), key_info_1.clone())
            .unwrap();
        let _ = manager
            .insert(key_identity_2.clone(), key_info_2.clone())
            .unwrap();

        assert_eq!(
            manager.remove(&key_identity_1).unwrap().unwrap(),
            key_info_1
        );
        assert_eq!(
            manager.remove(&key_identity_2).unwrap().unwrap(),
            key_info_2
        );

        fs::remove_file(&path).unwrap();
    }

    /// Test that keys with identical identities (aside from key name)
    /// produce separate entries.
    #[test]
    fn namespace_key_name() {
        let path =
            PathBuf::from(env!("OUT_DIR").to_owned() + "/kim/sqlite/namespace_key_name.sqlite3");
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_name_1 = "key_1".to_string();
        let key_name_2 = "key_2".to_string();
        let app_name = "the_application".to_string();

        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name.clone(), AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name_1,
        );
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name_2,
        );

        let key_info_1 = test_key_info_with_random_id();
        let key_info_2 = test_key_info_with_random_id();

        let _ = manager
            .insert(key_identity_1.clone(), key_info_1.clone())
            .unwrap();
        let _ = manager
            .insert(key_identity_2.clone(), key_info_2.clone())
            .unwrap();

        assert_eq!(
            manager.remove(&key_identity_1).unwrap().unwrap(),
            key_info_1
        );
        assert_eq!(
            manager.remove(&key_identity_2).unwrap().unwrap(),
            key_info_2
        );

        fs::remove_file(&path).unwrap();
    }

    /// Test that keys with identical identities (aside from provider name)
    /// produce the same entry.
    #[test]
    fn namespace_provider_name() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/namespace_provider_name.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_name = "key_name".to_string();
        let app_name = "the_application".to_string();

        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name.clone(), AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                "One provider name".to_string(),
            ),
            key_name.clone(),
        );
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                "Another provider name".to_string(),
            ),
            key_name,
        );

        let key_info = test_key_info_with_random_id();

        let _ = manager.insert(key_identity_1, key_info.clone()).unwrap();

        assert_eq!(manager.remove(&key_identity_2).unwrap().unwrap(), key_info);

        fs::remove_file(&path).unwrap();
    }

    /// Test that keys with identical identities (aside from provider name)
    /// produce the same entry.
    #[test]
    fn namespace_provider_uuid() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned() + "/kim/sqlite/namespace_provider_uuid.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();
        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let key_name = "key_name".to_string();
        let app_name = "the_application".to_string();

        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name.clone(), AuthType::NoAuth),
            ProviderIdentity::new(
                "some-random-uuid".to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name.clone(),
        );
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new(app_name, AuthType::NoAuth),
            ProviderIdentity::new(
                "some-random-uuid-that-isn't-the-same".to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name,
        );

        let key_info = test_key_info_with_random_id();

        let _ = manager.insert(key_identity_1, key_info.clone()).unwrap();

        assert_eq!(manager.remove(&key_identity_2).unwrap().unwrap(), key_info);

        fs::remove_file(&path).unwrap();
    }

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

    #[cfg(feature = "mbed-crypto-provider")]
    #[test]
    fn create_and_load_internal_keys() {
        let path = PathBuf::from(
            env!("OUT_DIR").to_owned()
                + "/kim/sqlite/create_and_load_mappings_internal_keys.sqlite3",
        );
        fs::remove_file(&path).unwrap_or_default();

        let key_name1 = "😀 Key One 😀".to_string();
        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new_internal(),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name1,
        );
        let key_info1 = test_key_info();

        let key_name2 = "😇 Key Two 😇".to_string();
        let key_identity_2 = KeyIdentity::new(
            ApplicationIdentity::new_internal(),
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

        {
            let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

            let _ = manager
                .insert(key_identity_1.clone(), key_info1.clone())
                .unwrap();
            let _ = manager
                .insert(key_identity_2.clone(), key_info2.clone())
                .unwrap();
        }
        // The local hashmap is dropped when leaving the inner scope.
        {
            let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

            assert_eq!(
                manager
                    .get_all(key_identity_1.provider.clone())
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                manager
                    .get_all(key_identity_2.provider.clone())
                    .unwrap()
                    .len(),
                1
            );

            // get() should return the key info of the internal key!
            assert_eq!(&key_info1, manager.get(&key_identity_1).unwrap().unwrap());

            // get() should not work for the same key if it is marked as External!
            let mut key_identity3 = key_identity_2.clone();
            key_identity3.application = ApplicationIdentity::new(
                key_identity_2.application().name().to_string(),
                AuthType::UnixPeerCredentials,
            );
            assert_eq!(None, manager.get(&key_identity3).unwrap());

            assert_eq!(manager.remove(&key_identity_1).unwrap().unwrap(), key_info1);
            assert_eq!(manager.remove(&key_identity_2).unwrap().unwrap(), key_info2);
            assert_eq!(
                manager
                    .get_all(key_identity_1.provider.clone())
                    .unwrap()
                    .len(),
                0
            );
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

    #[test]
    fn check_permissions() {
        let path =
            PathBuf::from(env!("OUT_DIR").to_owned() + "/kim/sqlite/check_permissions.sqlite3");
        fs::remove_file(&path).unwrap_or_default();

        let app_name1 = "App1".to_string();
        let key_name1 = "Key1".to_string();
        let key_identity_1 = KeyIdentity::new(
            ApplicationIdentity::new(app_name1, AuthType::NoAuth),
            ProviderIdentity::new(
                CoreProvider::PROVIDER_UUID.to_string(),
                CoreProvider::DEFAULT_PROVIDER_NAME.to_string(),
            ),
            key_name1,
        );
        let key_info1 = test_key_info();

        let mut manager = SQLiteKeyInfoManager::new(path.clone()).unwrap();

        let _ = manager.insert(key_identity_1.clone(), key_info1).unwrap();

        let permissions = Permissions::from_mode(FILE_PERMISSION);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & permissions.mode(),
            permissions.mode()
        );

        let _ = manager.remove(&key_identity_1).unwrap().unwrap();

        fs::remove_file(&path).unwrap();
    }
}
