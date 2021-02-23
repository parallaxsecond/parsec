// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! A key info manager storing key triple to key info mapping on files on disk
//!
//! The path where the mappings should be stored is configurable. Because of possible data races,
//! there should not be two instances of this manager pointing to the same mapping folder at a time.
//! Methods modifying the mapping will also block until the modifications are done on disk to be
//! ensured to not lose mappings.
//! Because application and key names can contain any UTF-8 characters, those strings are converted
//! to base64 strings so that they can be used as filenames. Because of filenames limitations, some
//! very long UTF-8 names might not be able to be represented as a filename and will fail. For
//! example, for operating systems having a limit of 255 characters for filenames (Unix systems),
//! names will be limited to 188 bytes of UTF-8 characters.
//! For security reasons, only the PARSEC service should have the ability to modify these files.
use super::{KeyInfo, KeyTriple, ManageKeyInfo};
use crate::authenticators::ApplicationName;
use anyhow::{Context, Result};
use log::{error, info, warn};
use parsec_interface::requests::ProviderID;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::fs::{DirEntry, File};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

/// Default path where the mapping files will be stored on disk
pub const DEFAULT_MAPPINGS_PATH: &str = "/var/lib/parsec/mappings";

/// A key info manager storing key triple to key info mapping on files on disk
#[derive(Debug)]
pub struct OnDiskKeyInfoManager {
    /// Internal mapping, used for non-modifying operations.
    key_store: HashMap<KeyTriple, KeyInfo>,
    /// Folder where all the key triple to key info mappings are saved. This folder will be created
    /// if it does already exist.
    mappings_dir_path: PathBuf,
}

/// Encodes a KeyTriple's data into base64 strings that can be used as filenames.
/// The ProviderID will not be converted as a base64 as it can always be represented as a String
/// being a number from 0 and 255.
fn key_triple_to_base64_filenames(key_triple: &KeyTriple) -> (String, String, String) {
    (
        base64::encode_config(key_triple.app_name.as_bytes(), base64::URL_SAFE),
        (key_triple.provider_id as u8).to_string(),
        base64::encode_config(key_triple.key_name.as_bytes(), base64::URL_SAFE),
    )
}

/// Decodes base64 bytes to its original String value.
///
/// # Errors
///
/// Returns an error as a string if either the decoding or the bytes conversion to UTF-8 failed.
fn base64_data_to_string(base64_bytes: &[u8]) -> Result<String, String> {
    match base64::decode_config(base64_bytes, base64::URL_SAFE) {
        Ok(decode_bytes) => match String::from_utf8(decode_bytes) {
            Ok(string) => Ok(string),
            Err(error) => Err(error.to_string()),
        },
        Err(error) => Err(error.to_string()),
    }
}

/// Decodes key triple's data to the original path.
/// The Provider ID data is not converted as base64.
///
/// # Errors
///
/// Returns an error as a string if either the decoding or the bytes conversion to UTF-8 failed.
fn base64_data_triple_to_key_triple(
    app_name: &[u8],
    provider_id: ProviderID,
    key_name: &[u8],
) -> Result<KeyTriple, String> {
    let app_name = ApplicationName::from_name(base64_data_to_string(app_name)?);
    let key_name = base64_data_to_string(key_name)?;

    Ok(KeyTriple {
        app_name,
        provider_id,
        key_name,
    })
}

/// Converts an OsStr reference to a byte array.
///
/// # Errors
///
/// Returns a custom std::io error if the conversion failed.
fn os_str_to_u8_ref(os_str: &OsStr) -> std::io::Result<&[u8]> {
    match os_str.to_str() {
        Some(str) => Ok(str.as_bytes()),
        None => Err(Error::new(
            ErrorKind::Other,
            "Conversion from PathBuf to String failed.",
        )),
    }
}

/// Converts an OsStr reference to a ProviderID value.
///
/// # Errors
///
/// Returns a custom std::io error if the conversion failed.
fn os_str_to_provider_id(os_str: &OsStr) -> std::io::Result<ProviderID> {
    match os_str.to_str() {
        Some(str) => match str.parse::<u8>() {
            Ok(provider_id_u8) => match ProviderID::try_from(provider_id_u8) {
                Ok(provider_id) => Ok(provider_id),
                Err(response_status) => {
                    Err(Error::new(ErrorKind::Other, response_status.to_string()))
                }
            },
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "Failed to convert Provider directory name to an u8 number.",
            )),
        },
        None => Err(Error::new(
            ErrorKind::Other,
            "Conversion from PathBuf to String failed.",
        )),
    }
}

/// Lists all the directory paths in the given directory path.
fn list_dirs(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    // read_dir returning an iterator over Result<DirEntry>, there is first a conversion to a path
    // and then a check if the path is a directory or not.
    let dir_entries: std::io::Result<Vec<DirEntry>> = path.read_dir()?.collect();
    Ok(dir_entries?
        .iter()
        .map(|dir_entry| dir_entry.path())
        .filter(|dir_path| dir_path.is_dir())
        .collect())
}

/// Lists all the file paths in the given directory path.
fn list_files(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir_entries: std::io::Result<Vec<DirEntry>> = path.read_dir()?.collect();
    Ok(dir_entries?
        .iter()
        .map(|dir_entry| dir_entry.path())
        .filter(|dir_path| dir_path.is_file())
        .collect())
}

/// Filesystem-based `KeyInfoManager`
///
/// The `OnDiskKeyInfoManager` relies on access control mechanisms provided by the OS for
/// the filesystem to ensure security of the mappings.
impl OnDiskKeyInfoManager {
    /// Creates an instance of the on-disk manager from the mapping files. This function will
    /// create the mappings directory if it does not already exist.
    /// The mappings folder is composed of three levels: two levels of directory and one level
    /// of files. The key triple to key info mappings are represented on disk as the following:
    ///
    /// mappings_dir_path/
    /// |---app1/
    /// |   |---provider1/
    /// |   |   |---key1
    /// |   |   |---key2
    /// |   |   |   ...
    /// |   |   |---keyP
    /// |   |---provider2/
    /// |   |   ...
    /// |   |---providerM/
    /// |---app2/
    /// |   ...
    /// |---appN/
    ///
    /// where the path of a key name from the mappings directory is the key triple (application,
    /// provider, key) and the data inside the key name file is the key info serialised in binary
    /// format.
    /// Each mapping is contained in its own file to prevent the modification of one mapping
    /// impacting the other ones.
    ///
    /// # Errors
    ///
    /// Returns an std::io error if the function failed reading the mapping files.
    fn new(mappings_dir_path: PathBuf) -> Result<OnDiskKeyInfoManager> {
        let mut key_store = HashMap::new();

        // Will ignore if the mappings directory already exists.
        fs::create_dir_all(&mappings_dir_path).with_context(|| {
            format!(
                "Failed to create Key Info Mappings directory at {:?}",
                mappings_dir_path
            )
        })?;

        for app_name_dir_path in list_dirs(&mappings_dir_path)?.iter() {
            for provider_dir_path in list_dirs(&app_name_dir_path)?.iter() {
                for key_name_file_path in list_files(&provider_dir_path)?.iter() {
                    let mut key_info = Vec::new();
                    let mut key_info_file = File::open(&key_name_file_path).with_context(|| {
                        format!(
                            "Failed to open Key Info Mappings file at {:?}",
                            key_name_file_path
                        )
                    })?;
                    let _ = key_info_file.read_to_end(&mut key_info)?;
                    let key_info = bincode::deserialize(&key_info[..]).map_err(|e| {
                        format_error!("Error deserializing key info", e);
                        Error::new(ErrorKind::Other, "error deserializing key info")
                    })?;
                    match base64_data_triple_to_key_triple(
                        os_str_to_u8_ref(app_name_dir_path.file_name().expect(
                            "The application name directory path should contain a final component.",
                        ))?,
                        os_str_to_provider_id(provider_dir_path.file_name().expect(
                            "The provider directory path should contain a final component.",
                        ))?,
                        os_str_to_u8_ref(key_name_file_path.file_name().expect(
                            "The key name directory path should contain a final component.",
                        ))?,
                    ) {
                        Ok(key_triple) => {
                            if crate::utils::GlobalConfig::log_error_details() {
                                warn!(
                                    "Inserting Key Triple ({}) mapping read from disk.",
                                    key_triple.clone()
                                );
                            }
                            let _ = key_store.insert(key_triple, key_info);
                        }
                        Err(string) => {
                            format_error!(
                                "Failed to convert the mapping path found to an UTF-8 string",
                                string
                            );
                            return Err(
                                Error::new(ErrorKind::Other, "error parsing mapping path").into()
                            );
                        }
                    }
                }
            }
        }

        if !crate::utils::GlobalConfig::log_error_details() {
            info!("Found {} mapping files", key_store.len());
        }

        Ok(OnDiskKeyInfoManager {
            key_store,
            mappings_dir_path,
        })
    }

    /// Saves the key triple to key info mapping in its own file.
    /// The filename will be `mappings/[APP_NAME]/[PROVIDER_NAME]/[KEY_NAME]` under the same path as the
    /// on-disk manager. It will contain the Key info data.
    fn save_mapping(&self, key_triple: &KeyTriple, key_info: &KeyInfo) -> std::io::Result<()> {
        if crate::utils::GlobalConfig::log_error_details() {
            warn!(
                "Saving Key Triple ({}) mapping to disk.",
                key_triple.clone()
            );
        }
        // Create the directories with base64 names.
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let provider_dir_path = self.mappings_dir_path.join(app_name).join(prov);
        let key_name_file_path = provider_dir_path.join(key_name);
        // Will ignore if they already exist.
        fs::create_dir_all(&provider_dir_path)?;

        if key_name_file_path.exists() {
            fs::remove_file(&key_name_file_path)?;
        }

        let mut mapping_file = fs::File::create(&key_name_file_path).map_err(|e| {
            error!(
                "Failed to create Key Info Mapping file at {:?}",
                key_name_file_path
            );
            e
        })?;
        mapping_file.write_all(&bincode::serialize(key_info).map_err(|e| {
            format_error!("Error serializing key info", e);
            Error::new(ErrorKind::Other, "error serializing key info")
        })?)
    }

    /// Removes the mapping file.
    /// Will do nothing if the mapping file does not exist.
    fn delete_mapping(&self, key_triple: &KeyTriple) -> std::io::Result<()> {
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let key_name_file_path = self
            .mappings_dir_path
            .join(app_name)
            .join(prov)
            .join(key_name);
        if key_name_file_path.exists() {
            fs::remove_file(key_name_file_path)
        } else {
            Ok(())
        }
    }
}

impl ManageKeyInfo for OnDiskKeyInfoManager {
    fn get(&self, key_triple: &KeyTriple) -> Result<Option<&KeyInfo>, String> {
        // An Option<&Vec<u8>> can not automatically coerce to an Option<&[u8]>, it needs to be
        // done by hand.
        if let Some(key_info) = self.key_store.get(key_triple) {
            Ok(Some(key_info))
        } else {
            Ok(None)
        }
    }

    fn get_all(&self, provider_id: ProviderID) -> Result<Vec<&KeyTriple>, String> {
        Ok(self
            .key_store
            .keys()
            .filter(|key_triple| key_triple.belongs_to_provider(provider_id))
            .collect())
    }

    fn insert(
        &mut self,
        key_triple: KeyTriple,
        key_info: KeyInfo,
    ) -> Result<Option<KeyInfo>, String> {
        if let Err(err) = self.save_mapping(&key_triple, &key_info) {
            Err(err.to_string())
        } else {
            Ok(self.key_store.insert(key_triple, key_info))
        }
    }

    fn remove(&mut self, key_triple: &KeyTriple) -> Result<Option<KeyInfo>, String> {
        if let Err(err) = self.delete_mapping(key_triple) {
            Err(err.to_string())
        } else if let Some(key_info) = self.key_store.remove(key_triple) {
            Ok(Some(key_info))
        } else {
            Ok(None)
        }
    }

    fn exists(&self, key_triple: &KeyTriple) -> Result<bool, String> {
        Ok(self.key_store.contains_key(key_triple))
    }
}

/// OnDiskKeyInfoManager builder
#[derive(Debug, Default)]
pub struct OnDiskKeyInfoManagerBuilder {
    mappings_dir_path: Option<PathBuf>,
}

impl OnDiskKeyInfoManagerBuilder {
    /// Create a new OnDiskKeyInfoManagerBuilder
    pub fn new() -> OnDiskKeyInfoManagerBuilder {
        OnDiskKeyInfoManagerBuilder {
            mappings_dir_path: None,
        }
    }

    /// Add a mappings directory path to the builder
    pub fn with_mappings_dir_path(mut self, path: PathBuf) -> OnDiskKeyInfoManagerBuilder {
        self.mappings_dir_path = Some(path);

        self
    }

    /// Build into a OnDiskKeyInfoManager
    pub fn build(self) -> Result<OnDiskKeyInfoManager> {
        OnDiskKeyInfoManager::new(
            self.mappings_dir_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MAPPINGS_PATH)),
        )
    }
}

#[cfg(test)]
mod test {
    use super::super::{KeyInfo, KeyTriple, ManageKeyInfo};
    use super::OnDiskKeyInfoManager;
    use crate::authenticators::ApplicationName;
    use parsec_interface::operations::psa_algorithm::{
        Algorithm, AsymmetricSignature, Hash, SignHash,
    };
    use parsec_interface::operations::psa_key_attributes::{
        Attributes, Lifetime, Policy, Type, UsageFlags,
    };
    use parsec_interface::requests::ProviderID;
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
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_get_key_info_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_get_key_info".to_string());
        let key_info = test_key_info();

        assert!(manager.get(&key_triple).unwrap().is_none());

        assert!(manager
            .insert(key_triple.clone(), key_info.clone())
            .unwrap()
            .is_none());

        let stored_key_info = manager
            .get(&key_triple)
            .unwrap()
            .expect("Failed to get key info")
            .clone();

        assert_eq!(stored_key_info, key_info);
        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_remove_key() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_remove_key_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_remove_key".to_string());
        let key_info = test_key_info();

        let _ = manager.insert(key_triple.clone(), key_info).unwrap();

        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn remove_unexisting_key() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/remove_unexisting_key_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("remove_unexisting_key".to_string());
        assert_eq!(manager.remove(&key_triple).unwrap(), None);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exists() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/exists_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("exists".to_string());
        let key_info = test_key_info();

        assert!(!manager.exists(&key_triple).unwrap());

        let _ = manager.insert(key_triple.clone(), key_info).unwrap();
        assert!(manager.exists(&key_triple).unwrap());

        let _ = manager.remove(&key_triple).unwrap();
        assert!(!manager.exists(&key_triple).unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_overwrites() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_overwrites_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_overwrites".to_string());
        let key_info_1 = test_key_info();
        let key_info_2 = KeyInfo {
            id: vec![0xaa, 0xbb, 0xcc],
            attributes: test_key_attributes(),
        };

        let _ = manager.insert(key_triple.clone(), key_info_1).unwrap();
        let _ = manager
            .insert(key_triple.clone(), key_info_2.clone())
            .unwrap();

        let stored_key_info = manager
            .get(&key_triple)
            .unwrap()
            .expect("Failed to get key info")
            .clone();

        assert_eq!(stored_key_info, key_info_2);
        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_ascii() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/big_names_ascii_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let big_app_name_ascii = ApplicationName::from_name("  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string());
        let big_key_name_ascii = "  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string();

        let key_triple = KeyTriple::new(big_app_name_ascii, ProviderID::Core, big_key_name_ascii);
        let key_info = test_key_info();

        let _ = manager
            .insert(key_triple.clone(), key_info.clone())
            .unwrap();
        assert_eq!(manager.remove(&key_triple).unwrap().unwrap(), key_info);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_emoticons() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/big_names_emoticons_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

        let big_app_name_emoticons = ApplicationName::from_name("😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string());
        let big_key_name_emoticons = "😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string();

        let key_triple = KeyTriple::new(
            big_app_name_emoticons,
            ProviderID::MbedCrypto,
            big_key_name_emoticons,
        );
        let key_info = test_key_info();

        let _ = manager
            .insert(key_triple.clone(), key_info.clone())
            .unwrap();
        assert_eq!(manager.remove(&key_triple).unwrap().unwrap(), key_info);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn create_and_load() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/create_and_load_mappings");

        let app_name1 = ApplicationName::from_name("😀 Application One 😀".to_string());
        let key_name1 = "😀 Key One 😀".to_string();
        let key_triple1 = KeyTriple::new(app_name1, ProviderID::Core, key_name1);
        let key_info1 = test_key_info();

        let app_name2 = ApplicationName::from_name("😇 Application Two 😇".to_string());
        let key_name2 = "😇 Key Two 😇".to_string();
        let key_triple2 = KeyTriple::new(app_name2, ProviderID::MbedCrypto, key_name2);
        let key_info2 = KeyInfo {
            id: vec![0x12, 0x22, 0x32],
            attributes: test_key_attributes(),
        };

        let app_name3 = ApplicationName::from_name("😈 Application Three 😈".to_string());
        let key_name3 = "😈 Key Three 😈".to_string();
        let key_triple3 = KeyTriple::new(app_name3, ProviderID::Core, key_name3);
        let key_info3 = KeyInfo {
            id: vec![0x13, 0x23, 0x33],
            attributes: test_key_attributes(),
        };
        {
            let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

            let _ = manager
                .insert(key_triple1.clone(), key_info1.clone())
                .unwrap();
            let _ = manager
                .insert(key_triple2.clone(), key_info2.clone())
                .unwrap();
            let _ = manager
                .insert(key_triple3.clone(), key_info3.clone())
                .unwrap();
        }
        // The local hashmap is dropped when leaving the inner scope.
        {
            let mut manager = OnDiskKeyInfoManager::new(path.clone()).unwrap();

            assert_eq!(manager.remove(&key_triple1).unwrap().unwrap(), key_info1);
            assert_eq!(manager.remove(&key_triple2).unwrap().unwrap(), key_info2);
            assert_eq!(manager.remove(&key_triple3).unwrap().unwrap(), key_info3);
        }

        fs::remove_dir_all(path).unwrap();
    }

    fn new_key_triple(key_name: String) -> KeyTriple {
        KeyTriple::new(
            ApplicationName::from_name("Testing Application 😎".to_string()),
            ProviderID::MbedCrypto,
            key_name,
        )
    }
}
