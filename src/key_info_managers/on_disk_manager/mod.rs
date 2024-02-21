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
use crate::authenticators::{Application, ApplicationIdentity, Auth, INTERNAL_APP_NAME};
use crate::utils::config::KeyInfoManagerType;

use super::{KeyIdentity, KeyInfo, ManageKeyInfo, ProviderIdentity};
use crate::providers::core::Provider as CoreProvider;
#[cfg(feature = "cryptoauthlib-provider")]
use crate::providers::cryptoauthlib::Provider as CryptoAuthLibProvider;
#[cfg(feature = "mbed-crypto-provider")]
use crate::providers::mbed_crypto::Provider as MbedCryptoProvider;
#[cfg(feature = "pkcs11-provider")]
use crate::providers::pkcs11::Provider as Pkcs11Provider;
#[cfg(feature = "tpm-provider")]
use crate::providers::tpm::Provider as TpmProvider;
#[cfg(feature = "trusted-service-provider")]
use crate::providers::trusted_service::Provider as TrustedServiceProvider;
use anyhow::{Context, Result};
use base64::Engine;
use log::{error, info, warn};
use parsec_interface::requests::{AuthType, ProviderId};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::Permissions;
use std::fs::{DirEntry, File};
use std::io::{Error, ErrorKind, Read, Write};
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{fmt, fs};

/// Default path where the mapping files will be stored on disk
pub const DEFAULT_MAPPINGS_PATH: &str = "/var/lib/parsec/mappings";

/// Directory in which the internal keys file will be held
const INTERNAL_KEYS_PARSEC_DIR: &str = INTERNAL_APP_NAME;

///Permissions for all directories under database directory
///Should only be visible to parsec user
pub const DIR_PERMISSION: u32 = 0o700;

///Permissions for all files under database directory
///Should only be visible to parsec user
pub const FILE_PERMISSION: u32 = 0o600;

const CORE_PROVIDER: &str = "core";
const PKCS11_PROVIDER: &str = "pkcs11";
const MBEDCRYPTO_PROVIDER: &str = "mbedcrypto";
const TPM_PROVIDER: &str = "tpm";
const TRUSTEDS_PROVIDER: &str = "trusted-service";
const CRYPTOAUTH_PROVIDER: &str = "cryptoauthlib";

/// Provider names for internal storage.
const PROVIDER_NAMES: [&str; 6] = [
    CORE_PROVIDER,
    PKCS11_PROVIDER,
    MBEDCRYPTO_PROVIDER,
    TPM_PROVIDER,
    TRUSTEDS_PROVIDER,
    CRYPTOAUTH_PROVIDER,
];

/// String wrapper for app names
#[deprecated(since = "0.9.0", note = "ApplicationIdentity should be used instead.")]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ApplicationName {
    name: String,
}

#[allow(deprecated)]
impl Deref for ApplicationName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

#[allow(deprecated)]
#[deprecated(since = "0.9.0", note = "ApplicationIdentity should be used instead.")]
impl ApplicationName {
    /// Create ApplicationName from name string only
    pub fn from_name(name: String) -> ApplicationName {
        ApplicationName { name }
    }
}

#[allow(deprecated)]
impl fmt::Display for ApplicationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[allow(deprecated)]
impl From<Application> for ApplicationName {
    fn from(app: Application) -> Self {
        ApplicationName::from_name(app.identity().name().clone())
    }
}

/// Should only be used internally to map KeyTriple to the new KeyIdentity
/// for the on_disk_manager KeyInfoManager.
/// Structure corresponds to a unique identifier of the key.
/// It is used internally by the Key ID manager to refer to a key.
#[deprecated(since = "0.9.0", note = "KeyIdentity should be used instead.")]
#[allow(deprecated)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyTriple {
    app_name: ApplicationName,
    provider_id: ProviderId,
    key_name: String,
}

#[allow(deprecated)]
#[deprecated(since = "0.9.0", note = "KeyIdentity should be used instead.")]
impl KeyTriple {
    /// Creates a new instance of KeyTriple.
    pub fn new(app_name: ApplicationName, provider_id: ProviderId, key_name: String) -> KeyTriple {
        KeyTriple {
            app_name,
            provider_id,
            key_name,
        }
    }

    /// Checks if this key belongs to a specific provider.
    pub fn belongs_to_provider(&self, provider_id: ProviderId) -> bool {
        self.provider_id == provider_id
    }
    /// Get the provider id
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Get the key name
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Get the app name
    pub fn app_name(&self) -> &ApplicationName {
        &self.app_name
    }
}

#[allow(deprecated)]
impl fmt::Display for KeyTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyTriple: app_name=\"{}\" provider_id={} key_name=\"{}\"",
            self.app_name, self.provider_id, self.key_name
        )
    }
}

#[allow(deprecated)]
impl TryFrom<KeyIdentity> for KeyTriple {
    type Error = String;

    fn try_from(key_identity: KeyIdentity) -> std::result::Result<Self, Self::Error> {
        let provider_id = match key_identity.provider.uuid().as_str() {
            CoreProvider::PROVIDER_UUID => Ok(ProviderId::Core),
            #[cfg(feature = "cryptoauthlib-provider")]
            CryptoAuthLibProvider::PROVIDER_UUID => Ok(ProviderId::CryptoAuthLib),
            #[cfg(feature = "mbed-crypto-provider")]
            MbedCryptoProvider::PROVIDER_UUID => Ok(ProviderId::MbedCrypto),
            #[cfg(feature = "pkcs11-provider")]
            Pkcs11Provider::PROVIDER_UUID => Ok(ProviderId::Pkcs11),
            #[cfg(feature = "tpm-provider")]
            TpmProvider::PROVIDER_UUID => Ok(ProviderId::Tpm),
            #[cfg(feature = "trusted-service-provider")]
            TrustedServiceProvider::PROVIDER_UUID => Ok(ProviderId::TrustedService),
            _ => Err(format!(
                "Cannot convert from KeyIdentity to KeyTriple.
                Provider \"{}\" is not recognised.
                Could be it does not exist, or Parsec was not compiled with the required provider feature flags.",
                key_identity.provider().uuid()
            )),
        }?;

        Ok(KeyTriple {
            provider_id,
            app_name: ApplicationName::from_name(key_identity.application().name().to_string()),
            key_name: key_identity.key_name,
        })
    }
}

#[allow(deprecated)]
impl TryFrom<(KeyTriple, ProviderIdentity, Auth)> for KeyIdentity {
    type Error = String;

    fn try_from(
        (key_triple, provider_identity, auth): (KeyTriple, ProviderIdentity, Auth),
    ) -> std::result::Result<Self, Self::Error> {
        // Result types required by clippy as Err result has the possibility of not being compiled.
        let provider_uuid = match key_triple.provider_id {
            ProviderId::Core => Ok::<String, Self::Error>(
                CoreProvider::PROVIDER_UUID.to_string(),
            ),
            #[cfg(feature = "cryptoauthlib-provider")]
            ProviderId::CryptoAuthLib => Ok::<String, Self::Error>(CryptoAuthLibProvider::PROVIDER_UUID.to_string()),
            #[cfg(feature = "mbed-crypto-provider")]
            ProviderId::MbedCrypto => Ok::<String, Self::Error>(MbedCryptoProvider::PROVIDER_UUID.to_string()),
            #[cfg(feature = "pkcs11-provider")]
            ProviderId::Pkcs11 => Ok::<String, Self::Error>(Pkcs11Provider::PROVIDER_UUID.to_string()),
            #[cfg(feature = "tpm-provider")]
            ProviderId::Tpm => Ok::<String, Self::Error>(TpmProvider::PROVIDER_UUID.to_string()),
            #[cfg(feature = "trusted-service-provider")]
            ProviderId::TrustedService => Ok::<String, Self::Error>(TrustedServiceProvider::PROVIDER_UUID.to_string()),
            #[cfg(not(all(
                feature = "cryptoauthlib-provider",
                feature = "mbed-crypto-provider",
                feature = "pkcs11-provider",
                feature = "tpm-provider",
                feature = "trusted-service-provider",
            )))]
            _ => Err(format!("Cannot convert from KeyTriple to KeyIdentity.\nProvider \"{}\" is not recognised.\nCould be it does not exist, or Parsec was not compiled with the required provider feature flags.", key_triple.provider_id)),
        }?;

        let app_identity = match auth {
            Auth::Internal => ApplicationIdentity::new_internal(),
            Auth::Client(auth_type) => {
                ApplicationIdentity::new(key_triple.app_name().to_string(), auth_type)
            }
        };
        Ok(KeyIdentity {
            provider: ProviderIdentity::new(provider_uuid, provider_identity.name().clone()),
            application: app_identity,
            key_name: key_triple.key_name,
        })
    }
}

/// A key info manager storing key triple to key info mapping on files on disk
#[derive(Debug)]
pub struct OnDiskKeyInfoManager {
    /// Internal mapping, used for non-modifying operations.
    #[allow(deprecated)]
    key_store: HashMap<KeyTriple, KeyInfo>,
    /// Internal mapping with Internal Keys, used for non-modifying operations.
    #[allow(deprecated)]
    key_store_internal: HashMap<KeyTriple, KeyInfo>,
    /// Folder where all the key triple to key info mappings are saved. This folder will be created
    /// if it does already exist.
    mappings_dir_path: PathBuf,
    /// The AuthType currently being used by Parsec and hence used to namespace the OnDiskKeyInfoManager.
    auth_type: AuthType,
}

/// Encodes a KeyTriple's data into base64 strings that can be used as filenames.
/// The ProviderId will not be converted as a base64 as it can always be represented as a String
/// being a number from 0 and 255.
#[allow(deprecated)]
fn key_triple_to_base64_filenames(key_triple: &KeyTriple) -> (String, String, String) {
    (
        base64::engine::general_purpose::URL_SAFE.encode(key_triple.app_name.as_bytes()),
        (key_triple.provider_id as u8).to_string(),
        base64::engine::general_purpose::URL_SAFE.encode(key_triple.key_name.as_bytes()),
    )
}

/// Decodes base64 bytes to its original String value.
///
/// # Errors
///
/// Returns an error as a string if either the decoding or the bytes conversion to UTF-8 failed.
fn base64_data_to_string(base64_bytes: &[u8]) -> Result<String, String> {
    match base64::engine::general_purpose::URL_SAFE.decode(base64_bytes) {
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
#[allow(deprecated)]
fn base64_data_triple_to_key_triple(
    app_name: &[u8],
    provider_id: ProviderId,
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

/// Converts an OsStr reference to a ProviderId value.
///
/// # Errors
///
/// Returns a custom std::io error if the conversion failed.
fn os_str_to_provider_id(os_str: &OsStr) -> std::io::Result<ProviderId> {
    match os_str.to_str() {
        Some(str) => match str.parse::<u8>() {
            Ok(provider_id_u8) => match ProviderId::try_from(provider_id_u8) {
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

/// Splits a filename into provider_name + key name (for internal keys only)
///
/// # Errors
///
/// Returns None if no provider_name was detected
fn split_provider_key_filename(filename: &str) -> Option<(String, String)> {
    for name in PROVIDER_NAMES {
        if filename.starts_with(name) {
            return Some((name.to_string(), filename.replacen(name, "", 1)));
        }
    }
    None
}

fn provider_id_to_str(provid: ProviderId) -> &'static str {
    match provid {
        ProviderId::Core => CORE_PROVIDER,
        ProviderId::Pkcs11 => PKCS11_PROVIDER,
        ProviderId::MbedCrypto => MBEDCRYPTO_PROVIDER,
        ProviderId::Tpm => TPM_PROVIDER,
        ProviderId::TrustedService => TRUSTEDS_PROVIDER,
        ProviderId::CryptoAuthLib => CRYPTOAUTH_PROVIDER,
    }
}

fn str_to_provider_id(provid: &str) -> Option<ProviderId> {
    match provid {
        CORE_PROVIDER => Some(ProviderId::Core),
        PKCS11_PROVIDER => Some(ProviderId::Pkcs11),
        MBEDCRYPTO_PROVIDER => Some(ProviderId::MbedCrypto),
        TPM_PROVIDER => Some(ProviderId::Tpm),
        TRUSTEDS_PROVIDER => Some(ProviderId::TrustedService),
        CRYPTOAUTH_PROVIDER => Some(ProviderId::CryptoAuthLib),
        _ => None,
    }
}

fn prov_and_key_to_str(provider_id: ProviderId, key_name: &str) -> String {
    let mut p_name = provider_id_to_str(provider_id).to_string();
    p_name.push_str(key_name);
    p_name
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
#[allow(deprecated)]
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
    /// |---parsec/
    /// |   |---provider1-INTERNAL1
    /// |   |---provider2-INTERNAL2
    ///
    /// where the path of a key name from the mappings directory is the key triple (application,
    /// provider, key) and the data inside the key name file is the key info serialised in binary
    /// format.
    /// The INTERNAL files under the parsec directory stores the information of those keys that are
    /// internally generated. The file name of the INTERNAL files has as its first component the
    /// provider name of the provider that generated the internal key.
    /// Each mapping is contained in its own file to prevent the modification of one mapping
    /// impacting the other ones.
    ///
    /// # Errors
    ///
    /// Returns an std::io error if the function failed reading the mapping files.
    fn new(mappings_dir_path: PathBuf, auth_type: AuthType) -> Result<OnDiskKeyInfoManager> {
        let mut key_store = HashMap::new();
        let mut key_store_internal = HashMap::new();

        // Will ignore if the mappings directory already exists.
        fs::create_dir_all(&mappings_dir_path).with_context(|| {
            format!(
                "Failed to create Key Info Mappings directory at {:?}",
                mappings_dir_path
            )
        })?;

        // The INTERNAL files are the only files that on the second level in the directory structure
        // and store the information of internal keys
        let parsec_dir = mappings_dir_path.join(INTERNAL_KEYS_PARSEC_DIR);
        fs::create_dir_all(&parsec_dir)
            .with_context(|| format!("Failed to create Parsec directory at {:?}", parsec_dir))?;
        fs::set_permissions(&parsec_dir, Permissions::from_mode(DIR_PERMISSION))?;

        for internal_key_path in list_files(&parsec_dir)?.iter() {
            let key_name_internal = base64_data_to_string(os_str_to_u8_ref(
                internal_key_path
                    .file_name()
                    .expect("The key name directory path should contain a final component."),
            )?)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

            // If provider name is not recognized, ignore the key.
            let keytriple = match split_provider_key_filename(&key_name_internal) {
                None => continue,
                Some((prov, key_name)) => KeyTriple::new(
                    ApplicationName::from_name(INTERNAL_KEYS_PARSEC_DIR.to_string()),
                    // Provider name has been recognized, so if None is returned here something has
                    // gone terribly wrong.
                    str_to_provider_id(&prov).unwrap(),
                    key_name,
                ),
            };

            let mut key_info = Vec::new();
            let mut key_info_file = File::open(internal_key_path).with_context(|| {
                format!(
                    "Failed to open Key Info Mappings file at {:?}",
                    internal_key_path
                )
            })?;
            let _ = key_info_file.read_to_end(&mut key_info)?;
            let key_info = bincode::deserialize(&key_info[..]).map_err(|e| {
                format_error!("Error deserializing key info", e);
                Error::new(ErrorKind::Other, "error deserializing key info")
            })?;
            let _ = key_store_internal.insert(keytriple, key_info);
        }

        for app_name_dir_path in list_dirs(&mappings_dir_path)?.iter() {
            for provider_dir_path in list_dirs(app_name_dir_path)?.iter() {
                for key_name_file_path in list_files(provider_dir_path)?.iter() {
                    let mut key_info = Vec::new();
                    let mut key_info_file = File::open(key_name_file_path).with_context(|| {
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

        let permissions = Permissions::from_mode(DIR_PERMISSION);
        fs::set_permissions(&mappings_dir_path, permissions)?;

        Ok(OnDiskKeyInfoManager {
            key_store,
            key_store_internal,
            mappings_dir_path,
            auth_type,
        })
    }

    /// Saves the key triple to key info mapping in its own file.
    /// The filename will be `mappings/[APP_NAME]/[PROVIDER_NAME]/[KEY_NAME]` under the same path as the
    /// on-disk manager. It will contain the Key info data.
    fn save_mapping(
        &self,
        key_triple: &KeyTriple,
        key_info: &KeyInfo,
        auth: &Auth,
    ) -> std::io::Result<()> {
        if crate::utils::GlobalConfig::log_error_details() {
            warn!(
                "Saving Key Triple ({}) mapping to disk.",
                key_triple.clone()
            );
        }
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let key_name_file_path = match auth {
            Auth::Internal => {
                let prov_key_name =
                    prov_and_key_to_str(key_triple.provider_id, &key_triple.key_name);
                let prov_key_name =
                    base64::engine::general_purpose::URL_SAFE.encode(prov_key_name.as_bytes());
                // INTERNAL_KEYS_PARSEC_DIR has already been created with the necessary permissions
                self.mappings_dir_path
                    .join(INTERNAL_KEYS_PARSEC_DIR)
                    .join(prov_key_name)
            }
            Auth::Client(_) => {
                // Create the directories with base64 names.
                let app_dir_path = self.mappings_dir_path.join(app_name);
                let provider_dir_path = app_dir_path.join(prov);
                let key_name_file_path = provider_dir_path.join(key_name);
                // Will ignore if they already exist.
                fs::create_dir_all(&provider_dir_path).map_err(|e| {
                    format_error!(
                        format!(
                            "Failed to create provider directory as {:?}",
                            &provider_dir_path
                        ),
                        e
                    );
                    e
                })?;
                let dir_permissions = Permissions::from_mode(DIR_PERMISSION);
                fs::set_permissions(&app_dir_path, dir_permissions.clone())?;
                fs::set_permissions(&provider_dir_path, dir_permissions)?;

                if key_name_file_path.exists() {
                    fs::remove_file(&key_name_file_path)?;
                }
                key_name_file_path
            }
        };

        // Create the mapping file with the corresponding permissions and write the key information
        let mut mapping_file = File::create(&key_name_file_path).map_err(|e| {
            error!(
                "Failed to create Key Info Mapping file at {:?}",
                key_name_file_path
            );
            e
        })?;

        let file_permissions = Permissions::from_mode(FILE_PERMISSION);
        fs::set_permissions(&key_name_file_path, file_permissions)?;
        mapping_file.write_all(&bincode::serialize(key_info).map_err(|e| {
            format_error!("Error serializing key info", e);
            Error::new(ErrorKind::Other, "error serializing key info")
        })?)
    }

    /// Removes the mapping file.
    /// Will do nothing if the mapping file does not exist.
    fn delete_mapping(&self, key_triple: &KeyTriple, auth: &Auth) -> std::io::Result<()> {
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let key_name_file_path = match auth {
            Auth::Internal => {
                let prov_key_name = prov_and_key_to_str(key_triple.provider_id, &key_name);

                // INTERNAL_KEYS_PARSEC_DIR has already been created with the necessary permissions
                self.mappings_dir_path
                    .join(INTERNAL_KEYS_PARSEC_DIR)
                    .join(prov_key_name)
            }
            Auth::Client(_) => self
                .mappings_dir_path
                .join(app_name)
                .join(prov)
                .join(key_name),
        };
        if key_name_file_path.exists() {
            fs::remove_file(key_name_file_path)
        } else {
            Ok(())
        }
    }
}

#[allow(deprecated)]
impl ManageKeyInfo for OnDiskKeyInfoManager {
    fn key_info_manager_type(&self) -> KeyInfoManagerType {
        KeyInfoManagerType::OnDisk
    }

    fn get(&self, key_identity: &KeyIdentity) -> Result<Option<&KeyInfo>, String> {
        let key_triple = KeyTriple::try_from(key_identity.clone())?;
        // An Option<&Vec<u8>> can not automatically coerce to an Option<&[u8]>, it needs to be
        // done by hand.
        let curr_key_store = match key_identity.application().auth() {
            &Auth::Internal => &self.key_store_internal,
            _ => &self.key_store,
        };

        if let Some(key_info) = curr_key_store.get(&key_triple) {
            Ok(Some(key_info))
        } else {
            Ok(None)
        }
    }

    fn get_all(&self, provider_identity: ProviderIdentity) -> Result<Vec<KeyIdentity>, String> {
        let provider_id = ProviderId::try_from(provider_identity.clone())?;
        let mut key_identites = Vec::new();

        let key_triples_internal = self
            .key_store_internal
            .keys()
            .filter(|key_triple| key_triple.belongs_to_provider(provider_id));

        for key_triple_internal in key_triples_internal {
            let key_identity = KeyIdentity::try_from((
                key_triple_internal.clone(),
                provider_identity.clone(),
                Auth::Internal,
            ))?;
            key_identites.push(key_identity)
        }
        let key_triples_external = self
            .key_store
            .keys()
            .filter(|key_triple| key_triple.belongs_to_provider(provider_id));

        for key_triple_external in key_triples_external {
            let key_identity = KeyIdentity::try_from((
                key_triple_external.clone(),
                provider_identity.clone(),
                Auth::Client(self.auth_type),
            ))?;
            key_identites.push(key_identity)
        }
        Ok(key_identites)
    }

    fn insert(
        &mut self,
        key_identity: KeyIdentity,
        key_info: KeyInfo,
    ) -> Result<Option<KeyInfo>, String> {
        let key_triple = KeyTriple::try_from(key_identity.clone())?;
        if let Err(err) =
            self.save_mapping(&key_triple, &key_info, key_identity.application().auth())
        {
            Err(err.to_string())
        } else if key_identity.application().is_internal() {
            Ok(self.key_store_internal.insert(key_triple, key_info))
        } else {
            Ok(self.key_store.insert(key_triple, key_info))
        }
    }

    fn remove(&mut self, key_identity: &KeyIdentity) -> Result<Option<KeyInfo>, String> {
        let key_triple = KeyTriple::try_from(key_identity.clone())?;
        if let Err(err) = self.delete_mapping(&key_triple, key_identity.application().auth()) {
            return Err(err.to_string());
        }
        if key_identity.application().is_internal() {
            Ok(self.key_store_internal.remove(&key_triple))
        } else if !key_identity.application().is_internal() {
            Ok(self.key_store.remove(&key_triple))
        } else {
            Ok(None)
        }
    }

    fn exists(&self, key_identity: &KeyIdentity) -> Result<bool, String> {
        let key_triple = KeyTriple::try_from(key_identity.clone())?;
        match *key_identity.application().auth() {
            Auth::Internal => Ok(self.key_store_internal.contains_key(&key_triple)),
            Auth::Client(_) => Ok(self.key_store.contains_key(&key_triple)),
        }
    }
}

/// OnDiskKeyInfoManager builder
#[derive(Debug, Default)]
pub struct OnDiskKeyInfoManagerBuilder {
    mappings_dir_path: Option<PathBuf>,
    auth_type: Option<AuthType>,
}

impl OnDiskKeyInfoManagerBuilder {
    /// Create a new OnDiskKeyInfoManagerBuilder
    pub fn new() -> OnDiskKeyInfoManagerBuilder {
        OnDiskKeyInfoManagerBuilder {
            mappings_dir_path: None,
            auth_type: None,
        }
    }

    /// Add a mappings directory path to the builder
    pub fn with_mappings_dir_path(mut self, path: PathBuf) -> OnDiskKeyInfoManagerBuilder {
        self.mappings_dir_path = Some(path);

        self
    }

    /// Add an authentication type to the builder
    pub fn with_auth_type(mut self, default_auth_type: AuthType) -> OnDiskKeyInfoManagerBuilder {
        self.auth_type = Some(default_auth_type);

        self
    }

    /// Build into a OnDiskKeyInfoManager
    pub fn build(self) -> Result<OnDiskKeyInfoManager> {
        OnDiskKeyInfoManager::new(
            self.mappings_dir_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MAPPINGS_PATH)),
            self.auth_type.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "AuthType must be supplied to OnDiskKeyInfoManager",
                )
            })?,
        )
    }
}

#[cfg(test)]
mod test {
    use super::super::{KeyIdentity, KeyInfo, ManageKeyInfo};
    use super::OnDiskKeyInfoManager;
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

    #[test]
    fn insert_get_key_info() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_get_key_info_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_remove_key() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_remove_key_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

        let key_identity = new_key_identity("insert_remove_key".to_string());
        let key_info = test_key_info();

        let _ = manager.insert(key_identity.clone(), key_info).unwrap();

        assert!(manager.remove(&key_identity).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn remove_unexisting_key() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/remove_unexisting_key_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

        let key_identity = new_key_identity("remove_unexisting_key".to_string());
        assert_eq!(manager.remove(&key_identity).unwrap(), None);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exists() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/exists_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

        let key_identity = new_key_identity("exists".to_string());
        let key_info = test_key_info();

        assert!(!manager.exists(&key_identity).unwrap());

        let _ = manager.insert(key_identity.clone(), key_info).unwrap();
        assert!(manager.exists(&key_identity).unwrap());

        let _ = manager.remove(&key_identity).unwrap();
        assert!(!manager.exists(&key_identity).unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_overwrites() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/insert_overwrites_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_ascii() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/big_names_ascii_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_emoticons() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/big_names_emoticons_mappings");
        let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(feature = "mbed-crypto-provider")]
    #[test]
    fn create_and_load() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/create_and_load_mappings");

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
            let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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
            let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

            assert_eq!(manager.remove(&key_identity_1).unwrap().unwrap(), key_info1);
            assert_eq!(manager.remove(&key_identity_2).unwrap().unwrap(), key_info2);
            assert_eq!(manager.remove(&key_identity_3).unwrap().unwrap(), key_info3);
        }

        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(feature = "mbed-crypto-provider")]
    #[test]
    fn create_and_load_internal_keys() {
        let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/create_and_load_internal_mappings");

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
            let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();
            let _ = manager
                .insert(key_identity_1.clone(), key_info1.clone())
                .unwrap();
            let _ = manager
                .insert(key_identity_2.clone(), key_info2.clone())
                .unwrap();
        }
        // The local hashmap is dropped when leaving the inner scope.
        {
            let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();

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

        fs::remove_dir_all(path).unwrap();
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

    #[cfg(feature = "mbed-crypto-provider")]
    mod permissions_test {
        use super::*;
        use crate::key_info_managers::on_disk_manager::DIR_PERMISSION;
        use crate::key_info_managers::on_disk_manager::FILE_PERMISSION;
        use std::fs::Permissions;
        use std::io;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        // loop through every directory and file and check permissions
        fn check_permissions(dir: &Path) -> io::Result<()> {
            let file_permissions = Permissions::from_mode(FILE_PERMISSION);
            let dir_permissions = Permissions::from_mode(DIR_PERMISSION);
            if dir.is_dir() {
                for entry in fs::read_dir(dir)? {
                    let path = entry?.path();
                    if path.is_dir() {
                        assert_eq!(
                            fs::metadata(&path)?.permissions().mode() & dir_permissions.mode(),
                            dir_permissions.mode()
                        );
                        check_permissions(&path)?;
                    } else {
                        assert_eq!(
                            fs::metadata(&path)?.permissions().mode() & file_permissions.mode(),
                            file_permissions.mode()
                        );
                    }
                }
            }
            Ok(())
        }

        #[test]
        fn check_kim_permissions() {
            let dir_permissions = Permissions::from_mode(DIR_PERMISSION);
            let path = PathBuf::from(env!("OUT_DIR").to_owned() + "/check_permissions");
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

            let app_name2 = "App2".to_string();
            let key_name2 = "Key2".to_string();
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

            let mut manager = OnDiskKeyInfoManager::new(path.clone(), AuthType::NoAuth).unwrap();
            assert_eq!(
                fs::metadata(path.clone()).unwrap().permissions().mode() & dir_permissions.mode(),
                dir_permissions.mode()
            );
            let _ = manager.insert(key_identity_1.clone(), key_info1).unwrap();
            let _ = manager.insert(key_identity_2.clone(), key_info2).unwrap();

            let _ = check_permissions(&path).is_ok();
            let _ = manager.remove(&key_identity_1).unwrap().unwrap();
            let _ = manager.remove(&key_identity_2).unwrap().unwrap();

            fs::remove_dir_all(path).unwrap();
        }
    }
}
