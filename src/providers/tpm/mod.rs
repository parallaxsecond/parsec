// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 provider
//!
//! Provider allowing clients to use hardware or software TPM 2.0 implementations
//! for their Parsec operations.
use super::Provide;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::{KeyIdentity, KeyInfoManagerClient};
use crate::providers::crypto_capability::CanDoCrypto;
use crate::providers::ProviderIdentity;
use derivative::Derivative;
use log::{info, trace};
use parsec_interface::operations::list_providers::Uuid;
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags,
};
use parsec_interface::operations::{
    attest_key, can_do_crypto, prepare_key_attestation, psa_asymmetric_decrypt,
    psa_asymmetric_encrypt, psa_destroy_key, psa_export_public_key, psa_generate_key,
    psa_generate_random, psa_import_key, psa_sign_hash, psa_verify_hash,
};
use parsec_interface::operations::{list_clients, list_keys, list_providers::ProviderInfo};
use parsec_interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Mutex;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{SymmetricCipherParameters, SymmetricDefinitionObject};
use tss_esapi::Tcti;
use zeroize::Zeroize;

mod asym_encryption;
mod asym_sign;
mod capability_discovery;
mod generate_random;
mod key_attestation;
mod key_management;
mod utils;

const SUPPORTED_OPCODES: [Opcode; 12] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaGenerateRandom,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaAsymmetricDecrypt,
    Opcode::PsaAsymmetricEncrypt,
    Opcode::CanDoCrypto,
    Opcode::AttestKey,
    Opcode::PrepareKeyAttestation,
];

const ROOT_KEY_SIZE: u16 = 2048;
const ROOT_KEY_AUTH_SIZE: usize = 32;
const AUTH_STRING_PREFIX: &str = "str:";
const AUTH_HEX_PREFIX: &str = "hex:";

/// Provider for Trusted Platform Modules
///
/// Operations for this provider are serviced using the TPM 2.0 software stack,
/// on top of the Enhanced System API. This implementation can be used with any
/// implementation compliant with the specification, be it hardware or software
/// (e.g. firmware TPMs).
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    // The identity of the provider including uuid & name.
    provider_identity: ProviderIdentity,

    // The Mutex is needed both because interior mutability is needed to the ESAPI Context
    // structure that is shared between threads and because two threads are not allowed the same
    // ESAPI context simultaneously.
    esapi_context: Mutex<tss_esapi::TransientKeyContext>,
    // The Key Info Manager stores the key context and its associated authValue (a PasswordContext
    // structure).
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
}

impl Provider {
    /// The default provider name for tpm provider
    pub const DEFAULT_PROVIDER_NAME: &'static str = "tpm-provider";

    /// The UUID for this provider
    pub const PROVIDER_UUID: &'static str = "1e4954a4-ff21-46d3-ab0c-661eeb667e1d";

    // Creates and initialise a new instance of TpmProvider.
    fn new(
        provider_name: String,
        key_info_store: KeyInfoManagerClient,
        esapi_context: tss_esapi::TransientKeyContext,
    ) -> Provider {
        Provider {
            provider_identity: ProviderIdentity {
                name: provider_name,
                uuid: String::from(Self::PROVIDER_UUID),
            },
            esapi_context: Mutex::new(esapi_context),
            key_info_store,
        }
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: 1e4954a4-ff21-46d3-ab0c-661eeb667e1d
            uuid: Uuid::parse_str(Provider::PROVIDER_UUID).or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("TPM provider, interfacing with a library implementing the TCG TSS 2.0 Enhanced System API specification."),
            vendor: String::from("Trusted Computing Group (TCG)"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderId::Tpm,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }

    fn list_keys(
        &self,
        application_identity: &ApplicationIdentity,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");
        Ok(list_keys::Result {
            keys: self.key_info_store.list_keys(application_identity)?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");
        Ok(list_clients::Result {
            clients: self
                .key_info_store
                .list_clients()?
                .into_iter()
                .map(|application_identity| application_identity.name().clone())
                .collect(),
        })
    }

    fn psa_generate_random(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        self.psa_generate_random_internal(op)
    }

    fn psa_generate_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(application_identity, op)
    }

    fn psa_import_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        self.psa_import_key_internal(application_identity, op)
    }

    fn psa_export_public_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        self.psa_export_public_key_internal(application_identity, op)
    }

    fn psa_destroy_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(application_identity, op)
    }

    fn psa_sign_hash(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        self.psa_sign_hash_internal(application_identity, op)
    }

    fn psa_verify_hash(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        trace!("psa_verify_hash ingress");
        self.psa_verify_hash_internal(application_identity, op)
    }

    fn psa_asymmetric_encrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        trace!("psa_asymmetric_encrypt ingress");
        self.psa_asymmetric_encrypt_internal(application_identity, op)
    }

    fn psa_asymmetric_decrypt(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(application_identity, op)
    }

    /// Check if the crypto operation is supported by TPM provider
    /// by using CanDoCrypto trait.
    fn can_do_crypto(
        &self,
        application_identity: &ApplicationIdentity,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto TPM ingress");
        self.can_do_crypto_main(application_identity, op)
    }

    fn prepare_key_attestation(
        &self,
        application_identity: &ApplicationIdentity,
        op: prepare_key_attestation::Operation,
    ) -> Result<prepare_key_attestation::Result> {
        trace!("prepare_key_attestation ingress");
        self.prepare_key_attestation_internal(application_identity, op)
    }

    fn attest_key(
        &self,
        application_identity: &ApplicationIdentity,
        op: attest_key::Operation,
    ) -> Result<attest_key::Result> {
        trace!("attest_key ingress");
        self.attest_key_internal(application_identity, op)
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        info!("Dropping the TPM Provider.");
    }
}

/// Builder for TpmProvider
///
/// This builder contains some confidential information that is passed to the TpmProvider. The
/// TpmProvider will zeroize this data when dropping. This data will not be cloned when
/// building.
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    provider_name: Option<String>,
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
    tcti: Option<String>,
    owner_hierarchy_auth: Option<String>,
    endorsement_hierarchy_auth: Option<String>,
}

impl ProviderBuilder {
    /// Create a new TPM provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            provider_name: None,
            key_info_store: None,
            tcti: None,
            owner_hierarchy_auth: None,
            endorsement_hierarchy_auth: None,
        }
    }

    /// Add a provider name
    pub fn with_provider_name(mut self, provider_name: String) -> ProviderBuilder {
        self.provider_name = Some(provider_name);

        self
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(mut self, key_info_store: KeyInfoManagerClient) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the TCTI used for this provider
    pub fn with_tcti(mut self, tcti: &str) -> ProviderBuilder {
        self.tcti = Some(tcti.to_owned());

        self
    }

    /// Specify the owner hierarchy authentication to use
    pub fn with_owner_hierarchy_auth(mut self, owner_hierarchy_auth: String) -> ProviderBuilder {
        self.owner_hierarchy_auth = Some(owner_hierarchy_auth);

        self
    }

    /// Specify the endorsement hierarchy authentication to use
    pub fn with_endorsement_hierarchy_auth(
        mut self,
        endorsement_hierarchy_auth: String,
    ) -> ProviderBuilder {
        self.endorsement_hierarchy_auth = Some(endorsement_hierarchy_auth);

        self
    }

    fn get_hierarchy_auth(&mut self, mut auth: Option<String>) -> std::io::Result<Vec<u8>> {
        match auth.take() {
            None => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "missing owner hierarchy auth",
            )),
            Some(mut auth) if auth.starts_with(AUTH_STRING_PREFIX) => {
                Ok(auth.split_off(AUTH_STRING_PREFIX.len()).into())
            }
            Some(mut auth) if auth.starts_with(AUTH_HEX_PREFIX) => Ok(hex::decode(
                auth.split_off(AUTH_STRING_PREFIX.len()),
            )
            .map_err(|_| {
                std::io::Error::new(ErrorKind::InvalidData, "invalid hex owner hierarchy auth")
            })?),
            Some(auth) => Ok(auth.into()),
        }
    }

    /// Identify the best cipher for our needs supported by the TPM.
    ///
    /// The algorithms sought are the following, in the given order:
    /// * AES-256 in CFB mode
    /// * AES-128 in CFB mode
    ///
    /// The method is unsafe because it relies on creating a TSS Context which could cause
    /// undefined behaviour if multiple such contexts are opened concurrently.
    unsafe fn find_default_context_cipher(&self) -> std::io::Result<SymmetricDefinitionObject> {
        info!("Checking for ciphers supported by the TPM.");
        let ciphers = [
            SymmetricDefinitionObject::AES_256_CFB,
            SymmetricDefinitionObject::AES_128_CFB,
        ];
        let mut ctx = tss_esapi::Context::new(
            Tcti::from_str(self.tcti.as_ref().ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "TCTI configuration missing")
            })?)
            .map_err(|_| {
                std::io::Error::new(ErrorKind::InvalidData, "Invalid TCTI configuration string")
            })?,
        )
        .map_err(|e| {
            format_error!("Error when creating TSS Context", e);
            std::io::Error::new(ErrorKind::InvalidData, "failed initializing TSS context")
        })?;
        for cipher in ciphers.iter() {
            if ctx
                .test_parms(tss_esapi::structures::PublicParameters::SymCipher(
                    SymmetricCipherParameters::new(*cipher),
                ))
                .is_ok()
            {
                return Ok(*cipher);
            }
        }
        Err(std::io::Error::new(
            ErrorKind::Other,
            "desired ciphers not supported",
        ))
    }

    /// Create an instance of TpmProvider
    ///
    /// # Safety
    ///
    /// Undefined behaviour might appear if two instances of TransientObjectContext are created
    /// using a same TCTI that does not handle multiple applications concurrently.
    pub unsafe fn build(mut self) -> std::io::Result<Provider> {
        let owner_auth_unparsed = self.owner_hierarchy_auth.take();
        let owner_auth = self.get_hierarchy_auth(owner_auth_unparsed)?;
        let default_cipher = self.find_default_context_cipher()?;
        let tcti = Tcti::from_str(self.tcti.as_ref().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "TCTI configuration missing")
        })?)
        .map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidData, "Invalid TCTI configuration string")
        })?;
        self.tcti.zeroize();
        self.owner_hierarchy_auth.zeroize();
        let mut builder = tss_esapi::abstraction::transient::TransientKeyContextBuilder::new()
            .with_tcti(tcti)
            .with_root_key_size(ROOT_KEY_SIZE)
            .with_root_key_auth_size(ROOT_KEY_AUTH_SIZE)
            .with_hierarchy_auth(Hierarchy::Owner, owner_auth)
            .with_root_hierarchy(Hierarchy::Owner)
            .with_session_hash_alg(HashingAlgorithm::Sha256)
            .with_default_context_cipher(default_cipher);
        if self.endorsement_hierarchy_auth.is_some() {
            let endorsement_auth_unparsed = self.endorsement_hierarchy_auth.take();
            let endorsement_auth = self.get_hierarchy_auth(endorsement_auth_unparsed)?;
            builder = builder.with_hierarchy_auth(Hierarchy::Endorsement, endorsement_auth);
            self.endorsement_hierarchy_auth.zeroize();
        }

        let built_provider = Provider::new(
            self.provider_name.ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "missing provider name")
            })?,
            self.key_info_store.ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "missing key info store")
            })?,
            builder.build().map_err(|e| {
                format_error!("Error creating TSS Transient Object Context", e);
                std::io::Error::new(ErrorKind::InvalidData, "failed initializing TSS context")
            })?,
        );

        // Get the root key from the key store
        let root_key_identity = KeyIdentity::new(
            ApplicationIdentity::new_internal(),
            built_provider.provider_identity.clone(),
            String::from("RootKeyTPM"),
        );
        let key_is_stored = match built_provider
            .key_info_store
            .does_not_exist(&root_key_identity)
        {
            Ok(()) => false,
            Err(ResponseStatus::PsaErrorAlreadyExists) => true,
            Err(e) => Err(e).map_err(|e| {
                format_error!("Failure accessing Key Info Manager", e);
                std::io::Error::new(ErrorKind::InvalidData, "Key existence check failed")
            })?,
        };

        if key_is_stored {
            let stored_root_key_name: Vec<u8> = built_provider
                .key_info_store
                .get_key_id(&root_key_identity)
                .map_err(|e| {
                    format_error!("Error getting Key Identities from the Key Info Store", e);
                    std::io::Error::new(ErrorKind::InvalidData, "failed getting Key Identities")
                })?;
            // Check if the stored public part coincides with the one in the context
            let mut esapi_context = built_provider
                .esapi_context
                .lock()
                .expect("ESAPI Context lock poisoned");

            let root_key_name = esapi_context.get_root_key_name().map_err(|e| {
                format_error!("Error getting the Root Key's name", e);
                std::io::Error::new(ErrorKind::InvalidData, "failed getting Root Key's Name")
            })?;

            if root_key_name.value().to_vec() != stored_root_key_name {
                let e = std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Obtained Root Key name does not coincide with the stored one",
                );
                format_error!("Error when verifying the Root Key's Name", e);
                return Err(e);
            }
        } else {
            let mut esapi_context = built_provider
                .esapi_context
                .lock()
                .expect("ESAPI Context lock poisoned");

            let root_key_name = esapi_context.get_root_key_name().map_err(|e| {
                format_error!("Error getting the the Root Key's Name", e);
                std::io::Error::new(ErrorKind::InvalidData, "failed getting Root Key's Name")
            })?;

            let attributes = Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaPublicKey,
                bits: ROOT_KEY_SIZE as usize,
                policy: Policy {
                    // Internal key, usage_flags information is not relevant
                    usage_flags: UsageFlags::default(),
                    // Internal key, permitted_algorithms information is not relevant
                    permitted_algorithms: Algorithm::None,
                },
            };

            built_provider
                .key_info_store
                .insert_key_info(
                    root_key_identity,
                    &(root_key_name.value().to_vec()),
                    attributes,
                )
                .map_err(|_| {
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Failed to insert Key Info in the Key Store",
                    )
                })?;
        }

        Ok(built_provider)
    }
}

#[cfg(test)]
mod test {
    use crate::key_info_managers::{KeyIdentity, KeyInfoManagerFactory};
    use crate::providers::tpm::ROOT_KEY_SIZE;
    use crate::providers::tpm::{Provider, ProviderBuilder};
    use crate::providers::ApplicationIdentity;
    use crate::providers::ProviderIdentity;
    use crate::utils::config::{KeyInfoManagerConfig, KeyInfoManagerType};
    use parsec_interface::operations::psa_algorithm::Algorithm;
    use parsec_interface::operations::psa_key_attributes::{
        Attributes, Lifetime, Policy, Type, UsageFlags,
    };
    use parsec_interface::requests::AuthType;

    // This test can only be run with a TPM already available in your system.
    // Ignored unless specified
    #[ignore]
    #[test]
    fn test_root_key_check() {
        // Test configuration should be changed to adapt to your system's TPM
        let tcti = "mssim:host=127.0.0.1,port=2321";
        let owner_hierarchy_auth = "hex:74706d5f70617373";
        let endorsement_hierarchy_auth = "str:endorsement_pass".to_string();

        let provider_identity =
            ProviderIdentity::new(Provider::PROVIDER_UUID.to_string(), "Tpm".to_string());
        let kim_config = KeyInfoManagerConfig {
            name: "sqlite-manager".to_string(),
            manager_type: KeyInfoManagerType::SQLite,
            store_path: None,
            sqlite_db_path: Some(
                "./kim-mappings/sqlite/sqlite-key-info-manager.sqlite3".to_string(),
            ),
        };

        let kim_factory = KeyInfoManagerFactory::new(&kim_config, AuthType::NoAuth).unwrap();
        // Builds the tpm provider and inserts an internal key
        {
            let builder = ProviderBuilder::new()
                .with_key_info_store(kim_factory.build_client(provider_identity.clone()))
                .with_tcti(tcti)
                .with_provider_name("Tpm".to_string())
                .with_owner_hierarchy_auth(owner_hierarchy_auth.to_string())
                .with_endorsement_hierarchy_auth(endorsement_hierarchy_auth.clone());

            unsafe {
                let _ = builder.build().unwrap();
            }
        }

        // Builds the tpm provider, checking that the internally stored key matches
        // the newly generated one.
        // Then, it modifies the key information inside so that the next check fails.
        {
            let builder = ProviderBuilder::new()
                .with_key_info_store(kim_factory.build_client(provider_identity.clone()))
                .with_tcti(tcti)
                .with_provider_name("Tpm".to_string())
                .with_owner_hierarchy_auth(owner_hierarchy_auth.to_string())
                .with_endorsement_hierarchy_auth(endorsement_hierarchy_auth.clone());
            // Reads the key and verifies the created one vs the stored one

            let built_provider = unsafe { builder.build().unwrap() };

            // replace the key info from the internal key with some incorrect information
            let root_key_identity = KeyIdentity::new(
                ApplicationIdentity::new_internal(),
                built_provider.provider_identity.clone(),
                String::from("RootKeyTPM"),
            );
            let attributes = Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaPublicKey,
                bits: ROOT_KEY_SIZE as usize,
                policy: Policy {
                    // Internal key, usage_flags information is not relevant
                    usage_flags: UsageFlags::default(),
                    // Internal key, permitted_algorithms information is not relevant
                    permitted_algorithms: Algorithm::None,
                },
            };

            let test_material: Vec<u8> = vec![1, 2];

            built_provider
                .key_info_store
                .replace_key_info(root_key_identity, &test_material, attributes)
                .unwrap();
        }

        // Should fail as the newly replaced key information does not match
        // the previously created one.
        {
            let builder = ProviderBuilder::new()
                .with_key_info_store(kim_factory.build_client(provider_identity))
                .with_tcti(tcti)
                .with_provider_name("Tpm".to_string())
                .with_owner_hierarchy_auth(owner_hierarchy_auth.to_string())
                .with_endorsement_hierarchy_auth(endorsement_hierarchy_auth);
            assert!(unsafe { builder.build().is_err() });
        }
    }
}
