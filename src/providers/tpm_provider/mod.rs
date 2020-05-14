// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 provider
//!
//! Provider allowing clients to use hardware or software TPM 2.0 implementations
//! for their Parsec operations.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::ManageKeyInfo;
use derivative::Derivative;
use log::{error, info};
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{
    list_opcodes, psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
    psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, RwLock};
use tss_esapi::utils::algorithm_specifiers::Cipher;
use tss_esapi::Tcti;
use uuid::Uuid;

mod asym_sign;
mod key_management;
mod utils;

const SUPPORTED_OPCODES: [Opcode; 7] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::ListOpcodes,
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
pub struct TpmProvider {
    // The Mutex is needed both because interior mutability is needed to the ESAPI Context
    // structure that is shared between threads and because two threads are not allowed the same
    // ESAPI context simultaneously.
    esapi_context: Mutex<tss_esapi::TransientKeyContext>,
    // The Key Info Manager stores the key context and its associated authValue (a PasswordContext
    // structure).
    #[derivative(Debug = "ignore")]
    key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
}

impl TpmProvider {
    // Creates and initialise a new instance of TpmProvider.
    fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
        esapi_context: tss_esapi::TransientKeyContext,
    ) -> Option<TpmProvider> {
        Some(TpmProvider {
            esapi_context: Mutex::new(esapi_context),
            key_info_store,
        })
    }
}

impl Provide for TpmProvider {
    fn list_opcodes(&self, _op: list_opcodes::Operation) -> Result<list_opcodes::Result> {
        Ok(list_opcodes::Result {
            opcodes: SUPPORTED_OPCODES.iter().copied().collect(),
        })
    }

    fn describe(&self) -> Result<ProviderInfo> {
        Ok(ProviderInfo {
            // Assigned UUID for this provider: 1e4954a4-ff21-46d3-ab0c-661eeb667e1d
            uuid: Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("TPM provider, interfacing with a library implementing the TCG TSS 2.0 Enhanced System API specification."),
            vendor: String::from("Trusted Computing Group (TCG)"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::Tpm,
        })
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        self.psa_generate_key_internal(app_name, op)
    }

    fn psa_import_key(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        self.psa_import_key_internal(app_name, op)
    }

    fn psa_export_public_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        self.psa_export_public_key_internal(app_name, op)
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        self.psa_destroy_key_internal(app_name, op)
    }

    fn psa_sign_hash(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        self.psa_sign_hash_internal(app_name, op)
    }

    fn psa_verify_hash(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        self.psa_verify_hash_internal(app_name, op)
    }
}

impl Drop for TpmProvider {
    fn drop(&mut self) {
        info!("Dropping the TPM Provider.");
    }
}

/// Builder for TpmProvider
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct TpmProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
    tcti: Option<Tcti>,
    owner_hierarchy_auth: Option<String>,
}

impl TpmProviderBuilder {
    pub fn new() -> TpmProviderBuilder {
        TpmProviderBuilder {
            key_info_store: None,
            tcti: None,
            owner_hierarchy_auth: None,
        }
    }

    pub fn with_key_info_store(
        mut self,
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> TpmProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    pub fn with_tcti(mut self, tcti: &str) -> TpmProviderBuilder {
        // Convert from a String to the enum.
        self.tcti = match tcti {
            "device" => Some(Tcti::Device),
            "mssim" => Some(Tcti::Mssim),
            _ => {
                error!("The string {} does not match a TCTI device.", tcti);
                None
            }
        };

        self
    }

    pub fn with_owner_hierarchy_auth(mut self, owner_hierarchy_auth: String) -> TpmProviderBuilder {
        self.owner_hierarchy_auth = Some(owner_hierarchy_auth);

        self
    }

    fn get_hierarchy_auth(&mut self) -> std::io::Result<Vec<u8>> {
        match self.owner_hierarchy_auth.take() {
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
            .or_else(|_| {
                Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid hex owner hierarchy auth",
                ))
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
    unsafe fn find_default_context_cipher(&self) -> std::io::Result<Cipher> {
        let ciphers = [Cipher::aes_256_cfb(), Cipher::aes_128_cfb()];
        let mut ctx = tss_esapi::Context::new(
            self.tcti
                .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing TCTI"))?,
        )
        .or_else(|e| {
            error!("Error when creating TSS Context ({})", e);
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "failed initializing TSS context",
            ))
        })?;
        for cipher in ciphers.iter() {
            if ctx
                .test_parms(tss_esapi::utils::PublicParmsUnion::SymDetail(*cipher))
                .is_ok()
            {
                return Ok(*cipher);
            }
        }
        Err(std::io::Error::new(
            ErrorKind::Other,
            "desired ciphers not supported by TPM",
        ))
    }

    /// Create an instance of TpmProvider
    ///
    /// # Safety
    ///
    /// Undefined behaviour might appear if two instances of TransientObjectContext are created
    /// using a same TCTI that does not handle multiple applications concurrently.
    pub unsafe fn build(mut self) -> std::io::Result<TpmProvider> {
        let hierarchy_auth = self.get_hierarchy_auth()?;
        let default_cipher = self.find_default_context_cipher()?;
        let tcti = self
            .tcti
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing TCTI"))?;
        TpmProvider::new(
            self.key_info_store.ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "missing key info store")
            })?,
            tss_esapi::abstraction::transient::TransientKeyContextBuilder::new()
                .with_tcti(tcti)
                .with_root_key_size(ROOT_KEY_SIZE)
                .with_root_key_auth_size(ROOT_KEY_AUTH_SIZE)
                .with_hierarchy_auth(hierarchy_auth)
                .with_hierarchy(tss_esapi::utils::Hierarchy::Owner)
                .with_session_hash_alg(
                    tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256.into(),
                )
                .with_default_context_cipher(default_cipher)
                .build()
                .or_else(|e| {
                    error!("Error creating TSS Transient Object Context ({}).", e);
                    Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "failed initializing TSS context",
                    ))
                })?,
        )
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "failed initializing TPM provider")
        })
    }
}
