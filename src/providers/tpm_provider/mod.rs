// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 provider
//!
//! Provider allowing clients to use hardware or software TPM 2.0 implementations
//! for their Parsec operations.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use derivative::Derivative;
use log::{error, info};
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::{
    list_opcodes, psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
    psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, RwLock};
use tss_esapi::{
    constants::TPM2_ALG_SHA256, utils::AsymSchemeUnion, utils::Signature, utils::TpmsContext, Tcti,
};
use uuid::Uuid;

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

const ROOT_KEY_SIZE: usize = 2048;
const ROOT_KEY_AUTH_SIZE: usize = 32;

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
    esapi_context: Mutex<tss_esapi::TransientObjectContext>,
    // The Key Info Manager stores the key context and its associated authValue (a PasswordContext
    // structure).
    #[derivative(Debug = "ignore")]
    key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
}

// Public exponent value for all RSA keys.
const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];
const AUTH_VAL_LEN: usize = 32;

// The RSA Public Key data are DER encoded with the following representation:
// RSAPublicKey ::= SEQUENCE {
//     modulus            INTEGER,  -- n
//     publicExponent     INTEGER   -- e
// }
#[derive(Serialize, Deserialize, Debug)]
struct RsaPublicKey {
    modulus: IntegerAsn1,
    public_exponent: IntegerAsn1,
}

// The PasswordContext is what is stored by the Key Info Manager.
#[derive(Serialize, Deserialize)]
struct PasswordContext {
    context: TpmsContext,
    auth_value: Vec<u8>,
}

// Inserts a new mapping in the Key Info manager that stores the PasswordContext.
fn insert_password_context(
    store_handle: &mut dyn ManageKeyInfo,
    key_triple: KeyTriple,
    password_context: PasswordContext,
    key_attributes: KeyAttributes,
) -> Result<()> {
    let error_storing = |e| Err(key_info_managers::to_response_status(e));

    let key_info = KeyInfo {
        id: bincode::serialize(&password_context)?,
        attributes: key_attributes,
    };

    if store_handle
        .insert(key_triple, key_info)
        .or_else(error_storing)?
        .is_some()
    {
        error!("Inserting a mapping in the Key Info Manager that would overwrite an existing one.");
        Err(ResponseStatus::PsaErrorAlreadyExists)
    } else {
        Ok(())
    }
}

// Gets a PasswordContext mapping to the KeyTriple given.
fn get_password_context(
    store_handle: &dyn ManageKeyInfo,
    key_triple: KeyTriple,
) -> Result<(PasswordContext, KeyAttributes)> {
    let key_info = store_handle
        .get(&key_triple)
        .or_else(|e| Err(key_info_managers::to_response_status(e)))?
        .ok_or_else(|| {
            error!(
                "Key triple \"{}\" does not exist in the Key Info Manager.",
                key_triple
            );
            ResponseStatus::PsaErrorDoesNotExist
        })?;
    Ok((bincode::deserialize(&key_info.id)?, key_info.attributes))
}

impl TpmProvider {
    // Creates and initialise a new instance of TpmProvider.
    fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
        esapi_context: tss_esapi::TransientObjectContext,
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
        if op.attributes.key_type != KeyType::RsaKeyPair {
            error!("The TPM provider currently only supports creating RSA key pairs.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        // This should never panic on 32 bits or more machines.
        let key_size = std::convert::TryFrom::try_from(op.attributes.key_bits)
            .expect("Conversion to usize failed.");

        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (key_context, auth_value) = esapi_context
            .create_rsa_signing_key(key_size, AUTH_VAL_LEN)
            .or_else(|e| {
                error!("Error creating a RSA signing key: {}.", e);
                Err(utils::to_response_status(e))
            })?;

        insert_password_context(
            &mut *store_handle,
            key_triple,
            PasswordContext {
                context: key_context,
                auth_value,
            },
            attributes,
        )?;

        Ok(psa_generate_key::Result {})
    }

    fn psa_import_key(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        if op.attributes.key_type != KeyType::RsaPublicKey {
            error!("The TPM provider currently only supports importing RSA public key.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        let key_data = op.data;

        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let public_key: RsaPublicKey = picky_asn1_der::from_bytes(&key_data).or_else(|err| {
            error!("Could not deserialise key elements: {}.", err);
            Err(ResponseStatus::PsaErrorInvalidArgument)
        })?;

        if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
            error!("Only positive modulus and public exponent are supported.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        if public_key.public_exponent.as_unsigned_bytes_be() != PUBLIC_EXPONENT {
            error!("The TPM Provider only supports 0x101 as public exponent for RSA public keys, {:?} given.", public_key.public_exponent.as_unsigned_bytes_be());
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        let key_data = public_key.modulus.as_unsigned_bytes_be();
        let len = key_data.len();

        let key_bits = attributes.key_bits;
        if key_bits != 0 && len * 8 != key_bits as usize {
            error!("If the key_bits field is non-zero (value is {}) it must be equal to the size of the key in data.", attributes.key_bits);
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        if len != 128 && len != 256 {
            error!(
                "The TPM provider only supports 1024 and 2048 bits RSA public keys ({} bits given).",
                len * 8
            );
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let pub_key_context = esapi_context
            .load_external_rsa_public_key(&key_data)
            .or_else(|e| {
                error!("Error creating a RSA signing key: {}.", e);
                Err(utils::to_response_status(e))
            })?;

        insert_password_context(
            &mut *store_handle,
            key_triple,
            PasswordContext {
                context: pub_key_context,
                auth_value: Vec::new(),
            },
            attributes,
        )?;

        Ok(psa_import_key::Result {})
    }

    fn psa_export_public_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (password_context, _key_attributes) = get_password_context(&*store_handle, key_triple)?;

        let pub_key_data = esapi_context
            .read_public_key(password_context.context)
            .or_else(|e| {
                error!("Error reading a public key: {}.", e);
                Err(utils::to_response_status(e))
            })?;

        let key = RsaPublicKey {
            // To produce a valid ASN.1 RSAPublicKey structure, 0x00 is put in front of the positive
            // modulus if highest significant bit is one, to differentiate it from a negative number.
            modulus: IntegerAsn1::from_unsigned_bytes_be(pub_key_data),
            public_exponent: IntegerAsn1::from_signed_bytes_be(PUBLIC_EXPONENT.to_vec()),
        };
        let key_data = picky_asn1_der::to_vec(&key).or_else(|err| {
            error!("Could not serialise key elements: {}.", err);
            Err(ResponseStatus::PsaErrorCommunicationFailure)
        })?;

        Ok(psa_export_public_key::Result { data: key_data })
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");

        let error_closure = |e| Err(key_info_managers::to_response_status(e));
        if store_handle
            .remove(&key_triple)
            .or_else(error_closure)?
            .is_none()
        {
            error!(
                "Key triple \"{}\" does not exist in the Key Info Manager.",
                key_triple
            );
            Err(ResponseStatus::PsaErrorDoesNotExist)
        } else {
            Ok(psa_destroy_key::Result {})
        }
    }

    fn psa_sign_hash(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        if alg
            != (AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            })
        {
            error!(
                "The TPM provider currently only supports signature algorithm to be RSA PKCS#1 v1.5 and the text hashed with SHA-256.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        if hash.len() != 32 {
            error!("The SHA-256 hash must be 32 bytes long.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let (password_context, key_attributes) = get_password_context(&*store_handle, key_triple)?;

        key_attributes.can_sign_hash()?;
        key_attributes.permits_alg(alg.into())?;
        key_attributes.compatible_with_alg(alg.into())?;

        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            } => (),
            _ => {
                error!(
                    "The TPM provider currently only supports \"RSA PKCS#1 v1.5 signature with hashing\" algorithm with SHA-256 as hashing algorithm for the PsaSignHash operation.");
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        let signature = esapi_context
            .sign(
                password_context.context,
                &password_context.auth_value,
                &hash,
            )
            .or_else(|e| {
                error!("Error signing: {}.", e);
                Err(utils::to_response_status(e))
            })?;

        Ok(psa_sign_hash::Result {
            signature: signature.signature,
        })
    }

    fn psa_verify_hash(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let signature = op.signature;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        if alg
            != (AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            })
        {
            error!(
                "The TPM provider currently only supports signature algorithm to be RSA PKCS#1 v1.5 and the text hashed with SHA-256.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        if hash.len() != 32 {
            error!("The SHA-256 hash must be 32 bytes long.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256),
            signature,
        };

        let (password_context, key_attributes) = get_password_context(&*store_handle, key_triple)?;

        key_attributes.can_verify_hash()?;
        key_attributes.permits_alg(alg.into())?;
        key_attributes.compatible_with_alg(alg.into())?;

        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            } => (),
            _ => {
                error!(
                    "The TPM provider currently only supports \"RSA PKCS#1 v1.5 signature with hashing\" algorithm with SHA-256 as hashing algorithm for the PsaVerifyHash operation.");
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        let _ = esapi_context
            .verify_signature(password_context.context, &hash, signature)
            .or_else(|e| Err(utils::to_response_status(e)))?;

        Ok(psa_verify_hash::Result {})
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

    /// Create an instance of TpmProvider
    ///
    /// # Safety
    ///
    /// Undefined behaviour might appear if two instances of TransientObjectContext are created
    /// using a same TCTI that does not handle multiple applications concurrently.
    pub unsafe fn build(self) -> std::io::Result<TpmProvider> {
        TpmProvider::new(
            self.key_info_store.ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "missing key info store")
            })?,
            tss_esapi::TransientObjectContext::new(
                self.tcti
                    .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing TCTI"))?,
                ROOT_KEY_SIZE,
                ROOT_KEY_AUTH_SIZE,
                self.owner_hierarchy_auth
                    .ok_or_else(|| {
                        std::io::Error::new(ErrorKind::InvalidData, "missing owner hierarchy auth")
                    })?
                    .as_bytes(),
            )
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
