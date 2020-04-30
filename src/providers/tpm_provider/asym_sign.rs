// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{key_management, utils, TpmProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::error;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use tss_esapi::{constants::TPM2_ALG_SHA256, utils::AsymSchemeUnion, utils::Signature};

impl TpmProvider {
    pub(super) fn psa_sign_hash_internal(
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

        let (password_context, key_attributes) =
            key_management::get_password_context(&*store_handle, key_triple)?;

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

    pub(super) fn psa_verify_hash_internal(
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

        let (password_context, key_attributes) =
            key_management::get_password_context(&*store_handle, key_triple)?;

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
