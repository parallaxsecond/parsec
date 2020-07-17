// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{key_management, utils, TpmProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::error;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};

impl TpmProvider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, op.key_name.clone());

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (password_context, key_attributes) =
            key_management::get_password_context(&*store_handle, key_triple)?;

        match op.alg {
            AsymmetricSignature::RsaPkcs1v15Sign { .. } => (),
            AsymmetricSignature::Ecdsa { .. } => (),
            _ => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Requested algorithm is not supported by the TPM provider: {:?}",
                        op.alg
                    );
                } else {
                    error!("Requested algorithm is not supported by the TPM provider");
                }
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        op.validate(key_attributes)?;

        let signature = esapi_context
            .sign(
                password_context.context,
                &password_context.auth_value,
                &op.hash,
            )
            .map_err(|e| {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!("Error signing: {}.", e);
                }
                utils::to_response_status(e)
            })?;

        Ok(psa_sign_hash::Result {
            signature: utils::signature_data_to_bytes(signature.signature, key_attributes)?.into(),
        })
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, op.key_name.clone());

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (password_context, key_attributes) =
            key_management::get_password_context(&*store_handle, key_triple)?;

        match op.alg {
            AsymmetricSignature::RsaPkcs1v15Sign { .. } => (),
            AsymmetricSignature::Ecdsa { .. } => (),
            _ => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Requested algorithm is not supported by the TPM provider: {:?}",
                        op.alg
                    );
                } else {
                    error!("Requested algorithm is not supported by the TPM provider");
                }
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        op.validate(key_attributes)?;

        let signature = utils::parsec_to_tpm_signature(op.signature, key_attributes, op.alg)?;

        let _ = esapi_context
            .verify_signature(password_context.context, &op.hash, signature)
            .map_err(utils::to_response_status)?;

        Ok(psa_verify_hash::Result {})
    }
}
