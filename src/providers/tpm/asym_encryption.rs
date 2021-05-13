// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{
    utils::{self, PasswordContext},
    Provider,
};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderId, Result};
use std::convert::TryInto;
use std::ops::Deref;

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::Tpm, op.key_name.clone());

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let password_context: PasswordContext = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        match esapi_context.rsa_encrypt(
            password_context.context,
            Some(
                password_context
                    .auth_value
                    .try_into()
                    .map_err(utils::to_response_status)?,
            ),
            op.plaintext
                .deref()
                .clone()
                .try_into()
                .map_err(utils::to_response_status)?,
            utils::convert_asym_scheme_to_tpm(op.alg.into())?,
            match op.salt {
                Some(salt) => Some(
                    salt.deref()
                        .to_vec()
                        .try_into()
                        .map_err(utils::to_response_status)?,
                ),
                None => None,
            },
        ) {
            Ok(ciphertext) => Ok(psa_asymmetric_encrypt::Result {
                ciphertext: ciphertext.value().to_vec().into(),
            }),
            Err(tss_error) => {
                let error = utils::to_response_status(tss_error);
                format_error!("Encryption failed", tss_error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_asymmetric_decrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::Tpm, op.key_name.clone());

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let password_context: PasswordContext = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        match esapi_context.rsa_decrypt(
            password_context.context,
            Some(
                password_context
                    .auth_value
                    .try_into()
                    .map_err(utils::to_response_status)?,
            ),
            op.ciphertext
                .deref()
                .clone()
                .try_into()
                .map_err(utils::to_response_status)?,
            utils::convert_asym_scheme_to_tpm(op.alg.into())?,
            match op.salt {
                Some(salt) => Some(
                    salt.deref()
                        .to_vec()
                        .try_into()
                        .map_err(utils::to_response_status)?,
                ),
                None => None,
            },
        ) {
            Ok(plaintext) => Ok(psa_asymmetric_decrypt::Result {
                plaintext: plaintext.value().to_vec().into(),
            }),
            Err(tss_error) => {
                let error = utils::to_response_status(tss_error);
                format_error!("Encryption failed", tss_error);
                Err(error)
            }
        }
    }
}
