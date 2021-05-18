// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderId, ResponseStatus, Result};
use psa_crypto::operations::asym_encryption;
use psa_crypto::types::key;

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_name = op.key_name.clone();

        let key_triple = KeyTriple::new(app_name, ProviderId::MbedCrypto, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");
        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = key::Attributes::from_key_id(id)?;

        op.validate(key_attributes)?;
        let salt_buff = op.salt.as_ref().map(|salt| salt.as_slice());
        let alg = op.alg;
        let buffer_size = key_attributes.asymmetric_encrypt_output_size(alg)?;
        let mut ciphertext = vec![0u8; buffer_size];

        match asym_encryption::encrypt(id, alg, &op.plaintext, salt_buff, &mut ciphertext) {
            Ok(output_size) => {
                ciphertext.resize(output_size, 0);
                Ok(psa_asymmetric_encrypt::Result {
                    ciphertext: ciphertext.into(),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Encrypt status: ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_asymmetric_decrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::MbedCrypto, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = key::Attributes::from_key_id(id)?;
        op.validate(key_attributes)?;
        let salt_buff = op.salt.as_ref().map(|salt| salt.as_slice());
        let buffer_size = key_attributes.asymmetric_decrypt_output_size(op.alg)?;
        let mut plaintext = vec![0u8; buffer_size];

        match asym_encryption::decrypt(id, op.alg, &op.ciphertext, salt_buff, &mut plaintext) {
            Ok(output_size) => {
                plaintext.resize(output_size, 0);
                Ok(psa_asymmetric_decrypt::Result {
                    plaintext: plaintext.into(),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Decrypt status: ", error);
                Err(error)
            }
        }
    }
}
