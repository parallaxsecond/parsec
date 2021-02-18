// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_aead_decrypt, psa_aead_encrypt};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use psa_crypto::operations::aead;
use psa_crypto::types::key;

impl Provider {
    pub(super) fn psa_aead_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_aead_encrypt::Operation,
    ) -> Result<psa_aead_encrypt::Result> {
        let key_name = op.key_name.clone();

        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");
        let id = key::Id::from_persistent_key_id(key_id);
        let key_attributes = key::Attributes::from_key_id(id)?;

        op.validate(key_attributes)?;
        let alg = op.alg;
        let buffer_size = key_attributes.aead_encrypt_output_size(alg, op.plaintext.len())?;
        let mut ciphertext = vec![0u8; buffer_size];

        match aead::encrypt(
            id,
            alg,
            &op.nonce,
            &op.additional_data,
            &op.plaintext,
            &mut ciphertext,
        ) {
            Ok(output_size) => {
                ciphertext.resize(output_size, 0);
                Ok(psa_aead_encrypt::Result {
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

    pub(super) fn psa_aead_decrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_aead_decrypt::Operation,
    ) -> Result<psa_aead_decrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id);
        let key_attributes = key::Attributes::from_key_id(id)?;
        op.validate(key_attributes)?;
        let buffer_size = key_attributes.aead_decrypt_output_size(op.alg, op.ciphertext.len())?;
        let mut plaintext = vec![0u8; buffer_size];

        match aead::decrypt(
            id,
            op.alg,
            &op.nonce,
            &op.additional_data,
            &op.ciphertext,
            &mut plaintext,
        ) {
            Ok(output_size) => {
                plaintext.resize(output_size, 0);
                Ok(psa_aead_decrypt::Result {
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
