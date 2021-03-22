// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::to_response_status;
use super::KeyPairType;
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use cryptoki::types::mechanism::Mechanism;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use std::convert::TryFrom;

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mech = Mechanism::try_from(Algorithm::from(op.alg)).map_err(to_response_status)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PublicKey)?;
        info!("Located encrypting key.");

        trace!("Encrypt* commands");
        Ok(psa_asymmetric_encrypt::Result {
            ciphertext: session
                .encrypt(&mech, key, &op.plaintext)
                .map_err(to_response_status)?
                .into(),
        })
    }

    pub(super) fn psa_asymmetric_decrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mech = Mechanism::try_from(Algorithm::from(op.alg)).map_err(to_response_status)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PrivateKey)?;
        info!("Located decrypting key.");

        trace!("Decrypt* command");
        Ok(psa_asymmetric_decrypt::Result {
            plaintext: session
                .decrypt(&mech, key, &op.ciphertext)
                .map_err(to_response_status)?
                .into(),
        })
    }

    pub(super) fn software_psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let alg = op.alg;
        let salt_buff = op.salt.as_ref().map(|salt| salt.as_slice());
        let buffer_size = key_attributes.asymmetric_encrypt_output_size(alg)?;
        let mut ciphertext = vec![0u8; buffer_size];
        let pub_key_id = self.move_pub_key_to_psa_crypto(&key_triple)?;

        info!("Encrypting plaintext with PSA Crypto");
        let res = match psa_crypto::operations::asym_encryption::encrypt(
            pub_key_id,
            alg,
            &op.plaintext,
            salt_buff,
            &mut ciphertext,
        ) {
            Ok(output_size) => {
                ciphertext.resize(output_size, 0);
                Ok(psa_asymmetric_encrypt::Result {
                    ciphertext: ciphertext.into(),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Asymmetric encryption failed", error);
                Err(error)
            }
        };

        let _ = self.remove_psa_crypto_pub_key(pub_key_id);
        res
    }
}
