// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::{algorithm_to_mechanism, to_response_status};
use super::KeyPairType;
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use cryptoki::error::Error;
use cryptoki::error::RvError;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricEncryption};
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        op.validate(key_attributes)?;

        let mech = algorithm_to_mechanism(Algorithm::from(op.alg)).map_err(to_response_status)?;

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
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        op.validate(key_attributes)?;

        let mech = algorithm_to_mechanism(Algorithm::from(op.alg)).map_err(to_response_status)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PrivateKey)?;
        info!("Located decrypting key.");

        trace!("Decrypt* command");
        Ok(psa_asymmetric_decrypt::Result {
            plaintext: session
                .decrypt(&mech, key, &op.ciphertext)
                .map_err(|e| {
                    // If the algorithm is RSA with PKCS#1 v1.5 padding and we get CKR_ENCRYPTED_DATA_INVALID back,
                    // it means the padding has been deemed invalid and we should let the caller know
                    // about that. This allows clients to mitigate attacks that leverage padding
                    // oracles a la Bleichenbacher.
                    // See https://cryptosense.com/blog/why-pkcs1v1-5-encryption-should-be-put-out-of-our-misery
                    // for more details.
                    if let Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt) =
                        key_attributes.policy.permitted_algorithms
                    {
                        match e {
                            Error::Pkcs11(RvError::EncryptedDataInvalid) => {
                                return ResponseStatus::PsaErrorInvalidPadding
                            }
                            _ => (),
                        }
                    }
                    to_response_status(e)
                })?
                .into(),
        })
    }

    pub(super) fn software_psa_asymmetric_encrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        op.validate(key_attributes)?;

        let alg = op.alg;
        let salt_buff = op.salt.as_ref().map(|salt| salt.as_slice());
        let buffer_size = key_attributes.asymmetric_encrypt_output_size(alg)?;
        let mut ciphertext = vec![0u8; buffer_size];
        let pub_key_id = self.move_pub_key_to_psa_crypto(&key_identity)?;

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
