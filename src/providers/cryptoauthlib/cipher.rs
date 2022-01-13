// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use log::error;
use parsec_interface::operations::psa_algorithm::Cipher;
use parsec_interface::operations::{psa_cipher_decrypt, psa_cipher_encrypt, psa_generate_random};
use parsec_interface::requests::{ResponseStatus, Result};
use std::convert::TryInto;

const CIPHER_IV_SIZE: usize = 16;
const CIPHER_CTR_SIZE: u8 = 4;

impl Provider {
    /// Check if given Cipher Algorithm need generated initialization vector to run
    pub(super) fn algorithm_need_iv(&self, alg: &Cipher) -> bool {
        !matches!(alg, Cipher::EcbNoPadding)
    }

    /// Convert Cipher Algorithm type from parsec to rust_cryptoauthlib type
    pub(super) fn get_cipher_algorithm(
        &self,
        mut cipher_params: rust_cryptoauthlib::CipherParam,
        alg: &Cipher,
    ) -> Result<rust_cryptoauthlib::CipherAlgorithm> {
        match alg {
            Cipher::Cfb => Ok(rust_cryptoauthlib::CipherAlgorithm::Cfb(cipher_params)),
            Cipher::Ctr => {
                cipher_params.counter_size = Some(CIPHER_CTR_SIZE);
                Ok(rust_cryptoauthlib::CipherAlgorithm::Ctr(cipher_params))
            }
            Cipher::Ofb => Ok(rust_cryptoauthlib::CipherAlgorithm::Ofb(cipher_params)),
            Cipher::EcbNoPadding => Ok(rust_cryptoauthlib::CipherAlgorithm::Ecb(cipher_params)),
            Cipher::CbcNoPadding => Ok(rust_cryptoauthlib::CipherAlgorithm::Cbc(cipher_params)),
            Cipher::CbcPkcs7 => Ok(rust_cryptoauthlib::CipherAlgorithm::CbcPkcs7(cipher_params)),
            _ => {
                error!("Cipher encryption failed: given algorithm is not supported.");
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }

    /// Generate random non-zero initialization vector
    pub fn generate_iv(&self) -> Result<Vec<u8>> {
        let random_op = psa_generate_random::Operation {
            size: CIPHER_IV_SIZE,
        };
        let random_bytes = self
            .psa_generate_random_internal(random_op)?
            .random_bytes
            .to_vec();
        Ok(random_bytes)
    }

    pub(super) fn psa_cipher_encrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_cipher_encrypt::Operation,
    ) -> Result<psa_cipher_encrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        op.validate(key_attributes)?;

        let mut cipher_param = rust_cryptoauthlib::CipherParam {
            ..Default::default()
        };
        let mut generated_iv = vec![0u8; 0];
        if self.algorithm_need_iv(&op.alg) {
            generated_iv = self.generate_iv()?;
            cipher_param.iv = Some(generated_iv[..].try_into()?);
        }

        let mut plaintext = op.plaintext.to_vec();
        let key_id = self.key_info_store.get_key_id::<u8>(&key_identity)?;

        let result = self.device.cipher_encrypt(
            self.get_cipher_algorithm(cipher_param, &op.alg)?,
            key_id,
            &mut plaintext,
        );
        match result {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                generated_iv.append(&mut plaintext);
                let ciphertext = zeroize::Zeroizing::new(generated_iv);
                Ok(psa_cipher_encrypt::Result { ciphertext })
            }
            rust_cryptoauthlib::AtcaStatus::AtcaInvalidSize
            | rust_cryptoauthlib::AtcaStatus::AtcaInvalidId
            | rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                error!("Cipher encryption failed: given plaintext is invalid.");
                Err(ResponseStatus::PsaErrorInvalidArgument)
            }
            _ => Err(ResponseStatus::PsaErrorGenericError),
        }
    }

    pub(super) fn psa_cipher_decrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_cipher_decrypt::Operation,
    ) -> Result<psa_cipher_decrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        op.validate(key_attributes)?;

        let mut cipher_param = rust_cryptoauthlib::CipherParam {
            ..Default::default()
        };
        let mut ciphertext = op.ciphertext.to_vec();

        if self.algorithm_need_iv(&op.alg) {
            if ciphertext.len() < CIPHER_IV_SIZE {
                error!(
                    "Cipher decryption failed: given ciphertext is too short to contain initialization vector."
                );
                return Err(ResponseStatus::PsaErrorInvalidArgument);
            }
            let mut iv = ciphertext;
            ciphertext = iv.split_off(CIPHER_IV_SIZE);
            cipher_param.iv = Some(iv[..].try_into()?);
        }

        let key_id = self.key_info_store.get_key_id::<u8>(&key_identity)?;

        let result = self.device.cipher_decrypt(
            self.get_cipher_algorithm(cipher_param, &op.alg)?,
            key_id,
            &mut ciphertext,
        );

        match result {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                let plaintext = zeroize::Zeroizing::new(ciphertext);
                Ok(psa_cipher_decrypt::Result { plaintext })
            }
            rust_cryptoauthlib::AtcaStatus::AtcaInvalidSize
            | rust_cryptoauthlib::AtcaStatus::AtcaInvalidId
            | rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                error!("Cipher decryption failed: given ciphertext is invalid.");
                Err(ResponseStatus::PsaErrorInvalidArgument)
            }
            _ => Err(ResponseStatus::PsaErrorGenericError),
        }
    }
}
