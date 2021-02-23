// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use super::{utils, KeyPairType, ReadWriteSession, Session};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use std::convert::TryFrom;
use utils::CkMechanism;

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

        let mut mech = CkMechanism::try_from(Algorithm::from(op.alg))?;
        let (mech, _params) = mech.as_c_type();

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Asymmetric encrypt in session {}", session.session_handle());
        }

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PublicKey)?;
        info!("Located encrypting key.");

        trace!("EncryptInit command");
        match self
            .backend
            .encrypt_init(session.session_handle(), &mech, key)
        {
            Ok(_) => {
                info!("Encrypting operation initialized.");

                trace!("Encrypt command");
                match self
                    .backend
                    .encrypt(session.session_handle(), &op.plaintext)
                {
                    Ok(ciphertext) => Ok(psa_asymmetric_encrypt::Result {
                        ciphertext: ciphertext.into(),
                    }),
                    Err(e) => {
                        format_error!("Failed to execute encrypting operation", e);
                        Err(utils::to_response_status(e))
                    }
                }
            }
            Err(e) => {
                format_error!("Failed to initialize encrypting operation", e);
                Err(utils::to_response_status(e))
            }
        }
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

        let mut mech = CkMechanism::try_from(Algorithm::from(op.alg))?;
        let (mech, _params) = mech.as_c_type();

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Asymmetric decrypt in session {}", session.session_handle());
        }

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PrivateKey)?;
        info!("Located decrypting key.");

        trace!("DecryptInit command");
        match self
            .backend
            .decrypt_init(session.session_handle(), &mech, key)
        {
            Ok(_) => {
                info!("Decrypt operation initialized.");

                trace!("Decrypt command");
                match self
                    .backend
                    .decrypt(session.session_handle(), &op.ciphertext)
                {
                    Ok(plaintext) => Ok(psa_asymmetric_decrypt::Result {
                        plaintext: plaintext.into(),
                    }),
                    Err(e) => Err(utils::to_response_status(e)),
                }
            }
            Err(e) => {
                format_error!("Failed to initialize decrypting operation", e);
                Err(utils::to_response_status(e))
            }
        }
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
