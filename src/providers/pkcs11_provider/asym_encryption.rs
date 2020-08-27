// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Pkcs11Provider;
use super::{key_management::get_key_info, utils, KeyPairType, ReadWriteSession, Session};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderID, Result};
use std::convert::TryFrom;
use utils::CkMechanism;

impl Pkcs11Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let (key_id, key_attributes) = get_key_info(&key_triple, &*store_handle)?;

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
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let (key_id, key_attributes) = get_key_info(&key_triple, &*store_handle)?;

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
}
