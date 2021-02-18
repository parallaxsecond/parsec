// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use super::{utils, KeyPairType, ReadWriteSession, Session};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use std::convert::TryFrom;
use utils::CkMechanism;

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());

        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mut mech = CkMechanism::try_from(Algorithm::from(op.alg))?;
        let (mech, _params) = mech.as_c_type();

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Asymmetric sign in session {}", session.session_handle());
        }

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PrivateKey)?;
        info!("Located signing key.");

        trace!("SignInit command");
        match self.backend.sign_init(session.session_handle(), &mech, key) {
            Ok(_) => {
                info!("Signing operation initialized.");

                trace!("Sign command");
                match self.backend.sign(
                    session.session_handle(),
                    &utils::digest_info(op.alg, op.hash.to_vec())?,
                ) {
                    Ok(signature) => Ok(psa_sign_hash::Result {
                        signature: signature.into(),
                    }),
                    Err(e) => {
                        format_error!("Failed to execute signing operation", e);
                        Err(utils::to_response_status(e))
                    }
                }
            }
            Err(e) => {
                format_error!("Failed to initialize signing operation", e);
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mut mech = CkMechanism::try_from(Algorithm::from(op.alg))?;
        let (mech, _params) = mech.as_c_type();

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Asymmetric verify in session {}", session.session_handle());
        }

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PublicKey)?;
        info!("Located public key.");

        trace!("VerifyInit command");
        match self
            .backend
            .verify_init(session.session_handle(), &mech, key)
        {
            Ok(_) => {
                info!("Verify operation initialized.");

                trace!("Verify command");
                match self.backend.verify(
                    session.session_handle(),
                    &utils::digest_info(op.alg, op.hash.to_vec())?,
                    &op.signature,
                ) {
                    Ok(_) => Ok(psa_verify_hash::Result {}),
                    Err(e) => Err(utils::to_response_status(e)),
                }
            }
            Err(e) => {
                format_error!("Failed to initialize verifying operation", e);
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn software_psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let pub_key_id = self.move_pub_key_to_psa_crypto(&key_triple)?;

        info!("Verifying signature with PSA Crypto");
        let res = match psa_crypto::operations::asym_signature::verify_hash(
            pub_key_id,
            op.alg,
            &op.hash,
            &op.signature,
        ) {
            Ok(()) => Ok(psa_verify_hash::Result {}),
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Verify hash failed", error);
                Err(error)
            }
        };

        let _ = self.remove_psa_crypto_pub_key(pub_key_id);
        res
    }
}
