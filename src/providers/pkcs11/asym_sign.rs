// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::to_response_status;
use super::Provider;
use super::{utils, KeyPairType};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use cryptoki::types::mechanism::Mechanism;
use log::{info, trace};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderId, ResponseStatus, Result};
use std::convert::TryFrom;

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::Pkcs11, op.key_name.clone());

        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mech = Mechanism::try_from(Algorithm::from(op.alg)).map_err(to_response_status)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PrivateKey)?;
        info!("Located signing key.");

        trace!("Sign* command");
        Ok(psa_sign_hash::Result {
            signature: session
                .sign(&mech, key, &utils::digest_info(op.alg, op.hash.to_vec())?)
                .map_err(to_response_status)?
                .into(),
        })
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::Pkcs11, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mech = Mechanism::try_from(Algorithm::from(op.alg)).map_err(to_response_status)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PublicKey)?;
        info!("Located public key.");

        trace!("Verify* command");
        session
            .verify(
                &mech,
                key,
                &utils::digest_info(op.alg, op.hash.to_vec())?,
                &op.signature,
            )
            .map_err(to_response_status)?;
        Ok(psa_verify_hash::Result {})
    }

    pub(super) fn software_psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::Pkcs11, op.key_name.clone());
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
