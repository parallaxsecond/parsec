// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use parsec_interface::operations::psa_algorithm::RawKeyAgreement;
use parsec_interface::operations::psa_raw_key_agreement;
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::Secret;

impl Provider {
    pub(super) fn psa_raw_key_agreement_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_raw_key_agreement::Operation,
    ) -> Result<psa_raw_key_agreement::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.private_key_name.clone(),
        );
        let key_id = self.key_info_store.get_key_id::<u8>(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        op.validate(key_attributes)?;

        match op.alg {
            RawKeyAgreement::Ecdh => {
                let parameters = rust_cryptoauthlib::EcdhParams {
                    out_target: rust_cryptoauthlib::EcdhTarget::Output,
                    slot_id: Some(key_id),
                    ..Default::default()
                };
                let mut key_data = op.peer_key.to_vec();
                if key_data.len() == 65 {
                    key_data = op.peer_key[1..].to_vec();
                }
                match self.device.ecdh(parameters, &key_data) {
                    Ok(result) => {
                        let shared_secret = result.pms.unwrap().to_vec();
                        Ok(psa_raw_key_agreement::Result {
                            shared_secret: Secret::new(shared_secret),
                        })
                    }
                    Err(status) => {
                        format_error!("Raw key agreement status: ", status);
                        Err(ResponseStatus::PsaErrorGenericError)
                    }
                }
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}
