// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// CAL supports CCM with:
// - tag lenght must be <4,16> and must be even number
// - nonce lenght must be <7,13>
// CAL supports GCM with:
// - tag lenght must be <12,16>
// - nonce lenght must be <7,13>

use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use log::error;
use parsec_interface::operations::psa_algorithm::{Aead, AeadWithDefaultLengthTag};
use parsec_interface::operations::{psa_aead_decrypt, psa_aead_encrypt};
use parsec_interface::requests::{ResponseStatus, Result};

const DEFAULT_TAG_LENGTH: usize = 16;

pub fn get_tag_length(alg: &Aead) -> Option<usize> {
    match alg {
        Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm) => Some(DEFAULT_TAG_LENGTH),
        Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm) => Some(DEFAULT_TAG_LENGTH),
        Aead::AeadWithShortenedTag {
            aead_alg: AeadWithDefaultLengthTag::Ccm,
            tag_length,
        } => Some(*tag_length),
        Aead::AeadWithShortenedTag {
            aead_alg: AeadWithDefaultLengthTag::Gcm,
            tag_length,
        } => Some(*tag_length),
        _ => None,
    }
}

pub fn is_ccm_selected(alg: &Aead) -> bool {
    matches!(
        alg,
        Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)
            | Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                ..
            }
    )
}

pub fn get_aead_algorithm(
    aead_params: rust_cryptoauthlib::AeadParam,
    alg: &Aead,
) -> rust_cryptoauthlib::AeadAlgorithm {
    if is_ccm_selected(alg) {
        rust_cryptoauthlib::AeadAlgorithm::Ccm(aead_params)
    } else {
        rust_cryptoauthlib::AeadAlgorithm::Gcm(aead_params)
    }
}

impl Provider {
    pub(super) fn psa_aead_encrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_aead_encrypt::Operation,
    ) -> Result<psa_aead_encrypt::Result> {
        match get_tag_length(&op.alg) {
            Some(tag_length) => {
                let key_identity = KeyIdentity::new(
                    application_identity.clone(),
                    self.provider_identity.clone(),
                    op.key_name.clone(),
                );
                let key_id = self.key_info_store.get_key_id::<u8>(&key_identity)?;
                let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
                op.validate(key_attributes)?;

                let aead_param = rust_cryptoauthlib::AeadParam {
                    nonce: op.nonce.to_vec(),
                    tag_length: Some(tag_length as u8),
                    additional_data: Some(op.additional_data.to_vec()),
                    ..Default::default()
                };

                let mut plaintext = op.plaintext.to_vec();

                match self.device.aead_encrypt(
                    get_aead_algorithm(aead_param, &op.alg),
                    key_id,
                    &mut plaintext,
                ) {
                    Ok(tag) => {
                        plaintext.extend(tag);

                        Ok(psa_aead_encrypt::Result {
                            ciphertext: plaintext.into(),
                        })
                    }
                    Err(error) => {
                        error!("aead_encrypt failed CAL error {}.", error);
                        match error {
                            rust_cryptoauthlib::AtcaStatus::AtcaInvalidSize
                            | rust_cryptoauthlib::AtcaStatus::AtcaInvalidId
                            | rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                                Err(ResponseStatus::PsaErrorInvalidArgument)
                            }
                            _ => Err(ResponseStatus::PsaErrorGenericError),
                        }
                    }
                }
            }
            None => {
                error!("aead_encrypt failed, algorithm not supported");
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }

    pub(super) fn psa_aead_decrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_aead_decrypt::Operation,
    ) -> Result<psa_aead_decrypt::Result> {
        match get_tag_length(&op.alg) {
            Some(tag_length) => {
                let key_identity = KeyIdentity::new(
                    application_identity.clone(),
                    self.provider_identity.clone(),
                    op.key_name.clone(),
                );
                let key_id = self.key_info_store.get_key_id::<u8>(&key_identity)?;
                let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
                op.validate(key_attributes)?;

                if tag_length < op.ciphertext.len() {
                    let mut ciphertext = op.ciphertext.to_vec();
                    let tag = ciphertext.split_off(ciphertext.len() - tag_length);

                    let aead_param = rust_cryptoauthlib::AeadParam {
                        nonce: op.nonce.to_vec(),
                        tag: Some(tag),
                        additional_data: Some(op.additional_data.to_vec()),
                        ..Default::default()
                    };

                    match self.device.aead_decrypt(
                        get_aead_algorithm(aead_param, &op.alg),
                        key_id,
                        &mut ciphertext,
                    ) {
                        Ok(true) => Ok(psa_aead_decrypt::Result {
                            plaintext: ciphertext.into(),
                        }),
                        Ok(false) => {
                            error!("aead_decrypt authentication failed");
                            Err(ResponseStatus::PsaErrorInvalidSignature)
                        }
                        Err(error) => {
                            error!("aead_decrypt error {}", error);
                            match error {
                                rust_cryptoauthlib::AtcaStatus::AtcaInvalidSize
                                | rust_cryptoauthlib::AtcaStatus::AtcaInvalidId
                                | rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                                    Err(ResponseStatus::PsaErrorInvalidArgument)
                                }
                                _ => Err(ResponseStatus::PsaErrorGenericError),
                            }
                        }
                    }
                } else {
                    error!(
                        "aead_decrypt failed, tag lenght {} longer then ciphertext {}",
                        tag_length,
                        op.ciphertext.len()
                    );
                    Err(ResponseStatus::PsaErrorInvalidArgument)
                }
            }

            None => {
                error!("aead_decrypt failed, algorithm not supported");
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }
}
