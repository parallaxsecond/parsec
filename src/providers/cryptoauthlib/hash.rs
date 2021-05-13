// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use log::error;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::psa_hash_compare;
use parsec_interface::operations::psa_hash_compute;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    /// Calculate SHA2-256 digest for a given message using CALib.
    /// Ensure proper return value type.
    pub fn sha256(&self, msg: &[u8]) -> Result<psa_hash_compute::Result> {
        let mut hash = vec![0u8; rust_cryptoauthlib::ATCA_SHA2_256_DIGEST_SIZE];
        match self.device.sha(msg.to_vec(), &mut hash) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                Ok(psa_hash_compute::Result { hash: hash.into() })
            }
            rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                Err(ResponseStatus::PsaErrorInvalidArgument)
            }
            rust_cryptoauthlib::AtcaStatus::AtcaSmallBuffer => {
                Err(ResponseStatus::PsaErrorBufferTooSmall)
            }
            rust_cryptoauthlib::AtcaStatus::AtcaRxNoResponse
            | rust_cryptoauthlib::AtcaStatus::AtcaRxFail => {
                Err(ResponseStatus::PsaErrorCommunicationFailure)
            }
            _ => Err(ResponseStatus::PsaErrorGenericError),
        }
    }

    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        match op.alg {
            Hash::Sha256 => self.sha256(&op.input),
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }

    pub(super) fn psa_hash_compare_internal(
        &self,
        op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        // check hash length
        if op.hash.len() != op.alg.hash_length() {
            let error = ResponseStatus::PsaErrorInvalidArgument;
            error!("Invalid input hash length: {}", error);
            return Err(error);
        }
        match op.alg {
            Hash::Sha256 => {
                // compute hash
                let hash = self.sha256(&op.input)?.hash;
                // compare input vs. computed hash
                if op.hash != hash {
                    let error = ResponseStatus::PsaErrorInvalidSignature;
                    error!("Hash comparison failed: {}", error);
                    Err(error)
                } else {
                    Ok(psa_hash_compare::Result)
                }
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}
