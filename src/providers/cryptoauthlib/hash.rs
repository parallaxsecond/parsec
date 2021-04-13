// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use log::error;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::psa_hash_compare;
use parsec_interface::operations::psa_hash_compute;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        let mut hash = vec![0u8; op.alg.hash_length()];
        match op.alg {
            Hash::Sha256 => {
                let message = op.input.to_vec();

                let err = self.device.sha(message, &mut hash);
                match err {
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
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }

    pub(super) fn psa_hash_compare_internal(
        &self,
        op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        let alg_len = op.alg.hash_length();
        // calculate input hash
        let op_compute = psa_hash_compute::Operation {
            alg: op.alg,
            input: op.input,
        };
        // check hash length
        if op.hash.len() != alg_len {
            let error = ResponseStatus::PsaErrorInvalidArgument;
            error!("Hash length comparison failed: {}", error);
            return Err(error);
        }
        match self.psa_hash_compute_internal(op_compute) {
            Ok(psa_hash_compute::Result { hash }) => {
                // compare hashes
                if op.hash != hash {
                    let error = ResponseStatus::PsaErrorInvalidSignature;
                    error!("Hash comparison failed: {}", error);
                    return Err(error);
                }
                // return result
                Ok(psa_hash_compare::Result)
            }
            Err(error) => Err(error),
        }
    }
}
