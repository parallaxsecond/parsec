// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let mut random_bytes = vec![0u8; 0];
        let zero_vector = vec![0u8, op.size as u8];
        let mut loop_count = 0u8;
        // external loop to retry generation if vector is not secure
        loop {
            // calculate internal loop count
            let call_count = (op.size + rust_cryptoauthlib::ATCA_RANDOM_BUFFER_SIZE - 1)
                / rust_cryptoauthlib::ATCA_RANDOM_BUFFER_SIZE;
            // internal loop for vector size greater than buffer size
            for _i in 0..call_count {
                let mut buffer = Vec::with_capacity(rust_cryptoauthlib::ATCA_RANDOM_BUFFER_SIZE);
                let err = self.device.random(&mut buffer);
                match err {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                        // append buffer vector to result vector
                        random_bytes.append(&mut buffer);
                    }
                    _ => {
                        let error = ResponseStatus::PsaErrorGenericError;
                        format_error!("Bytes generation failed ", err);
                        return Err(error);
                    }
                }
            } // end internal loop
            random_bytes.truncate(op.size); // cut vector to desired size
            match random_bytes != zero_vector {
                true => {
                    break Ok(psa_generate_random::Result {
                        random_bytes: random_bytes.into(),
                    })
                }
                false => {
                    loop_count += 1;
                    if loop_count < 3 {
                        continue;
                    } else {
                        let err = ResponseStatus::PsaErrorInsufficientEntropy;
                        format_error!("Bytes generation failed ", err);
                        return Err(err);
                    }
                }
            }
        } // end external loop
    }
}
