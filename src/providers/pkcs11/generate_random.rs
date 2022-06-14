// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::to_response_status;
use super::Provider;
use log::error;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::{ResponseStatus, Result};
use std::convert::TryFrom;

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let length = u32::try_from(op.size).or_else(|_| {
            let error = ResponseStatus::PsaErrorGenericError;
            error!("Requested size is too large");
            Err(error)
        })?;

        let session = self.new_session()?;

        Ok(psa_generate_random::Result {
            random_bytes: session
                .generate_random_vec(length)
                .map_err(to_response_status)?
                .into(),
        })
    }
}
