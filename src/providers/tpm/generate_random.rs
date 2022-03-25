// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils;
use super::Provider;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::Result;

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let size = op.size;

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let random_bytes = esapi_context
            .as_mut()
            .execute_without_session(|esapi_context| esapi_context.get_random(size))
            .map_err(|e| {
                format_error!("Failed to get random bytes", e);
                utils::to_response_status(e)
            })?;
        Ok(psa_generate_random::Result {
            random_bytes: random_bytes.value().to_vec().into(),
        })
    }
}
