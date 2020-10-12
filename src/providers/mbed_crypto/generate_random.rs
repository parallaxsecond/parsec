use super::Provider;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::{ResponseStatus, Result};
use psa_crypto::operations::other::generate_random;

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let buffer_size = op.size;
        if buffer_size > crate::utils::GlobalConfig::buffer_size_limit() {
            let error = ResponseStatus::ResponseTooLarge;
            format_error!("Generate random status", error);
            return Err(error);
        }

        let mut buffer = vec![0u8; buffer_size];
        match generate_random(&mut buffer) {
            Ok(_) => Ok(psa_generate_random::Result {
                random_bytes: buffer.into(),
            }),
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Generate random status", error);
                Err(error)
            }
        }
    }
}
