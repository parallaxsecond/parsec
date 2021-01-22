use super::Provider;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::{ResponseStatus, Result};
use zeroize::Zeroizing;

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let mut random_bytes = vec![0u8, 0];
        // check input size
        // size 0 - no need to run operation
        if op.size == 0 {
            Ok(psa_generate_random::Result {
                random_bytes: Zeroizing::new(vec![]),
            })
        }
        // for size bigger than buffer size operation need to be executed multiple times
        else {
            // calculate loop count
            let call_count = (op.size / rust_cryptoauthlib::ACTA_RANDOM_BUFFER_SIZE) + 1;
            // loop
            for _i in 0..call_count {
                let mut buffer = Vec::with_capacity(rust_cryptoauthlib::ACTA_RANDOM_BUFFER_SIZE);
                let err = rust_cryptoauthlib::atcab_random(&mut buffer);
                match err {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                        // append buffer vector to result vector
                        random_bytes.append(&mut buffer);
                    }
                    _ => {
                        let error = ResponseStatus::PsaErrorGenericError;
                        format_error!("Hash computation failed ", err);
                        return Err(error);
                    }
                }
            }
            // cut vector to desired size
            random_bytes.truncate(op.size);
            Ok(psa_generate_random::Result {
                random_bytes: random_bytes.into(),
            })
        }
    }
}
