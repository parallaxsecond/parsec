use super::{utils, Provider};
use crate::authenticators::ApplicationName;
use crate::providers::crypto_capability::CanDoCrypto;
use log::{info, trace};
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::psa_key_attributes::{Attributes, Type};
use parsec_interface::requests::ResponseStatus::PsaErrorNotSupported;
use parsec_interface::requests::Result;

impl CanDoCrypto for Provider {
    fn can_do_crypto_internal(
        &self,
        _app_name: ApplicationName,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto_internal for TPM provider");

        // Check attributes compatibility

        // TO_DO what to do when attributes.policy.permitted_algorithms == Algorithm::None?
        // it should pass for generate_check and import_check
        let _ = utils::parsec_to_tpm_params(op.attributes).map_err(|_| PsaErrorNotSupported)?;
        Ok(can_do_crypto::Result)
    }

    fn use_check_internal(&self, _attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("use_check_internal for TPM provider");

        // This method can be called only if can_do_crypto_internal passed
        // where we check generic crypto capabilites.
        Ok(can_do_crypto::Result)
    }

    fn generate_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("generate_check_internal for TPM provider");
        match attributes.key_type {
            Type::RsaKeyPair | Type::EccKeyPair { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn import_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("import_check_internal for TPM provider");
        match attributes.key_type {
            Type::RsaPublicKey | Type::EccPublicKey { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }
}
