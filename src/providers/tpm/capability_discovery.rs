// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use super::{utils, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::providers::crypto_capability::CanDoCrypto;
use log::{info, trace};
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::psa_key_attributes::{Attributes, Type};
use parsec_interface::requests::ResponseStatus::PsaErrorNotSupported;
use parsec_interface::requests::Result;

impl CanDoCrypto for Provider {
    fn can_do_crypto_internal(
        &self,
        _application_identity: &ApplicationIdentity,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto_internal");

        // Check attributes compatibility with the provider
        match op.attributes.key_type {
            Type::RsaKeyPair | Type::RsaPublicKey => {
                let _ =
                    utils::rsa_key_bits(op.attributes.bits).map_err(|_| PsaErrorNotSupported)?;
                Ok(can_do_crypto::Result)
            }
            Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => {
                let _ = utils::convert_curve_to_tpm(op.attributes)?;
                Ok(can_do_crypto::Result)
            }
            _ => {
                info!("Unsupported key type {:?}", op.attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn use_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("use_check_internal");

        let _ = utils::parsec_to_tpm_params(attributes).map_err(|_| PsaErrorNotSupported)?;

        // TO-DO we also need to check capabilities of used TMP module.
        // TPM_GetCapability support in the tss-esapi crate is required.
        Ok(can_do_crypto::Result)
    }

    fn generate_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("generate_check_internal");
        match attributes.key_type {
            Type::RsaKeyPair | Type::EccKeyPair { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn import_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("import_check_internal");
        match attributes.key_type {
            Type::RsaPublicKey | Type::EccPublicKey { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }
}
