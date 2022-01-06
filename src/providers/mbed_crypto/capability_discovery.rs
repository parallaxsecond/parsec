// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use super::Provider;
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
        _app_identity: &ApplicationIdentity,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto_internal");

        // Check if psa-crypto can convert the attributes into PSA structure
        // The conversion includes some validity checks.
        op.attributes.can_convert_into_psa().map_err(|_| {
            info!("Unsupported key attributes {:?}", op.attributes);
            PsaErrorNotSupported
        })?;

        Ok(can_do_crypto::Result)
    }

    fn use_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("use_check_internal");

        let _ = Provider::check_key_size(attributes, false).map_err(|_| {
            info!("Unsupported key size {}", attributes.bits);
            PsaErrorNotSupported
        })?;

        Ok(can_do_crypto::Result)
    }

    fn generate_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("generate_check_internal");

        let _ = Provider::check_key_size(attributes, false).map_err(|_| {
            info!("Unsupported key size {}", attributes.bits);
            PsaErrorNotSupported
        })?;

        match attributes.key_type {
            Type::RsaKeyPair
            | Type::EccKeyPair { .. }
            | Type::DhKeyPair { .. }
            | Type::RawData
            | Type::Aes
            | Type::Camellia
            | Type::Chacha20 => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn import_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("import_check_internal");

        let _ = Provider::check_key_size(attributes, true).map_err(|_| {
            info!("Unsupported key size {}", attributes.bits);
            PsaErrorNotSupported
        })?;

        // We can import public keys and all the types we can generate.
        match attributes.key_type {
            Type::RsaPublicKey | Type::EccPublicKey { .. } | Type::DhPublicKey { .. } => {
                Ok(can_do_crypto::Result)
            }
            Type::RsaKeyPair
            | Type::EccKeyPair { .. }
            | Type::DhKeyPair { .. }
            | Type::RawData
            | Type::Aes
            | Type::Camellia
            | Type::Chacha20 => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }
}
