// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![allow(trivial_numeric_casts)]
use super::utils::algorithm_to_mechanism;
use super::{utils, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::providers::crypto_capability::CanDoCrypto;
use crate::providers::pkcs11::to_response_status;
use cryptoki::mechanism::{MechanismInfo, MechanismType};
use cryptoki::types::Ulong;
use log::{info, trace};
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::psa_algorithm::*;
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
                // Check for supported Hash for RSA PKCS#1 v1.5 signature algorithm.
                match op.attributes.policy.permitted_algorithms {
                    Algorithm::AsymmetricSignature(
                        alg @ AsymmetricSignature::RsaPkcs1v15Sign { .. },
                    ) => {
                        let _ = utils::digest_info(alg, vec![0, 1]).map_err(|_| {
                            info!("Unsupported Hash in signature algorithm {:?}", alg);
                            PsaErrorNotSupported
                        })?;
                    }
                    _ => (),
                }
                Ok(can_do_crypto::Result {})
            }
            Type::EccKeyPair { curve_family } | Type::EccPublicKey { curve_family } => {
                let _ = utils::ec_params(curve_family, op.attributes.bits).map_err(|_| {
                    info!(
                        "Unsupported EC curve family {} or key size {}",
                        curve_family, op.attributes.bits
                    );
                    PsaErrorNotSupported
                })?;
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

        let supported_mechanisms: Vec<MechanismType> = self
            .backend
            .get_mechanism_list(self.slot_number)
            .map_err(to_response_status)?;
        let mechanism = algorithm_to_mechanism(attributes.policy.permitted_algorithms)
            .map_err(to_response_status)?;
        if !(supported_mechanisms.contains(&mechanism.mechanism_type())) {
            info!("Mechanism {:?} is not supported", mechanism);
            return Err(PsaErrorNotSupported);
        }

        let mechanism_info: MechanismInfo = self
            .backend
            .get_mechanism_info(self.slot_number, mechanism.mechanism_type())
            .map_err(to_response_status)?;
        if std::any::type_name::<Ulong>() == std::any::type_name::<u64>() {
            if !(attributes.bits >= mechanism_info.min_key_size()
                && attributes.bits <= mechanism_info.max_key_size())
            {
                info!(
                    "Incorrect key size {} for mechanism {:?}",
                    attributes.bits, mechanism
                );
                return Err(PsaErrorNotSupported);
            }
        } else {
            if !(attributes.bits >= mechanism_info.min_key_size()
                && attributes.bits <= mechanism_info.max_key_size())
            {
                info!(
                    "Incorrect key size {} for mechanism {:?}",
                    attributes.bits, mechanism
                );
                return Err(PsaErrorNotSupported);
            }
        }
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
