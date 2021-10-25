#![allow(trivial_numeric_casts)]
use super::{utils, Provider};
use crate::authenticators::ApplicationName;
use crate::providers::crypto_capability::CanDoCrypto;
use crate::providers::pkcs11::to_response_status;
use cryptoki::types::mechanism::{Mechanism, MechanismInfo, MechanismType};
use cryptoki::types::Ulong;
use log::{info, trace};
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::psa_key_attributes::{Attributes, Type};
use parsec_interface::requests::ResponseStatus::PsaErrorNotSupported;
use parsec_interface::requests::Result;
use std::convert::TryFrom;

impl CanDoCrypto for Provider {
    fn can_do_crypto_internal(
        &self,
        _app_name: ApplicationName,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto_internal for PKCS11 provider");
        let attributes = op.attributes;
        match attributes.key_type {
            Type::RsaKeyPair | Type::RsaPublicKey => Ok(can_do_crypto::Result {}),
            Type::EccKeyPair { curve_family } | Type::EccPublicKey { curve_family } => {
                let _ = utils::ec_params(curve_family, attributes.bits).map_err(|_| {
                    info!(
                        "Unsupported EC curve family {} or key size {}",
                        curve_family, attributes.bits
                    );
                    PsaErrorNotSupported
                })?;
                Ok(can_do_crypto::Result)
            }
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn use_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("use_check_internal for PKCS11 provider");

        let supported_mechanisms: Vec<MechanismType> = self
            .backend
            .get_mechanism_list(self.slot_number)
            .map_err(to_response_status)?;
        let mechanism = Mechanism::try_from(attributes.policy.permitted_algorithms)
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
            if !((attributes.bits as u64) >= (*mechanism_info.min_key_size()).into()
                && (attributes.bits as u64) <= (*mechanism_info.max_key_size()).into())
            {
                info!(
                    "Incorrect key size {} for mechanism {:?}",
                    attributes.bits, mechanism
                );
                return Err(PsaErrorNotSupported);
            }
        } else {
            if !((attributes.bits as u64) >= (*mechanism_info.min_key_size() as u64)
                && (attributes.bits as u64) <= (*mechanism_info.max_key_size() as u64))
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
        trace!("generate_check_internal for PKCS11 provider");
        match attributes.key_type {
            Type::RsaKeyPair | Type::EccKeyPair { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }

    fn import_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("import_check_internal for PKCS11 provider");
        match attributes.key_type {
            Type::RsaPublicKey | Type::EccPublicKey { .. } => Ok(can_do_crypto::Result),
            _ => {
                info!("Unsupported key type {:?}", attributes.key_type);
                Err(PsaErrorNotSupported)
            }
        }
    }
}
