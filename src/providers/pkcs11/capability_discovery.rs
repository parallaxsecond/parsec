#![allow(unused, trivial_numeric_casts)]
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::providers::pkcs11::to_response_status;
use cryptoki::types::mechanism::Mechanism;
use cryptoki::types::mechanism::MechanismInfo;
use cryptoki::types::mechanism::MechanismType;
use cryptoki::types::Ulong;
use log::trace;
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::can_do_crypto::CheckType;
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::operations::psa_key_attributes::EccFamily;
use parsec_interface::operations::psa_key_attributes::Type;
use parsec_interface::requests::ResponseStatus::{InvalidEncoding, PsaErrorNotSupported};
use parsec_interface::requests::Result;
use std::convert::TryFrom;
use std::ops::Deref;

impl Provider {
    pub(super) fn can_do_crypto_internal(
        &self,
        _app_name: ApplicationName,
        op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        let attributes = op.attributes;
        let check_type = op.check_type;
        let supported_ecc_family_sizes = [192, 224, 256, 384, 512];
        match attributes.key_type {
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            }
            | Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => {
                if !(supported_ecc_family_sizes.contains(&attributes.bits)) {
                    return Err(PsaErrorNotSupported);
                }
            }
            Type::RsaKeyPair | Type::RsaPublicKey => (),
            _ => return Err(PsaErrorNotSupported),
        }
        match check_type {
            CheckType::Generate => return self.generate_check(attributes),
            CheckType::Import => return self.import_check(attributes),
            CheckType::Use => return self.use_check(attributes),
            CheckType::Derive => return Provider::derive_check(attributes),
        };
    }

    fn use_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        if attributes.policy.permitted_algorithms == Algorithm::None {
            return Err(PsaErrorNotSupported);
        }
        if !(attributes.policy.usage_flags.decrypt()
            || attributes.policy.usage_flags.encrypt()
            || attributes.policy.usage_flags.sign_hash()
            || attributes.policy.usage_flags.sign_message()
            || attributes.policy.usage_flags.verify_hash()
            || attributes.policy.usage_flags.verify_message())
        {
            return Err(PsaErrorNotSupported);
        }
        attributes.compatible_with_alg(attributes.policy.permitted_algorithms)?;

        let supported_mechanisms: Vec<MechanismType> = self
            .backend
            .get_mechanism_list(self.slot_number)
            .map_err(to_response_status)?;
        let mechanism = Mechanism::try_from(attributes.policy.permitted_algorithms)
            .map_err(to_response_status)?;
        if !(supported_mechanisms.contains(&mechanism.mechanism_type())) {
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
                return Err(PsaErrorNotSupported);
            }
        } else {
            if !((attributes.bits as u64) >= (*mechanism_info.min_key_size() as u64)
                && (attributes.bits as u64) <= (*mechanism_info.max_key_size() as u64))
            {
                return Err(PsaErrorNotSupported);
            }
        }
        return Ok(can_do_crypto::Result {});
    }

    fn derive_check(attributes: Attributes) -> Result<can_do_crypto::Result> {
        return Err(PsaErrorNotSupported);
    }

    fn generate_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        match attributes.key_type {
            Type::RsaKeyPair => (),
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => (),
            _ => return Err(PsaErrorNotSupported),
        }
        if attributes.policy.permitted_algorithms != Algorithm::None {
            return self.use_check(attributes);
        }
        return Ok(can_do_crypto::Result);
    }

    fn import_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        match attributes.key_type {
            Type::RsaPublicKey => (),
            Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => (),
            _ => return Err(PsaErrorNotSupported),
        }
        if attributes.policy.permitted_algorithms != Algorithm::None {
            return self.use_check(attributes);
        }
        return Ok(can_do_crypto::Result);
    }
}
