// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Crypto capabilities trait for Parsec providers
//!
//! The trait provides generic crypto compatibility checking methods
//! https://parallaxsecond.github.io/parsec-book/parsec_client/operations/can_do_crypto.html
//! https://parallaxsecond.github.io/parsec-book/parsec_client/operations/service_api_coverage.html

use crate::authenticators::ApplicationIdentity;
use log::{info, trace};
use parsec_interface::operations::can_do_crypto;
use parsec_interface::operations::can_do_crypto::{CheckType, Operation};
use parsec_interface::operations::psa_algorithm::Algorithm;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::ResponseStatus::PsaErrorNotSupported;
use parsec_interface::requests::Result;

/// Provider interface for checking crypto capabilities
///
/// Definition of the interface that a provider must expand to
/// be correctly checked for crypto compatibility.
pub trait CanDoCrypto {
    /// Check if the crypto operation is supported by provider.
    /// This method is called by Provide trait and doesn't need to be changed.
    fn can_do_crypto_main(
        &self,
        application_identity: &ApplicationIdentity,
        op: Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto_main in CanDoCrypto trait");
        let _ = self.can_do_crypto_internal(application_identity, op)?;

        match op.check_type {
            CheckType::Generate => self.generate_check(op.attributes),
            CheckType::Import => self.import_check(op.attributes),
            CheckType::Use => self.use_check(op.attributes),
            CheckType::Derive => self.derive_check(op.attributes),
        }
    }

    /// Common checks if an existing key of the key type that defined in the attributes
    /// and the same length can be used to perform the algorithm in policy.key_algorithm
    fn use_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("Use check in CanDoCrypto trait");
        if attributes.policy.permitted_algorithms == Algorithm::None {
            info!("No algorithm defined for the operation");
            return Err(PsaErrorNotSupported);
        }
        if !(attributes.policy.usage_flags.decrypt()
            || attributes.policy.usage_flags.encrypt()
            || attributes.policy.usage_flags.sign_hash()
            || attributes.policy.usage_flags.sign_message()
            || attributes.policy.usage_flags.verify_hash()
            || attributes.policy.usage_flags.verify_message())
        {
            info!("No usage flags defined for the operation");
            return Err(PsaErrorNotSupported);
        }
        attributes
            .compatible_with_alg(attributes.policy.permitted_algorithms)
            .map_err(|_| PsaErrorNotSupported)?;

        self.use_check_internal(attributes)
    }

    /// Common checks if a key with the attributes can be generated
    fn generate_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("Generate check in CanDoCrypto trait");
        let _ = self.generate_check_internal(attributes)?;

        if attributes.policy.permitted_algorithms != Algorithm::None {
            return self.use_check(attributes);
        }
        Ok(can_do_crypto::Result)
    }

    /// Common checks if a key with the attributes can be imported.
    fn import_check(&self, attributes: Attributes) -> Result<can_do_crypto::Result> {
        trace!("Import check in CanDoCrypto trait");
        let _ = self.import_check_internal(attributes)?;

        if attributes.policy.permitted_algorithms != Algorithm::None {
            return self.use_check(attributes);
        }
        Ok(can_do_crypto::Result)
    }

    /// Checks if a key with the attributes can be derived.
    fn derive_check(&self, _attributes: Attributes) -> Result<can_do_crypto::Result> {
        info!("Derive check type is not supported");
        Err(PsaErrorNotSupported)
    }

    /// Provider specific heck if the crypto operation is supported by provider.
    /// This method should be re-implemented by providers.
    fn can_do_crypto_internal(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: Operation,
    ) -> Result<can_do_crypto::Result>;

    /// Provider specific Use check.
    /// This method should be re-implemented by providers.
    fn use_check_internal(&self, _attributes: Attributes) -> Result<can_do_crypto::Result>;

    /// Provider specific Generate check.
    /// This method should be re-implemented by providers.
    fn generate_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result>;

    /// Provider specific Import check.
    /// This method should be re-implemented by providers.
    fn import_check_internal(&self, attributes: Attributes) -> Result<can_do_crypto::Result>;
}
