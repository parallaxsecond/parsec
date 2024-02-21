// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core inter-op with underlying hardware
//!
//! [Providers](https://parallaxsecond.github.io/parsec-book/parsec_service/providers.html)
//! are the real implementors of the operations that Parsec claims to support. They map to
//! functionality in the underlying hardware which allows the PSA Crypto operations to be
//! backed by a hardware root of trust.
use log::trace;
use parsec_interface::requests::Opcode;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;

pub mod core;

pub mod crypto_capability;

#[cfg(feature = "pkcs11-provider")]
//TODO: To remove when #301 is merged
#[allow(clippy::all)]
pub mod pkcs11;

#[cfg(feature = "mbed-crypto-provider")]
pub mod mbed_crypto;

#[cfg(feature = "tpm-provider")]
pub mod tpm;

#[cfg(feature = "cryptoauthlib-provider")]
pub mod cryptoauthlib;

#[cfg(feature = "trusted-service-provider")]
pub mod trusted_service;

use crate::authenticators::ApplicationIdentity;
use parsec_interface::operations::{
    attest_key, can_do_crypto, delete_client, list_authenticators, list_clients, list_keys,
    list_opcodes, list_providers, ping, prepare_key_attestation, psa_aead_decrypt,
    psa_aead_encrypt, psa_asymmetric_decrypt, psa_asymmetric_encrypt, psa_cipher_decrypt,
    psa_cipher_encrypt, psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key,
    psa_generate_random, psa_hash_compare, psa_hash_compute, psa_import_key, psa_raw_key_agreement,
    psa_sign_hash, psa_sign_message, psa_verify_hash, psa_verify_message,
};
use parsec_interface::requests::{ResponseStatus, Result};

use parsec_interface::requests::ProviderId;

/// The ProviderIdentity struct specifies a unique uuid-name
/// combination to form a unique provider identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderIdentity {
    /// The uuid of the provider
    uuid: String,
    /// The name of the provider set in the config, defaults to a suitable name.
    name: String,
}

impl fmt::Display for ProviderIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProviderIdentity: [uuid=\"{}\", name=\"{}\"]",
            self.uuid, self.name
        )
    }
}

impl ProviderIdentity {
    /// Creates a new instance of ProviderIdentity.
    pub fn new(uuid: String, name: String) -> ProviderIdentity {
        ProviderIdentity { uuid, name }
    }

    /// Get the uuid of the provider
    pub fn uuid(&self) -> &String {
        &self.uuid
    }

    /// Get the name of the provider
    pub fn name(&self) -> &String {
        &self.name
    }
}

impl TryFrom<ProviderIdentity> for ProviderId {
    type Error = String;

    fn try_from(provider_identity: ProviderIdentity) -> std::result::Result<Self, Self::Error> {
        let provider_id = match provider_identity.uuid.as_str() {
            core::Provider::PROVIDER_UUID => Ok(ProviderId::Core),
            #[cfg(feature = "cryptoauthlib-provider")]
            crate::providers::cryptoauthlib::Provider::PROVIDER_UUID => Ok(ProviderId::CryptoAuthLib),
            #[cfg(feature = "mbed-crypto-provider")]
            mbed_crypto::Provider::PROVIDER_UUID => Ok(ProviderId::MbedCrypto),
            #[cfg(feature = "pkcs11-provider")]
            pkcs11::Provider::PROVIDER_UUID => Ok(ProviderId::Pkcs11),
            #[cfg(feature = "tpm-provider")]
            tpm::Provider::PROVIDER_UUID => Ok(ProviderId::Tpm),
            #[cfg(feature = "trusted-service-provider")]
            crate::providers::trusted_service::Provider::PROVIDER_UUID => Ok(ProviderId::TrustedService),
            _ => Err(format!("Cannot convert from ProviderIdentity to ProviderId.\nProvider \"{}\" is not recognised.\nCould be it does not exist, or Parsec was not compiled with the required provider feature flags.", provider_identity.uuid)),
        }?;

        Ok(provider_id)
    }
}

/// Provider interface for servicing client operations
///
/// Definition of the interface that a provider must implement to
/// be linked into the service through a backend handler.
///
/// The methods with no default are used on a service-level by the
/// core provider and so must be supported by all providers.
pub trait Provide {
    /// Return a description of the current provider.
    ///
    /// The descriptions are gathered in the Core Provider and returned for a ListProviders operation.
    fn describe(&self) -> Result<(list_providers::ProviderInfo, HashSet<Opcode>)>;

    /// List the providers running in the service.
    fn list_providers(&self, _op: list_providers::Operation) -> Result<list_providers::Result> {
        trace!("list_providers ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// List the opcodes supported by the given provider.
    fn list_opcodes(&self, _op: list_opcodes::Operation) -> Result<list_opcodes::Result> {
        trace!("list_opcodes ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// List the authenticators supported by the given provider.
    fn list_authenticators(
        &self,
        _op: list_authenticators::Operation,
    ) -> Result<list_authenticators::Result> {
        trace!("list_authenticators ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Lists all keys belonging to the application.
    fn list_keys(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result>;

    /// Lists all clients currently having data in the service.
    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result>;

    /// Delete all data a client has in the service..
    fn delete_client(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: delete_client::Operation,
    ) -> Result<delete_client::Result> {
        trace!("delete_client ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a Ping operation to get the wire protocol version major and minor information.
    ///
    /// # Errors
    ///
    /// This operation will only fail if not implemented. It will never fail when being called on
    /// the `CoreProvider`.
    fn ping(&self, _op: ping::Operation) -> Result<ping::Result> {
        trace!("ping ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a GenerateKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to create a key with the same name later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. generate unique key ID
    /// 2. try key creation with it. If successfull go to 3 else return an error.
    /// 3. store the mappings between key name and key ID. If successfull return success, else go to 4.
    /// 4. try to delete the key created. If failed, log it and return the error from 3.
    fn psa_generate_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ImportKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to import a key with the same name later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. generate unique key ID
    /// 2. try key import with it. If successfull go to 3 else return an error.
    /// 3. store the mappings between key name and key ID. If successfull return success, else go to 4.
    /// 4. try to delete the key imported. If failed, log it and return the error from 3.
    fn psa_import_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ExportPublicKey operation.
    fn psa_export_public_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an ExportKey operation.
    fn psa_export_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        trace!("psa_export_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a DestroyKey operation.
    ///
    /// Providers should try, in a best-effort way, to handle failures in a way that it is possible
    /// to generate or create a key with the same name than the one destroyed later on.
    ///
    /// For providers using a Key Info Manager to map a key name with a provider-specific key
    /// identification, the following algorithm can be followed:
    /// 1. get the key ID from the key name using the KIM
    /// 2. destroy the key mappings
    /// 3. try to destroy the key
    fn psa_destroy_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a SignHash operation. This operation only signs the short digest given but does not
    /// hash it.
    fn psa_sign_hash(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a VerifyHash operation.
    fn psa_verify_hash(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        trace!("psa_verify_hash ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AsymmetricEncrypt operation.
    fn psa_asymmetric_encrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        trace!("psa_asymmetric_encrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AsymmetricDecrypt operation.
    fn psa_asymmetric_decrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AeadEncrypt operation.
    fn psa_aead_encrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_aead_encrypt::Operation,
    ) -> Result<psa_aead_encrypt::Result> {
        trace!("psa_aead_encrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute an AeadDecrypt operation.
    fn psa_aead_decrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_aead_decrypt::Operation,
    ) -> Result<psa_aead_decrypt::Result> {
        trace!("psa_aead_decrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a HashCompute operation.
    fn psa_hash_compute(
        &self,
        _op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        trace!("psa_hash_compute ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a HashCompare operation.
    fn psa_hash_compare(
        &self,
        _op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        trace!("psa_hash_compare ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a RawKeyAgreement operation.
    fn psa_raw_key_agreement(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_raw_key_agreement::Operation,
    ) -> Result<psa_raw_key_agreement::Result> {
        trace!("psa_raw_key_agreement ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Execute a GenerateRandom operation.
    fn psa_generate_random(
        &self,
        _op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        trace!("psa_generate_random ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Encrypt a short message with a symmetric cipher.
    fn psa_cipher_encrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_cipher_encrypt::Operation,
    ) -> Result<psa_cipher_encrypt::Result> {
        trace!("psa_cipher_encrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Decrypt a short message with a symmetric cipher.
    fn psa_cipher_decrypt(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_cipher_decrypt::Operation,
    ) -> Result<psa_cipher_decrypt::Result> {
        trace!("psa_cipher_decrypt ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Sign a message with a private key.
    fn psa_sign_message(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_sign_message::Operation,
    ) -> Result<psa_sign_message::Result> {
        trace!("psa_sign_message ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Verify the signature of a message using a public key.
    fn psa_verify_message(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: psa_verify_message::Operation,
    ) -> Result<psa_verify_message::Result> {
        trace!("psa_verify_message ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    ///Check if the crypto operation is supported by provider.
    fn can_do_crypto(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: can_do_crypto::Operation,
    ) -> Result<can_do_crypto::Result> {
        trace!("can_do_crypto main ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Prepare a key attestation operation.
    fn prepare_key_attestation(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: prepare_key_attestation::Operation,
    ) -> Result<prepare_key_attestation::Result> {
        trace!("prepare_key_attestation ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }

    /// Attest a key.
    fn attest_key(
        &self,
        _application_identity: &ApplicationIdentity,
        _op: attest_key::Operation,
    ) -> Result<attest_key::Result> {
        trace!("attest_key ingress");
        Err(ResponseStatus::PsaErrorNotSupported)
    }
}
