// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Pkcs11Provider;
use super::{key_management::get_key_info, utils, KeyPairType, ReadWriteSession, Session};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{error, info};
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use pkcs11::types::CK_MECHANISM;

impl Pkcs11Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        info!("Pkcs11 Provider - Asym Sign");

        let key_name = op.key_name;
        let mut hash = op.hash;
        let alg = op.alg;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let (key_id, key_attributes) = get_key_info(&key_triple, &*store_handle)?;

        key_attributes.can_sign_hash()?;
        key_attributes.permits_alg(alg.into())?;
        key_attributes.compatible_with_alg(alg.into())?;

        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            } => (),
            _ => {
                error!(
                    "The PKCS 11 provider currently only supports \"RSA PKCS#1 v1.5 signature with hashing\" algorithm with SHA-256 as hashing algorithm for the PsaSignHash operation.");
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        if alg
            != (AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            })
        {
            error!(
                "The PKCS 11 provider currently only supports signature algorithm to be RSA PKCS#1 v1.5 and the text hashed with SHA-256.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        if hash.len() != 32 {
            error!("The SHA-256 hash must be 32 bytes long.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let mech = CK_MECHANISM {
            mechanism: pkcs11::types::CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        info!("Asymmetric sign in session {}", session.session_handle());

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PrivateKey)?;
        info!("Located signing key.");

        match self.backend.sign_init(session.session_handle(), &mech, key) {
            Ok(_) => {
                info!("Signing operation initialized.");

                // Build a valid ASN.1 DigestInfo DER-encoded structure by appending the hash to a
                // DigestAlgorithmIdentifier value representing the SHA256 OID with no parameters.
                // The OID used is: "2.16.840.1.101.3.4.2.1".
                // It would be better to use the DigestInfo structure defined in this file but the
                // AlgorithmIdentifier structure does not currently support the simple SHA256 OID.
                // See Devolutions/picky-rs#19
                let mut digest_info = vec![
                    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ];
                digest_info.append(&mut hash);

                match self.backend.sign(session.session_handle(), &digest_info) {
                    Ok(signature) => Ok(psa_sign_hash::Result { signature }),
                    Err(e) => {
                        error!("Failed to execute signing operation. Error: {}", e);
                        Err(utils::to_response_status(e))
                    }
                }
            }
            Err(e) => {
                error!("Failed to initialize signing operation. Error: {}", e);
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        info!("Pkcs11 Provider - Asym Verify");

        let key_name = op.key_name;
        let mut hash = op.hash;
        let signature = op.signature;
        let alg = op.alg;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let (key_id, key_attributes) = get_key_info(&key_triple, &*store_handle)?;

        key_attributes.can_verify_hash()?;
        key_attributes.permits_alg(alg.into())?;
        key_attributes.compatible_with_alg(alg.into())?;

        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            } => (),
            _ => {
                error!(
                    "The PKCS 11 provider currently only supports \"RSA PKCS#1 v1.5 signature with hashing\" algorithm with SHA-256 as hashing algorithm for the PsaVerifyHash operation.");
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        if alg
            != (AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            })
        {
            error!(
                "The PKCS 11 provider currently only supports signature algorithm to be RSA PKCS#1 v1.5 and the text hashed with SHA-256.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        if hash.len() != 32 {
            error!("The SHA-256 hash must be 32 bytes long.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let mech = CK_MECHANISM {
            // Verify without hashing.
            mechanism: pkcs11::types::CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        info!("Asymmetric verify in session {}", session.session_handle());

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PublicKey)?;
        info!("Located public key.");

        match self
            .backend
            .verify_init(session.session_handle(), &mech, key)
        {
            Ok(_) => {
                info!("Verify operation initialized.");

                // Build a valid ASN.1 DigestInfo DER-encoded structure by appending the hash to a
                // DigestAlgorithmIdentifier value representing the SHA256 OID with no parameters.
                // The OID used is: "2.16.840.1.101.3.4.2.1".
                // It would be better to use the DigestInfo structure defined in this file but the
                // AlgorithmIdentifier structure does not currently support the simple SHA256 OID.
                // See Devolutions/picky-rs#19
                let mut digest_info = vec![
                    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ];
                digest_info.append(&mut hash);

                match self
                    .backend
                    .verify(session.session_handle(), &digest_info, &signature)
                {
                    Ok(_) => Ok(psa_verify_hash::Result {}),
                    Err(e) => Err(utils::to_response_status(e)),
                }
            }
            Err(e) => {
                error!("Failed to initialize verifying operation. Error: {}", e);
                Err(utils::to_response_status(e))
            }
        }
    }
}
