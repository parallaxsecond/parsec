// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils;
use super::utils::PasswordContext;
use super::utils::{validate_private_key, validate_public_key, PUBLIC_EXPONENT};
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers;
use crate::key_info_managers::KeyTriple;
use crate::key_info_managers::{KeyInfo, ManageKeyInfo};
use log::error;
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash, SignHash};
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use picky_asn1_x509::{RSAPrivateKey, RSAPublicKey};
use tss_esapi::abstraction::transient::RsaExponent;
use zeroize::Zeroize;

const AUTH_VAL_LEN: usize = 32;

// Inserts a new mapping in the Key Info manager that stores the PasswordContext.
fn insert_password_context(
    store_handle: &mut dyn ManageKeyInfo,
    key_triple: KeyTriple,
    mut password_context: PasswordContext,
    key_attributes: Attributes,
) -> Result<()> {
    let error_storing = |e| Err(key_info_managers::to_response_status(e));

    let key_info = KeyInfo {
        id: bincode::serialize(&password_context)?,
        attributes: key_attributes,
    };

    password_context.auth_value.zeroize();

    if store_handle
        .insert(key_triple, key_info)
        .or_else(error_storing)?
        .is_some()
    {
        error!("Inserting a mapping in the Key Info Manager that would overwrite an existing one.");
        Err(ResponseStatus::PsaErrorAlreadyExists)
    } else {
        Ok(())
    }
}

// Gets a PasswordContext mapping to the KeyTriple given.
pub fn get_password_context(
    store_handle: &dyn ManageKeyInfo,
    key_triple: KeyTriple,
) -> Result<(PasswordContext, Attributes)> {
    let key_info = store_handle
        .get(&key_triple)
        .map_err(key_info_managers::to_response_status)?
        .ok_or_else(|| {
            if crate::utils::GlobalConfig::log_error_details() {
                error!(
                    "Key triple \"{}\" does not exist in the Key Info Manager.",
                    key_triple
                );
            } else {
                error!("Key triple does not exist in the Key Info Manager.");
            }
            ResponseStatus::PsaErrorDoesNotExist
        })?;
    Ok((bincode::deserialize(&key_info.id)?, key_info.attributes))
}

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);

        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");

        store_handle.does_not_exist(&key_triple)?;

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (key_context, auth_value) = esapi_context
            .create_key(utils::parsec_to_tpm_params(attributes)?, AUTH_VAL_LEN)
            .map_err(|e| {
                format_error!("Error creating a RSA signing key", e);
                utils::to_response_status(e)
            })?;
        // We hardcode the AUTH_VAL_LEN, so we can assume there is an auth_value
        let auth_value = auth_value.unwrap();

        insert_password_context(
            &mut *store_handle,
            key_triple,
            PasswordContext {
                context: key_context,
                auth_value: auth_value.value().to_vec(),
            },
            attributes,
        )?;

        Ok(psa_generate_key::Result {})
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        match op.attributes.key_type {
            Type::RsaPublicKey => self.psa_import_key_internal_rsa_public(app_name, op),
            Type::RsaKeyPair => self.psa_import_key_internal_rsa_keypair(app_name, op),
            _ => {
                error!(
                    "The TPM provider does not support importing for the {:?} key type.",
                    op.attributes.key_type
                );
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }

    pub(super) fn psa_import_key_internal_rsa_public(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        // Currently only the RSA PKCS1 v1.5 signature scheme is supported
        // by the tss-esapi crate.
        if op.attributes.policy.permitted_algorithms
            != Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: SignHash::Specific(Hash::Sha256),
            })
        {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        let key_data = op.data;

        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        store_handle.does_not_exist(&key_triple)?;
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let public_key: RSAPublicKey = picky_asn1_der::from_bytes(key_data.expose_secret())
            .map_err(|err| {
                format_error!("Could not deserialise key elements", err);
                ResponseStatus::PsaErrorInvalidArgument
            })?;

        validate_public_key(&public_key, &attributes)?;

        let key_data = public_key.modulus.as_unsigned_bytes_be();
        let pub_key_context = esapi_context
            .load_external_rsa_public_key(&key_data)
            .map_err(|e| {
                format_error!("Error creating a RSA signing key", e);
                utils::to_response_status(e)
            })?;

        insert_password_context(
            &mut *store_handle,
            key_triple,
            PasswordContext {
                context: pub_key_context,
                auth_value: Vec::new(),
            },
            attributes,
        )?;

        Ok(psa_import_key::Result {})
    }

    pub(super) fn psa_import_key_internal_rsa_keypair(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        // Currently only the RSA PKCS1 v1.5 signature scheme is supported
        // by the tss-esapi crate.
        if op.attributes.policy.permitted_algorithms
            != Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: SignHash::Specific(Hash::Sha256),
            })
        {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        let key_data = op.data;

        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        store_handle.does_not_exist(&key_triple)?;
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let private_key: RSAPrivateKey = picky_asn1_der::from_bytes(key_data.expose_secret())
            .map_err(|err| {
                format_error!("Could not deserialise key elements", err);
                ResponseStatus::PsaErrorInvalidArgument
            })?;

        // Derive the public key from the keypair.
        let public_key = RSAPublicKey {
            modulus: private_key.modulus.clone(),
            public_exponent: private_key.public_exponent.clone(),
        };

        // Validate the public and the private key.
        validate_public_key(&public_key, &attributes)?;
        validate_private_key(&private_key, &attributes)?;

        let key_prime = private_key.prime_1.as_unsigned_bytes_be();
        let public_modulus = private_key.modulus.as_unsigned_bytes_be();

        let keypair_context = esapi_context
            .load_external_rsa(key_prime, public_modulus, RsaExponent::new(PUBLIC_EXPONENT))
            .map_err(|e| {
                format_error!("Error creating a RSA signing key", e);
                utils::to_response_status(e)
            })?;

        insert_password_context(
            &mut *store_handle,
            key_triple,
            PasswordContext {
                context: keypair_context,
                auth_value: Vec::new(),
            },
            attributes,
        )?;

        Ok(psa_import_key::Result {})
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);

        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (password_context, key_attributes) = get_password_context(&*store_handle, key_triple)?;

        let pub_key_data = esapi_context
            .read_public_key(password_context.context)
            .map_err(|e| {
                format_error!("Error reading a public key", e);
                utils::to_response_status(e)
            })?;

        Ok(psa_export_public_key::Result {
            data: utils::pub_key_to_bytes(pub_key_data, key_attributes)?.into(),
        })
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Tpm, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");

        if store_handle
            .remove(&key_triple)
            .map_err(key_info_managers::to_response_status)?
            .is_none()
        {
            if crate::utils::GlobalConfig::log_error_details() {
                error!(
                    "Key triple \"{}\" does not exist in the Key Info Manager.",
                    key_triple
                );
            } else {
                error!("Key triple does not exist in the Key Info Manager.");
            }
            Err(ResponseStatus::PsaErrorDoesNotExist)
        } else {
            Ok(psa_destroy_key::Result {})
        }
    }
}
