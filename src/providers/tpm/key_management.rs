// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils;
#[allow(deprecated)]
use super::utils::LegacyPasswordContext;
use super::utils::PasswordContext;
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use log::error;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::utils_deprecated_primitives::CheckDeprecated;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use std::convert::TryInto;

const AUTH_VAL_LEN: usize = 32;

impl Provider {
    #[allow(deprecated)]
    pub(super) fn get_key_ctx(&self, key_identity: &KeyIdentity) -> Result<PasswordContext> {
        // Try to deserialize into the new format
        self.key_info_store
            .get_key_id::<PasswordContext>(key_identity)
            .or_else(|e| {
                // If it failed, check if it was a deserialization error
                if let ResponseStatus::InvalidEncoding = e {
                    // Try to deserialize into legacy format
                    let legacy_ctx = self
                        .key_info_store
                        .get_key_id::<LegacyPasswordContext>(key_identity)?;

                    // Try to migrate the key context to the new format
                    let mut esapi_context = self
                        .esapi_context
                        .lock()
                        .expect("ESAPI Context lock poisoned");
                    let password_ctx = PasswordContext::new(
                        esapi_context
                            .migrate_key_from_ctx(
                                legacy_ctx.context,
                                Some(
                                    legacy_ctx
                                        .auth_value
                                        .clone()
                                        .try_into()
                                        .map_err(utils::to_response_status)?,
                                ),
                            )
                            .map_err(utils::to_response_status)?,
                        legacy_ctx.auth_value,
                    );

                    // Grab key attributes and replace legacy entry with new one
                    let attributes = self.key_info_store.get_key_attributes(key_identity)?;
                    self.key_info_store.replace_key_info(
                        key_identity.clone(),
                        &password_ctx,
                        attributes,
                    )?;
                    Ok(password_ctx)
                } else {
                    Err(e)
                }
            })
    }

    pub(super) fn psa_generate_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        return_on_deprecated!(op, "The key requested to generate is deprecated");

        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );

        self.key_info_store.does_not_exist(&key_identity)?;

        if op.attributes.key_type.is_public_key() {
            error!("A public key type can not be generated.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let (key_material, auth_value) = esapi_context
            .create_key(utils::parsec_to_tpm_params(attributes)?, AUTH_VAL_LEN)
            .map_err(|e| {
                format_error!("Error creating a RSA signing key", e);
                utils::to_response_status(e)
            })?;
        // We hardcode the AUTH_VAL_LEN, so we can assume there is an auth_value
        let auth_value = auth_value.unwrap();

        self.key_info_store.insert_key_info(
            key_identity,
            &PasswordContext::new(key_material, auth_value.to_vec()),
            attributes,
        )?;

        Ok(psa_generate_key::Result {})
    }

    pub(super) fn psa_import_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        warn_on_deprecated!(op, "The key requested to import is deprecated");

        match op.attributes.key_type {
            Type::RsaPublicKey | Type::EccPublicKey { .. } => (),
            _ => {
                error!(
                    "The TPM provider does not support importing for the {:?} key type.",
                    op.attributes.key_type
                );
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }

        let key_name = op.key_name;
        let attributes = op.attributes;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        let key_data = op.data;
        self.key_info_store.does_not_exist(&key_identity)?;
        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let attributes = utils::adjust_attributes_key_bits(attributes, key_data.expose_secret())?;
        let key_params = utils::parsec_to_tpm_params(attributes)?;
        let pub_key = utils::bytes_to_pub_key(key_data.expose_secret().to_vec(), &attributes)?;
        let key_material = esapi_context
            .load_external_public_key(pub_key, key_params)
            .map_err(|e| {
                format_error!("Error creating a RSA signing key", e);
                utils::to_response_status(e)
            })?;

        self.key_info_store.insert_key_info(
            key_identity,
            &PasswordContext::new(key_material, Vec::new()),
            attributes,
        )?;

        Ok(psa_import_key::Result {})
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );

        let password_context = self.get_key_ctx(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        Ok(psa_export_public_key::Result {
            data: utils::pub_key_to_bytes(
                password_context.key_material().public().clone(),
                key_attributes,
            )?
            .into(),
        })
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );

        self.key_info_store.remove_key_info(&key_identity)?;

        Ok(psa_destroy_key::Result {})
    }
}
