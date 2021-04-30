// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::to_response_status;
use super::{utils, KeyPairType, Provider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use cryptoki::types::mechanism::{Mechanism, MechanismType};
use cryptoki::types::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::types::session::Session;
use log::{error, info, trace};
use parsec_interface::operations::psa_key_attributes::{Id, Lifetime, Type};
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::RSAPublicKey;
use std::convert::{TryFrom, TryInto};

impl Provider {
    /// Find the PKCS 11 object handle corresponding to the key ID and the key type (public,
    /// private or any key type) given as parameters for the current session.
    pub(super) fn find_key(
        &self,
        session: &Session,
        key_id: u32,
        key_type: KeyPairType,
    ) -> Result<ObjectHandle> {
        let mut template = vec![Attribute::Id(key_id.to_be_bytes().to_vec())];

        match key_type {
            KeyPairType::PublicKey => template.push(Attribute::Class(ObjectClass::PUBLIC_KEY)),
            KeyPairType::PrivateKey => template.push(Attribute::Class(ObjectClass::PRIVATE_KEY)),
            KeyPairType::Any => (),
        }

        trace!("FindObjects commands");
        let objects = session
            .find_objects(&template)
            .map_err(to_response_status)?;

        if objects.is_empty() {
            Err(ResponseStatus::PsaErrorDoesNotExist)
        } else {
            Ok(objects[0])
        }
    }

    pub(super) fn move_pub_key_to_psa_crypto(&self, key_triple: &KeyTriple) -> Result<Id> {
        info!("Attempting to export public key");
        let export_operation = psa_export_public_key::Operation {
            key_name: key_triple.key_name().to_owned(),
        };
        let psa_export_public_key::Result { data } =
            self.psa_export_public_key_internal(key_triple.app_name().clone(), export_operation)?;

        info!("Importing public key into PSA Crypto");
        let mut attributes = self.key_info_store.get_key_attributes(&key_triple)?;
        attributes.lifetime = Lifetime::Volatile;
        attributes.key_type = match attributes.key_type {
            Type::RsaKeyPair | Type::RsaPublicKey => Type::RsaPublicKey,
            Type::EccKeyPair { curve_family } | Type::EccPublicKey { curve_family } => {
                Type::EccPublicKey { curve_family }
            }
            Type::DhKeyPair { group_family } | Type::DhPublicKey { group_family } => {
                Type::DhPublicKey { group_family }
            }
            _ => return Err(ResponseStatus::PsaErrorInvalidArgument),
        };
        let id = psa_crypto::operations::key_management::import(attributes, None, &data)?;

        Ok(id)
    }

    pub(super) fn remove_psa_crypto_pub_key(&self, pub_key_id: Id) -> Result<()> {
        info!("Removing public key stored in PSA.");
        unsafe { psa_crypto::operations::key_management::destroy(pub_key_id) }.map_err(|e| {
            error!("Failed to remove public key from PSA Crypto.");
            e
        })?;
        Ok(())
    }

    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        if op.attributes.key_type != Type::RsaKeyPair {
            error!("The PKCS11 provider currently only supports creating RSA key pairs.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let key_attributes = op.attributes;

        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        self.key_info_store.does_not_exist(&key_triple)?;

        let session = self.new_session()?;

        let key_id = self.create_key_id();

        let mut pub_template = vec![
            Attribute::Id(key_id.to_be_bytes().to_vec()),
            Attribute::Token(true.into()),
            Attribute::AllowedMechanisms(vec![Mechanism::try_from(
                key_attributes.policy.permitted_algorithms,
            )
            .map_err(to_response_status)?
            .mechanism_type()]),
        ];
        let mut priv_template = pub_template.clone();

        utils::key_pair_usage_flags_to_pkcs11_attributes(
            key_attributes.policy.usage_flags,
            &mut pub_template,
            &mut priv_template,
        );

        let mech = match key_attributes.key_type {
            Type::RsaKeyPair => {
                pub_template.push(Attribute::Private(false.into()));
                pub_template.push(Attribute::PublicExponent(utils::PUBLIC_EXPONENT.to_vec()));
                pub_template.push(Attribute::ModulusBits(
                    key_attributes.bits.try_into().map_err(to_response_status)?,
                ));
                Ok(Mechanism::RsaPkcsKeyPairGen)
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }?;

        match session.generate_key_pair(&mech, &pub_template, &priv_template) {
            Ok((public, private)) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_triple, &key_id, key_attributes)
                {
                    format_error!("Failed to insert the mappings, deleting the key.", e);
                    if let Err(e) = session.destroy_object(public) {
                        format_error!("Failed to destroy public part of the key: ", e);
                    }
                    if let Err(e) = session.destroy_object(private) {
                        format_error!("Failed to destroy private part of the key: ", e);
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(error) => {
                format_error!("Generate key status: ", error);
                Err(to_response_status(error))
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        match op.attributes.key_type {
            Type::RsaPublicKey => self.psa_import_key_internal_rsa_public(app_name, op),
            _ => {
                error!(
                    "The pkcs11 provider does not support the {:?} key type.",
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
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);

        self.key_info_store.does_not_exist(&key_triple)?;

        let session = self.new_session()?;

        let key_id = self.create_key_id();

        let mut template: Vec<Attribute> = Vec::new();

        let public_key: RSAPublicKey = picky_asn1_der::from_bytes(op.data.expose_secret())
            .map_err(|e| {
                format_error!("Failed to parse RsaPublicKey data", e);
                ResponseStatus::PsaErrorInvalidArgument
            })?;

        if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
            error!("Only positive modulus and public exponent are supported.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let modulus_object = public_key.modulus.as_unsigned_bytes_be();
        let exponent_object = public_key.public_exponent.as_unsigned_bytes_be();
        let bits = key_attributes.bits;
        if bits != 0 && modulus_object.len() * 8 != bits {
            if crate::utils::GlobalConfig::log_error_details() {
                error!(
                    "`bits` field of key attributes (value: {}) must be either 0 or equal to the size of the key in `data` (value: {}).",
                    key_attributes.bits,
                    modulus_object.len() * 8
                );
            } else {
                error!("`bits` field of key attributes must be either 0 or equal to the size of the key in `data`.");
            }

            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        template.push(Attribute::KeyType(KeyType::RSA));
        template.push(Attribute::Token(true.into()));
        template.push(Attribute::Modulus(modulus_object.into()));
        template.push(Attribute::PublicExponent(exponent_object.into()));
        template.push(Attribute::Verify(true.into()));
        template.push(Attribute::Encrypt(true.into()));
        template.push(Attribute::Id(key_id.to_be_bytes().to_vec()));
        template.push(Attribute::Private(false.into()));
        template.push(Attribute::AllowedMechanisms(vec![MechanismType::RSA_PKCS]));

        trace!("CreateObject command");
        match session.create_object(&template) {
            Ok(key) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_triple, &key_id, key_attributes)
                {
                    format_error!("Failed to insert the mappings, deleting the key.", e);
                    if let Err(e) = session.destroy_object(key) {
                        format_error!("Failed to destroy public key: ", e);
                    }
                    Err(e)
                } else {
                    Ok(psa_import_key::Result {})
                }
            }
            Err(error) => {
                format_error!("Import key status: ", error);
                Err(to_response_status(error))
            }
        }
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PublicKey)?;
        info!("Located key for export.");

        let mut attributes = session
            .get_attributes(
                key,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )
            .map_err(to_response_status)?;

        if attributes.len() != 2 {
            error!("Expected to find modulus and public exponent attributes in public key.");
            return Err(ResponseStatus::PsaErrorCommunicationFailure);
        }

        let modulus = if let Attribute::Modulus(vec) = attributes.remove(0) {
            IntegerAsn1::from_bytes_be_unsigned(vec)
        } else {
            error!("Expected to find modulus attribute.");
            return Err(ResponseStatus::PsaErrorCommunicationFailure);
        };
        let public_exponent = if let Attribute::PublicExponent(vec) = attributes.remove(0) {
            IntegerAsn1::from_bytes_be_unsigned(vec)
        } else {
            error!("Expected to find public exponent attribute.");
            return Err(ResponseStatus::PsaErrorCommunicationFailure);
        };

        let key = RSAPublicKey {
            modulus,
            public_exponent,
        };
        let data = picky_asn1_der::to_vec(&key).map_err(|err| {
            format_error!("Could not serialise key elements", err);
            ResponseStatus::PsaErrorCommunicationFailure
        })?;
        Ok(psa_export_public_key::Result { data: data.into() })
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let _ = self.key_info_store.remove_key_info(&key_triple)?;

        let session = self.new_session()?;

        let first_key = self.find_key(&session, key_id, KeyPairType::Any)?;
        session
            .destroy_object(first_key)
            .map_err(to_response_status)?;

        // Second key is optional.
        match self.find_key(&session, key_id, KeyPairType::Any) {
            Ok(key) => {
                trace!("DestroyObject command");
                session.destroy_object(key).map_err(to_response_status)
            }
            // A second key is optional.
            Err(ResponseStatus::PsaErrorDoesNotExist) => Ok(()),
            Err(e) => {
                format_error!("Error destroying key", e);
                Err(e)
            }
        }?;

        Ok(psa_destroy_key::Result {})
    }
}
