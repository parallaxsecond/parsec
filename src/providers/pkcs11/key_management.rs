// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::utils::{algorithm_to_mechanism, to_response_status};
use super::{utils, KeyPairType, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use log::{error, info, trace};
use parsec_interface::operations::psa_key_attributes::{EccFamily, Id, Lifetime, Type};
use parsec_interface::operations::utils_deprecated_primitives::CheckDeprecated;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use picky_asn1::wrapper::{IntegerAsn1, OctetStringAsn1};
use picky_asn1_x509::RsaPublicKey;
use std::convert::TryInto;

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

    pub(super) fn move_pub_key_to_psa_crypto(&self, key_identity: &KeyIdentity) -> Result<Id> {
        info!("Attempting to export public key");
        let export_operation = psa_export_public_key::Operation {
            key_name: key_identity.key_name().to_owned(),
        };
        let psa_export_public_key::Result { data } =
            self.psa_export_public_key_internal(key_identity.application(), export_operation)?;

        info!("Importing public key into PSA Crypto");
        let mut attributes = self.key_info_store.get_key_attributes(&key_identity)?;
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
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        return_on_deprecated!(op, "The key requested to generate is deprecated");

        if op.attributes.key_type.is_public_key() {
            error!("A public key type can not be generated.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let key_name = op.key_name;
        let key_attributes = op.attributes;

        if key_attributes.policy.usage_flags.export() && !self.allow_export {
            error!("The configuration of this provider does not allow it to generate keys that can be exported.");
            return Err(ResponseStatus::PsaErrorNotPermitted);
        }

        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        self.key_info_store.does_not_exist(&key_identity)?;

        let session = self.new_session()?;

        let key_id = self.create_key_id();

        let mut pub_template = vec![
            Attribute::Id(key_id.to_be_bytes().to_vec()),
            Attribute::Token(true.into()),
            Attribute::AllowedMechanisms(vec![algorithm_to_mechanism(
                key_attributes.policy.permitted_algorithms,
            )
            .map_err(to_response_status)?
            .mechanism_type()]),
        ];
        let mut priv_template = pub_template.clone();
        priv_template.push(Attribute::Class(ObjectClass::PRIVATE_KEY));
        pub_template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        pub_template.push(Attribute::Private(false.into()));

        utils::key_pair_usage_flags_to_pkcs11_attributes(
            key_attributes.policy.usage_flags,
            &mut pub_template,
            &mut priv_template,
        );

        let mech = match key_attributes.key_type {
            Type::RsaKeyPair => {
                pub_template.push(Attribute::PublicExponent(utils::PUBLIC_EXPONENT.to_vec()));
                pub_template.push(Attribute::ModulusBits(
                    key_attributes.bits.try_into().map_err(to_response_status)?,
                ));
                Ok(Mechanism::RsaPkcsKeyPairGen)
            }
            Type::EccKeyPair { curve_family } => {
                pub_template.push(Attribute::EcParams(
                    picky_asn1_der::to_vec(&utils::ec_params(curve_family, key_attributes.bits)?)
                        .map_err(|e| {
                        error!("Failed to generate EC parameters: {}", e);
                        ResponseStatus::PsaErrorGenericError
                    })?,
                ));
                Ok(Mechanism::EccKeyPairGen)
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }?;

        match session.generate_key_pair(&mech, &pub_template, &priv_template) {
            Ok((public, private)) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_identity, &key_id, key_attributes)
                {
                    format_error!("Failed to insert the mappings, deleting the key", e);
                    if let Err(e) = session.destroy_object(public) {
                        format_error!("Failed to destroy public part of the key", e);
                    }
                    if let Err(e) = session.destroy_object(private) {
                        format_error!("Failed to destroy private part of the key", e);
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(error) => {
                format_error!("Generate key status", error);
                Err(to_response_status(error))
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        warn_on_deprecated!(op, "The key requested to import is deprecated");

        let key_name = op.key_name;
        let key_attributes = op.attributes;

        if key_attributes.policy.usage_flags.export() && !self.allow_export {
            error!("The configuration of this provider does not allow it to generate keys that can be exported.");
            return Err(ResponseStatus::PsaErrorNotPermitted);
        }
        if op.data.expose_secret().is_empty() {
            error!("Key data is empty");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        self.key_info_store.does_not_exist(&key_identity)?;

        let session = self.new_session()?;

        let key_id = self.create_key_id();

        let mut template: Vec<Attribute> = Vec::new();
        template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        template.push(Attribute::Token(true.into()));
        template.push(Attribute::Verify(true.into()));
        template.push(Attribute::Id(key_id.to_be_bytes().to_vec()));

        match op.attributes.key_type {
            Type::RsaPublicKey => {
                self.handle_rsa_public_import_attrib(
                    op.data.expose_secret(),
                    key_attributes.bits,
                    &mut template,
                )?;
            }
            Type::EccPublicKey { curve_family } => {
                self.handle_ecc_public_import_attrib(
                    op.data.expose_secret(),
                    key_attributes.bits,
                    curve_family,
                    &mut template,
                )?;
            }
            _ => {
                error!(
                    "The pkcs11 provider does not support the {:?} key type.",
                    op.attributes.key_type
                );
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        }
        trace!("CreateObject command");
        match session.create_object(&template) {
            Ok(key) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_identity, &key_id, key_attributes)
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

    pub(super) fn handle_rsa_public_import_attrib(
        &self,
        key_data: &[u8],
        bits: usize,
        template: &mut Vec<Attribute>,
    ) -> Result<()> {
        let public_key: RsaPublicKey = picky_asn1_der::from_bytes(key_data).map_err(|e| {
            format_error!("Failed to parse RsaPublicKey data", e);
            ResponseStatus::PsaErrorInvalidArgument
        })?;

        if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
            error!("Only positive modulus and public exponent are supported.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let modulus_object = public_key.modulus.as_unsigned_bytes_be();
        let exponent_object = public_key.public_exponent.as_unsigned_bytes_be();
        if bits != 0 && modulus_object.len() * 8 != bits {
            if crate::utils::GlobalConfig::log_error_details() {
                error!(
                    "`bits` field of key attributes (value: {}) must be either 0 or equal to the size of the key in `data` (value: {}).",
                    bits,
                    modulus_object.len() * 8
                );
            } else {
                error!("`bits` field of key attributes must be either 0 or equal to the size of the key in `data`.");
            }

            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        template.push(Attribute::Modulus(modulus_object.into()));
        template.push(Attribute::PublicExponent(exponent_object.into()));
        template.push(Attribute::Encrypt(true.into()));
        template.push(Attribute::Private(false.into()));
        template.push(Attribute::AllowedMechanisms(vec![MechanismType::RSA_PKCS]));
        template.push(Attribute::KeyType(KeyType::RSA));

        Ok(())
    }

    pub(super) fn handle_ecc_public_import_attrib(
        &self,
        key_data: &[u8],
        bits: usize,
        curve_family: EccFamily,
        template: &mut Vec<Attribute>,
    ) -> Result<()> {
        match curve_family {
            EccFamily::Montgomery => {
                // Montgomery curves aren't supported because their format differs from what
                // we need below.
                // In any case, the list of curves for which we can create `EcParams` below
                // is even shorter than that.
                error!("Importing EC keys using Montgomery curves is not currently supported.");
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
            _ => (),
        }

        // For the format of ECC public keys, see:
        // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html#description
        let key_len = ((key_data.len() - 1) / 2) * 8;
        let bits = if bits == 0 { key_len } else { bits };
        if bits != key_len {
            if crate::utils::GlobalConfig::log_error_details() {
                error!(
                        "`bits` field of key attributes (value: {}) must be either 0 or equal to half the size of the key in `data` (value: {}) for Weierstrass curves.",
                        bits,
                        key_len
                    );
            } else {
                error!("`bits` field of key attributes must be either 0 or equal to half the size of the key in `data` for Weierstrass curves.");
            }
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        // The format expected by PKCS11 is an ASN.1 OctetString containing the
        // data that the PSA Crypto interface specifies.
        // See ECPoint in [SEC1](https://www.secg.org/sec1-v2.pdf). PKCS11 mandates using
        // [ANSI X9.62 ECPoint](https://cryptsoft.com/pkcs11doc/v220/group__SEC__12__3__3__ECDSA__PUBLIC__KEY__OBJECTS.html),
        // however SEC1 is an equivalent spec.
        let key_data =
            picky_asn1_der::to_vec(&OctetStringAsn1(key_data.to_vec())).map_err(|e| {
                error!("Failed to generate EC Point OctetString: {}", e);
                ResponseStatus::PsaErrorInvalidArgument
            })?;
        template.push(Attribute::EcPoint(key_data));
        template.push(Attribute::Private(false.into()));
        template.push(Attribute::AllowedMechanisms(vec![MechanismType::ECDSA]));
        template.push(Attribute::KeyType(KeyType::EC));
        template.push(Attribute::EcParams(
            picky_asn1_der::to_vec(&utils::ec_params(curve_family, bits)?).map_err(|e| {
                error!("Failed to generate EC parameters: {}", e);
                ResponseStatus::PsaErrorGenericError
            })?,
        ));

        Ok(())
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
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        let key_id = self.key_info_store.get_key_id(&key_identity)?;
        let session = self.new_session()?;

        let key = self.find_key(&session, key_id, KeyPairType::PublicKey)?;
        info!("Located key for export.");
        let data = match key_attributes.key_type {
            Type::RsaKeyPair | Type::RsaPublicKey => {
                self.export_public_rsa_internal(key, &session)?
            }
            Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => {
                self.export_public_ec_internal(key, &session)?
            }
            _ => {
                return Err(ResponseStatus::PsaErrorNotSupported);
            }
        };

        Ok(psa_export_public_key::Result { data: data.into() })
    }

    fn export_public_rsa_internal(&self, key: ObjectHandle, session: &Session) -> Result<Vec<u8>> {
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

        let key = RsaPublicKey {
            modulus,
            public_exponent,
        };
        Ok(picky_asn1_der::to_vec(&key).map_err(|err| {
            format_error!("Could not serialise key elements", err);
            ResponseStatus::PsaErrorCommunicationFailure
        })?)
    }

    fn export_public_ec_internal(&self, key: ObjectHandle, session: &Session) -> Result<Vec<u8>> {
        let mut attributes = session
            .get_attributes(key, &[AttributeType::EcPoint])
            .map_err(to_response_status)?;

        if attributes.len() != 1 {
            error!("Expected to find EC point attribute in public key.");
            return Err(ResponseStatus::PsaErrorCommunicationFailure);
        }

        if let Attribute::EcPoint(data) = attributes.remove(0) {
            // The format provided by PKCS11 is an ASN.1 OctetString containing the
            // data that the PSA Crypto interface expects.
            // See ECPoint in [SEC1](https://www.secg.org/sec1-v2.pdf). PKCS11 mandates using
            // [ANSI X9.62 ECPoint](https://cryptsoft.com/pkcs11doc/v220/group__SEC__12__3__3__ECDSA__PUBLIC__KEY__OBJECTS.html),
            // however SEC1 is an equivalent spec.
            let parsed_data = picky_asn1_der::from_bytes::<OctetStringAsn1>(&data);
            match parsed_data {
                Ok(key_data) => Ok(key_data.0),
                // Some PKCS#11 implementations provide the EC_POINT as raw bytes and fail to wrap in ASN.1 OctetString as
                // mandated by the spec. If the ASN.1 parse fails, then we assume that the raw bytes are the EC_POINT data,
                // and return those instead of failing, trading off strictness for broader interoperability.
                Err(_) => Ok(data),
            }
        } else {
            error!("Expected to find modulus attribute.");
            Err(ResponseStatus::PsaErrorCommunicationFailure)
        }
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
        let key_id = self.key_info_store.get_key_id(&key_identity)?;

        let _ = self.key_info_store.remove_key_info(&key_identity)?;

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
