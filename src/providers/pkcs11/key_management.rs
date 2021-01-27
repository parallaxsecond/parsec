// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{utils, KeyPairType, Provider, ReadWriteSession, Session};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{error, info, trace};
use parsec_interface::operations::psa_key_attributes::{Id, Lifetime, Type};
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::RSAPublicKey;
use pkcs11::types::{CKR_OK, CK_ATTRIBUTE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE};
use std::mem;

impl Provider {
    /// Find the PKCS 11 object handle corresponding to the key ID and the key type (public,
    /// private or any key type) given as parameters for the current session.
    pub(super) fn find_key(
        &self,
        session: CK_SESSION_HANDLE,
        key_id: [u8; 4],
        key_type: KeyPairType,
    ) -> Result<CK_OBJECT_HANDLE> {
        let mut template = vec![CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id)];
        match key_type {
            KeyPairType::PublicKey => template.push(
                CK_ATTRIBUTE::new(pkcs11::types::CKA_CLASS)
                    .with_ck_ulong(&pkcs11::types::CKO_PUBLIC_KEY),
            ),
            KeyPairType::PrivateKey => template.push(
                CK_ATTRIBUTE::new(pkcs11::types::CKA_CLASS)
                    .with_ck_ulong(&pkcs11::types::CKO_PRIVATE_KEY),
            ),
            KeyPairType::Any => (),
        }

        trace!("FindObjectsInit command");
        if let Err(e) = self.backend.find_objects_init(session, &template) {
            format_error!("Object enumeration init failed", e);
            Err(utils::to_response_status(e))
        } else {
            trace!("FindObjects command");
            match self.backend.find_objects(session, 1) {
                Ok(objects) => {
                    trace!("FindObjectsFinal command");
                    if let Err(e) = self.backend.find_objects_final(session) {
                        format_error!("Object enumeration final failed", e);
                        Err(utils::to_response_status(e))
                    } else if objects.is_empty() {
                        Err(ResponseStatus::PsaErrorDoesNotExist)
                    } else {
                        Ok(objects[0])
                    }
                }
                Err(e) => {
                    format_error!("Finding objects failed", e);
                    Err(utils::to_response_status(e))
                }
            }
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
        let (_, mut attributes) = self.get_key_info(key_triple)?;
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
        self.key_info_does_not_exist(&key_triple)?;

        let key_id = self.create_key_id();

        let modulus_bits = key_attributes.bits as u64;
        let (mech, mut pub_template, mut priv_template, mut allowed_mechanism) =
            utils::parsec_to_pkcs11_params(key_attributes, &key_id, &modulus_bits)?;

        pub_template.push(utils::mech_type_to_allowed_mech_attribute(
            &mut allowed_mechanism,
        ));
        priv_template.push(utils::mech_type_to_allowed_mech_attribute(
            &mut allowed_mechanism,
        ));

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;

        if crate::utils::GlobalConfig::log_error_details() {
            info!(
                "Generating RSA key pair in session {}",
                session.session_handle()
            );
        }

        trace!("GenerateKeyPair command");
        match self.backend.generate_key_pair(
            session.session_handle(),
            &mech,
            &pub_template,
            &priv_template,
        ) {
            Ok((first_key, second_key)) => {
                if let Err(e) = self.insert_key_id(key_triple, key_attributes, key_id) {
                    // Destroy the generated key in a best effort way to avoid zombies 🧟
                    if self
                        .backend
                        .destroy_object(session.session_handle(), first_key)
                        .is_err()
                    {
                        error!("Failed to destroy first part of the key pair.");
                    }
                    if self
                        .backend
                        .destroy_object(session.session_handle(), second_key)
                        .is_err()
                    {
                        error!("Failed to destroy second part of the key pair.");
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(e) => {
                format_error!("Generate Key Pair operation failed", e);
                Err(utils::to_response_status(e))
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
        self.key_info_does_not_exist(&key_triple)?;

        let key_id = self.create_key_id();

        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();

        let public_key: RSAPublicKey = picky_asn1_der::from_bytes(op.data.expose_secret())
            .map_err(|e| {
                format_error!("Failed to parse RsaPublicKey data", e);
                ResponseStatus::PsaErrorInvalidArgument
            })?;

        if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
            error!("Only positive modulus and public exponent are supported.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let modulus_object = &public_key.modulus.as_unsigned_bytes_be();
        let exponent_object = &public_key.public_exponent.as_unsigned_bytes_be();
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

        template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_CLASS)
                .with_ck_ulong(&pkcs11::types::CKO_PUBLIC_KEY),
        );
        template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_KEY_TYPE).with_ck_ulong(&pkcs11::types::CKK_RSA),
        );
        template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_TOKEN).with_bool(&pkcs11::types::CK_TRUE));
        template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS).with_bytes(modulus_object));
        template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT).with_bytes(exponent_object),
        );
        template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_VERIFY).with_bool(&pkcs11::types::CK_TRUE));
        template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ENCRYPT).with_bool(&pkcs11::types::CK_TRUE));
        template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id));
        template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PRIVATE).with_bool(&pkcs11::types::CK_FALSE),
        );

        // Restrict to RSA.
        let allowed_mechanisms = [pkcs11::types::CKM_RSA_PKCS];
        // The attribute contains a pointer to the allowed_mechanism array and its size as
        // ulValueLen.
        let mut allowed_mechanisms_attribute =
            CK_ATTRIBUTE::new(pkcs11::types::CKA_ALLOWED_MECHANISMS);
        allowed_mechanisms_attribute.ulValueLen = mem::size_of_val(&allowed_mechanisms) as u64;
        allowed_mechanisms_attribute.pValue = &allowed_mechanisms
            as *const pkcs11::types::CK_MECHANISM_TYPE
            as pkcs11::types::CK_VOID_PTR;
        template.push(allowed_mechanisms_attribute);

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;

        if crate::utils::GlobalConfig::log_error_details() {
            info!(
                "Importing RSA public key in session {}",
                session.session_handle()
            );
        }

        trace!("CreateObject command");
        match self
            .backend
            .create_object(session.session_handle(), &template)
        {
            Ok(key) => {
                if let Err(e) = self.insert_key_id(key_triple, key_attributes, key_id) {
                    if self
                        .backend
                        .destroy_object(session.session_handle(), key)
                        .is_err()
                    {
                        error!("Failed to destroy public key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_import_key::Result {})
                }
            }
            Err(e) => {
                format_error!("Import operation failed", e);
                Err(utils::to_response_status(e))
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
        let (key_id, _key_attributes) = self.get_key_info(&key_triple)?;

        let session = Session::new(self, ReadWriteSession::ReadOnly)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!(
                "Export RSA public key in session {}",
                session.session_handle()
            );
        }

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PublicKey)?;
        info!("Located key for export.");

        let mut size_attrs: Vec<CK_ATTRIBUTE> = Vec::new();
        size_attrs.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS));
        size_attrs.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT));

        // Get the length of the attributes to retrieve.
        trace!("GetAttributeValue command");
        let (modulus_len, public_exponent_len) =
            match self
                .backend
                .get_attribute_value(session.session_handle(), key, &mut size_attrs)
            {
                Ok((rv, attrs)) => {
                    if rv != CKR_OK {
                        format_error!("Error when extracting attribute", rv);
                        Err(utils::rv_to_response_status(rv))
                    } else {
                        Ok((attrs[0].ulValueLen, attrs[1].ulValueLen))
                    }
                }
                Err(e) => {
                    format_error!("Failed to read attributes from public key", e);
                    Err(utils::to_response_status(e))
                }
            }?;

        let mut modulus: Vec<pkcs11::types::CK_BYTE> = Vec::new();
        let mut public_exponent: Vec<pkcs11::types::CK_BYTE> = Vec::new();
        modulus.resize(modulus_len as usize, 0);
        public_exponent.resize(public_exponent_len as usize, 0);

        let mut extract_attrs: Vec<CK_ATTRIBUTE> = Vec::new();
        extract_attrs
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS).with_bytes(modulus.as_mut_slice()));
        extract_attrs.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT)
                .with_bytes(public_exponent.as_mut_slice()),
        );

        trace!("GetAttributeValue command");
        match self
            .backend
            .get_attribute_value(session.session_handle(), key, &mut extract_attrs)
        {
            Ok(res) => {
                let (rv, attrs) = res;
                if rv != CKR_OK {
                    format_error!("Error when extracting attribute", rv);
                    Err(utils::rv_to_response_status(rv))
                } else {
                    let modulus = attrs[0].get_bytes().map_err(|err| {
                        format_error!("Error getting bytes from modulus attribute", err);
                        ResponseStatus::PsaErrorCommunicationFailure
                    })?;
                    let public_exponent = attrs[1].get_bytes().map_err(|err| {
                        format_error!("Error getting bytes from public exponent attribute", err);
                        ResponseStatus::PsaErrorCommunicationFailure
                    })?;

                    // To produce a valid ASN.1 RSAPublicKey structure, 0x00 is put in front of the positive
                    // integer if highest significant bit is one, to differentiate it from a negative number.
                    let modulus = IntegerAsn1::from_bytes_be_unsigned(modulus);
                    let public_exponent = IntegerAsn1::from_bytes_be_unsigned(public_exponent);

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
            }
            Err(e) => {
                format_error!("Failed to read attributes from public key", e);
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let (key_id, _) = self.get_key_info(&key_triple)?;

        let _ = self.remove_key_id(&key_triple)?;

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        if crate::utils::GlobalConfig::log_error_details() {
            info!(
                "Deleting RSA keypair in session {}",
                session.session_handle()
            );
        }

        let first_res = match self.find_key(session.session_handle(), key_id, KeyPairType::Any) {
            Ok(key) => {
                trace!("DestroyObject command");
                match self.backend.destroy_object(session.session_handle(), key) {
                    Ok(_) => {
                        info!("Private part of the key destroyed successfully.");
                        Ok(())
                    }
                    Err(e) => {
                        format_error!("Failed to destroy private part of the key", e);
                        Err(utils::to_response_status(e))
                    }
                }
            }
            Err(e) => {
                format_error!("Error destroying key", e);
                Err(e)
            }
        };

        // Second key is optional.
        let second_res = match self.find_key(session.session_handle(), key_id, KeyPairType::Any) {
            Ok(key) => {
                trace!("DestroyObject command");
                match self.backend.destroy_object(session.session_handle(), key) {
                    Ok(_) => {
                        info!("Private part of the key destroyed successfully.");
                        Ok(())
                    }
                    Err(e) => {
                        format_error!("Failed to destroy private part of the key", e);
                        Err(utils::to_response_status(e))
                    }
                }
            }
            // A second key is optional.
            Err(ResponseStatus::PsaErrorDoesNotExist) => Ok(()),
            Err(e) => {
                format_error!("Error destroying key", e);
                Err(e)
            }
        };

        first_res?;
        second_res?;
        Ok(psa_destroy_key::Result {})
    }
}
