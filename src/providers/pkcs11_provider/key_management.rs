// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{
    utils, KeyInfo, KeyPairType, LocalIdStore, Pkcs11Provider, ReadWriteSession, RsaPublicKey,
    Session,
};
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use crate::key_info_managers::{self, ManageKeyInfo};
use log::{error, info, warn};
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use picky_asn1::wrapper::IntegerAsn1;
use pkcs11::types::{CKR_OK, CK_ATTRIBUTE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_SESSION_HANDLE};
use std::mem;

// Public exponent value for all RSA keys.
const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// Gets a key identifier and key attributes from the Key Info Manager.
pub fn get_key_info(
    key_triple: &KeyTriple,
    store_handle: &dyn ManageKeyInfo,
) -> Result<([u8; 4], KeyAttributes)> {
    match store_handle.get(key_triple) {
        Ok(Some(key_info)) => {
            if key_info.id.len() == 4 {
                let mut dst = [0; 4];
                dst.copy_from_slice(&key_info.id);
                Ok((dst, key_info.attributes))
            } else {
                error!("Stored Key ID is not valid.");
                Err(ResponseStatus::KeyInfoManagerError)
            }
        }
        Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

pub fn create_key_id(
    key_triple: KeyTriple,
    key_attributes: KeyAttributes,
    store_handle: &mut dyn ManageKeyInfo,
    local_ids_handle: &mut LocalIdStore,
) -> Result<[u8; 4]> {
    let mut key_id = rand::random::<[u8; 4]>();
    while local_ids_handle.contains(&key_id) {
        key_id = rand::random::<[u8; 4]>();
    }
    let key_info = KeyInfo {
        id: key_id.to_vec(),
        attributes: key_attributes,
    };
    match store_handle.insert(key_triple.clone(), key_info) {
        Ok(insert_option) => {
            if insert_option.is_some() {
                warn!("Overwriting Key triple mapping ({})", key_triple);
            }
            let _ = local_ids_handle.insert(key_id);

            Ok(key_id)
        }
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

pub fn remove_key_id(
    key_triple: &KeyTriple,
    key_id: [u8; 4],
    store_handle: &mut dyn ManageKeyInfo,
    local_ids_handle: &mut LocalIdStore,
) -> Result<()> {
    match store_handle.remove(key_triple) {
        Ok(_) => {
            let _ = local_ids_handle.remove(&key_id);
            Ok(())
        }
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

pub fn key_info_exists(key_triple: &KeyTriple, store_handle: &dyn ManageKeyInfo) -> Result<bool> {
    match store_handle.exists(key_triple) {
        Ok(val) => Ok(val),
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

impl Pkcs11Provider {
    /// Find the PKCS 11 object handle corresponding to the key ID and the key type (public or
    /// private key) given as parameters for the current session.
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

        if let Err(e) = self.backend.find_objects_init(session, &template) {
            error!("Object enumeration init failed with {}", e);
            Err(utils::to_response_status(e))
        } else {
            match self.backend.find_objects(session, 1) {
                Ok(objects) => {
                    if let Err(e) = self.backend.find_objects_final(session) {
                        error!("Object enumeration final failed with {}", e);
                        Err(utils::to_response_status(e))
                    } else if objects.is_empty() {
                        Err(ResponseStatus::PsaErrorDoesNotExist)
                    } else {
                        Ok(objects[0])
                    }
                }
                Err(e) => {
                    error!("Finding objects failed with {}", e);
                    Err(utils::to_response_status(e))
                }
            }
        }
    }
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        info!("Pkcs11 Provider - Create Key");

        if op.attributes.key_type != KeyType::RsaKeyPair {
            error!("The PKCS11 provider currently only supports creating RSA key pairs.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let key_attributes = op.attributes;
        // This should never panic on 32 bits or more machines.
        let key_size = std::convert::TryFrom::try_from(op.attributes.key_bits).unwrap();

        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_info_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::PsaErrorAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            key_attributes,
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let mech = CK_MECHANISM {
            mechanism: pkcs11::types::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();
        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();

        priv_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_SIGN).with_bool(&pkcs11::types::CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id));
        priv_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_TOKEN).with_bool(&pkcs11::types::CK_TRUE));

        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_VERIFY).with_bool(&pkcs11::types::CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id));
        pub_template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT).with_bytes(&PUBLIC_EXPONENT),
        );
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS_BITS).with_ck_ulong(&key_size));
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_TOKEN).with_bool(&pkcs11::types::CK_TRUE));
        pub_template.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PRIVATE).with_bool(&pkcs11::types::CK_FALSE),
        );
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ENCRYPT).with_bool(&pkcs11::types::CK_TRUE));

        let session = Session::new(self, ReadWriteSession::ReadWrite).or_else(|err| {
            error!("Error creating a new session: {}.", err);
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            Err(err)
        })?;

        info!(
            "Generating RSA key pair in session {}",
            session.session_handle()
        );

        match self.backend.generate_key_pair(
            session.session_handle(),
            &mech,
            &pub_template,
            &priv_template,
        ) {
            Ok(_key) => Ok(psa_generate_key::Result {}),
            Err(e) => {
                error!("Generate Key Pair operation failed with {}", e);
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        info!("Pkcs11 Provider - Import Key");

        if op.attributes.key_type != KeyType::RsaPublicKey {
            error!("The PKCS 11 provider currently only supports importing RSA public key.");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_info_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::PsaErrorAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            key_attributes,
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();

        let public_key: RsaPublicKey = picky_asn1_der::from_bytes(&op.data).or_else(|e| {
            error!("Failed to parse RsaPublicKey data ({}).", e);
            Err(ResponseStatus::PsaErrorInvalidArgument)
        })?;

        if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
            error!("Only positive modulus and public exponent are supported.");
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        let modulus_object = &public_key.modulus.as_unsigned_bytes_be();
        let exponent_object = &public_key.public_exponent.as_unsigned_bytes_be();
        let key_bits = key_attributes.key_bits;
        if key_bits != 0 && modulus_object.len() * 8 != key_bits as usize {
            error!("If the key_bits field is non-zero (value is {}) it must be equal to the size of the key in data.", key_attributes.key_bits);
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
        allowed_mechanisms_attribute.ulValueLen = mem::size_of_val(&allowed_mechanisms);
        allowed_mechanisms_attribute.pValue = &allowed_mechanisms
            as *const pkcs11::types::CK_MECHANISM_TYPE
            as pkcs11::types::CK_VOID_PTR;
        template.push(allowed_mechanisms_attribute);

        let session = Session::new(self, ReadWriteSession::ReadWrite).or_else(|err| {
            error!("Error creating a new session: {}.", err);
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            Err(err)
        })?;

        info!(
            "Importing RSA public key in session {}",
            session.session_handle()
        );

        match self
            .backend
            .create_object(session.session_handle(), &template)
        {
            Ok(_key) => Ok(psa_import_key::Result {}),
            Err(e) => {
                error!("Import operation failed with {}", e);
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        info!("Pkcs11 Provider - Export Public Key");

        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let (key_id, _key_attributes) = get_key_info(&key_triple, &*store_handle)?;

        let session = Session::new(self, ReadWriteSession::ReadOnly)?;
        info!(
            "Export RSA public key in session {}",
            session.session_handle()
        );

        let key = self.find_key(session.session_handle(), key_id, KeyPairType::PublicKey)?;
        info!("Located key for export.");

        let mut size_attrs: Vec<CK_ATTRIBUTE> = Vec::new();
        size_attrs.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS));
        size_attrs.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT));

        // Get the length of the attributes to retrieve.
        let (modulus_len, public_exponent_len) =
            match self
                .backend
                .get_attribute_value(session.session_handle(), key, &mut size_attrs)
            {
                Ok((rv, attrs)) => {
                    if rv != CKR_OK {
                        error!("Error when extracting attribute: {}.", rv);
                        Err(utils::rv_to_response_status(rv))
                    } else {
                        Ok((attrs[0].ulValueLen, attrs[1].ulValueLen))
                    }
                }
                Err(e) => {
                    error!("Failed to read attributes from public key. Error: {}", e);
                    Err(utils::to_response_status(e))
                }
            }?;

        let mut modulus: Vec<pkcs11::types::CK_BYTE> = Vec::new();
        let mut public_exponent: Vec<pkcs11::types::CK_BYTE> = Vec::new();
        modulus.resize(modulus_len, 0);
        public_exponent.resize(public_exponent_len, 0);

        let mut extract_attrs: Vec<CK_ATTRIBUTE> = Vec::new();
        extract_attrs
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS).with_bytes(modulus.as_mut_slice()));
        extract_attrs.push(
            CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT)
                .with_bytes(public_exponent.as_mut_slice()),
        );

        match self
            .backend
            .get_attribute_value(session.session_handle(), key, &mut extract_attrs)
        {
            Ok(res) => {
                let (rv, attrs) = res;
                if rv != CKR_OK {
                    error!("Error when extracting attribute: {}.", rv);
                    Err(utils::rv_to_response_status(rv))
                } else {
                    let modulus = attrs[0].get_bytes();
                    let public_exponent = attrs[1].get_bytes();

                    // To produce a valid ASN.1 RSAPublicKey structure, 0x00 is put in front of the positive
                    // integer if highest significant bit is one, to differentiate it from a negative number.
                    let modulus = IntegerAsn1::from_unsigned_bytes_be(modulus);
                    let public_exponent = IntegerAsn1::from_unsigned_bytes_be(public_exponent);

                    let key = RsaPublicKey {
                        modulus,
                        public_exponent,
                    };
                    let data = picky_asn1_der::to_vec(&key).or_else(|err| {
                        error!("Could not serialise key elements: {}.", err);
                        Err(ResponseStatus::PsaErrorCommunicationFailure)
                    })?;
                    Ok(psa_export_public_key::Result { data })
                }
            }
            Err(e) => {
                error!("Failed to read attributes from public key. Error: {}", e);
                Err(utils::to_response_status(e))
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        info!("Pkcs11 Provider - Destroy Key");

        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::Pkcs11, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let (key_id, _) = get_key_info(&key_triple, &*store_handle)?;

        let session = Session::new(self, ReadWriteSession::ReadWrite)?;
        info!(
            "Deleting RSA keypair in session {}",
            session.session_handle()
        );

        match self.find_key(session.session_handle(), key_id, KeyPairType::Any) {
            Ok(key) => {
                match self.backend.destroy_object(session.session_handle(), key) {
                    Ok(_) => info!("Private part of the key destroyed successfully."),
                    Err(e) => {
                        error!("Failed to destroy private part of the key. Error: {}", e);
                        return Err(utils::to_response_status(e));
                    }
                };
            }
            Err(e) => {
                error!("Error destroying key: {}", e);
                return Err(e);
            }
        };

        // Second key is optional.
        match self.find_key(session.session_handle(), key_id, KeyPairType::Any) {
            Ok(key) => {
                match self.backend.destroy_object(session.session_handle(), key) {
                    Ok(_) => info!("Private part of the key destroyed successfully."),
                    Err(e) => {
                        error!("Failed to destroy private part of the key. Error: {}", e);
                        return Err(utils::to_response_status(e));
                    }
                };
            }
            // A second key is optional.
            Err(ResponseStatus::PsaErrorDoesNotExist) => (),
            Err(e) => {
                error!("Error destroying key: {}", e);
                return Err(e);
            }
        };

        remove_key_id(
            &key_triple,
            key_id,
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        Ok(psa_destroy_key::Result {})
    }
}
