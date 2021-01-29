// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::error::Error;
use super::ts_protobuf::{
    CloseKeyIn, DestroyKeyIn, DestroyKeyOut, ExportPublicKeyIn, GenerateKeyIn, GenerateKeyOut,
    ImportKeyIn, ImportKeyOut, KeyAttributes, KeyLifetime, KeyPolicy, OpenKeyIn, OpenKeyOut,
};
use super::Context;
use log::info;
use psa_crypto::types::key::Attributes;
use psa_crypto::types::status::Error as PsaError;
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroize;

impl Context {
    /// Generate a key given its attributes and ID
    ///
    /// Lifetime flexibility is not supported: the `lifetime` parameter in the key
    /// attributes is essentially ignored and replaced with `KeyLifetime::Persistent`.
    pub fn generate_key(&self, key_attrs: Attributes, id: u32) -> Result<(), Error> {
        info!("Handling GenerateKey request");
        let generate_req = GenerateKeyIn {
            attributes: Some(KeyAttributes {
                r#type: u16::try_from(key_attrs.key_type)? as u32,
                key_bits: key_attrs.bits.try_into()?,
                lifetime: KeyLifetime::Persistent as u32,
                id,
                policy: Some(KeyPolicy {
                    usage: key_attrs.policy.usage_flags.try_into()?,
                    alg: key_attrs.policy.permitted_algorithms.try_into()?,
                }),
            }),
        };
        let GenerateKeyOut { handle } = self.send_request(&generate_req)?;

        let close_req = CloseKeyIn { handle };
        self.send_request(&close_req)?;

        Ok(())
    }

    /// Import a key given its attributes, ID, and key data.
    ///
    /// Lifetime flexibility is not supported: the `lifetime` parameter in the key
    /// attributes is essentially ignored and replaced with `KeyLifetime::Persistent`.
    ///
    /// Key data must be in the format described by the PSA Crypto format.
    pub fn import_key(&self, key_attrs: Attributes, id: u32, key_data: &[u8]) -> Result<(), Error> {
        info!("Handling ImportKey request");
        let mut data = key_data.to_vec();
        let import_req = ImportKeyIn {
            attributes: Some(KeyAttributes {
                r#type: u16::try_from(key_attrs.key_type).map_err(|e| {
                    data.zeroize();
                    e
                })? as u32,
                key_bits: key_attrs.bits.try_into().map_err(|e| {
                    data.zeroize();
                    e
                })?,
                lifetime: KeyLifetime::Persistent as u32,
                id,
                policy: Some(KeyPolicy {
                    usage: key_attrs.policy.usage_flags.into(),
                    alg: key_attrs
                        .policy
                        .permitted_algorithms
                        .try_into()
                        .map_err(|e| {
                            data.zeroize();
                            e
                        })?,
                }),
            }),
            data,
        };
        let ImportKeyOut { handle } = self.send_request(&import_req)?;

        let close_req = CloseKeyIn { handle };
        self.send_request(&close_req)?;

        Ok(())
    }

    /// Export the public part of a key given its ID.
    ///
    /// The public key data is returned in the format specified by the PSA Crypto
    /// format.
    pub fn export_public_key(&self, id: u32) -> Result<Vec<u8>, Error> {
        info!("Handling ExportPublicKey request");
        Ok(self.send_request_with_key(ExportPublicKeyIn::default(), id)?)
    }

    /// Destroy a key given its ID.
    pub fn destroy_key(&self, key_id: u32) -> Result<(), Error> {
        info!("Handling DestroyKey request");
        let open_req = OpenKeyIn { id: key_id };
        let OpenKeyOut { handle } = self.send_request(&open_req)?;

        let destroy_req = DestroyKeyIn { handle };
        let _proto_resp: DestroyKeyOut = self.send_request(&destroy_req)?;
        Ok(())
    }

    /// Verify if a key with a given ID exists.
    pub fn check_key_exists(&self, key_id: u32) -> Result<bool, Error> {
        info!("Handling CheckKey request");
        let open_req = OpenKeyIn { id: key_id };
        match self.send_request(&open_req) {
            Ok(OpenKeyOut { handle }) => {
                let close_req = CloseKeyIn { handle };
                self.send_request(&close_req)?;
                Ok(true)
            }
            Err(e) => {
                if e == Error::PsaCrypto(PsaError::DoesNotExist) {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }
}
