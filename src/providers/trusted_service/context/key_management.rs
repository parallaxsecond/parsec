// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::ts_protobuf::{
    CloseKeyIn, DestroyKeyIn, DestroyKeyOut, ExportPublicKeyIn, GenerateKeyIn, GenerateKeyOut,
    ImportKeyIn, ImportKeyOut, KeyAttributes, KeyLifetime, KeyPolicy, OpenKeyIn, OpenKeyOut,
};
use super::Context;
use log::info;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::ResponseStatus;
use psa_crypto::types::status::Error;
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroize;

impl Context {
    pub fn generate_key(&self, key_attrs: Attributes, id: u32) -> Result<(), ResponseStatus> {
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

    pub fn import_key(
        &self,
        key_attrs: Attributes,
        id: u32,
        key_data: &[u8],
    ) -> Result<(), ResponseStatus> {
        let mut import_req = ImportKeyIn {
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
            data: key_data.to_vec(),
        };
        let ImportKeyOut { handle } = self.send_request(&import_req)?;
        import_req.data.zeroize();

        let close_req = CloseKeyIn { handle };
        self.send_request(&close_req)?;

        Ok(())
    }

    pub fn export_public_key(&self, id: u32) -> Result<Vec<u8>, ResponseStatus> {
        Ok(self.send_request_with_key(ExportPublicKeyIn::default(), id)?)
    }

    pub fn destroy_key(&self, key_id: u32) -> Result<(), ResponseStatus> {
        info!("Handling DestroyKey request");
        if !self.check_key_exists(key_id)? {
            return Err(ResponseStatus::PsaErrorDoesNotExist);
        }
        let open_req = OpenKeyIn { id: key_id };
        let OpenKeyOut { handle } = self.send_request(&open_req)?;

        let destroy_req = DestroyKeyIn { handle };
        let _proto_resp: DestroyKeyOut = self.send_request(&destroy_req)?;
        Ok(())
    }

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
                if e == Error::DoesNotExist {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }
}
