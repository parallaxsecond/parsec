// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::ts_protobuf::{
    CloseKeyIn, DestroyKeyIn, DestroyKeyOut, GenerateKeyIn, GenerateKeyOut, KeyAttributes,
    KeyLifetime, KeyPolicy, OpenKeyIn, OpenKeyOut,
};
use super::Context;
use log::info;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::ResponseStatus;
use psa_crypto::types::status::Error;
use std::convert::{TryFrom, TryInto};

impl Context {
    pub fn generate_key(&self, key_attrs: Attributes, id: u32) -> Result<(), ResponseStatus> {
        info!("Handling GenerateKey request");
        let proto_req = GenerateKeyIn {
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
        let GenerateKeyOut { handle } = self.send_request(&proto_req)?;

        let proto_req = CloseKeyIn { handle };
        self.send_request(&proto_req)?;

        Ok(())
    }

    pub fn destroy_key(&self, key_id: u32) -> Result<(), ResponseStatus> {
        info!("Handling DestroyKey request");
        if !self.check_key_exists(key_id)? {
            return Err(ResponseStatus::PsaErrorDoesNotExist);
        }
        let proto_req = OpenKeyIn { id: key_id };
        let OpenKeyOut { handle } = self.send_request(&proto_req)?;

        let proto_req = DestroyKeyIn { handle };
        let _proto_resp: DestroyKeyOut = self.send_request(&proto_req)?;
        Ok(())
    }

    pub fn check_key_exists(&self, key_id: u32) -> Result<bool, Error> {
        info!("Handling CheckKey request");
        let proto_req = OpenKeyIn { id: key_id };
        match self.send_request(&proto_req) {
            Ok(OpenKeyOut { handle }) => {
                let proto_req = CloseKeyIn { handle };
                self.send_request(&proto_req)?;
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
