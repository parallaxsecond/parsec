// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::ts_protobuf::{SignHashIn, SignHashOut, VerifyHashIn};
use super::Context;
use log::info;
use parsec_interface::operations::psa_algorithm::AsymmetricSignature;
use parsec_interface::requests::ResponseStatus;
use std::convert::TryInto;

impl Context {
    /// Sign a hash with an asymmetric key given its ID and the signing algorithm.
    pub fn sign_hash(
        &self,
        key_id: u32,
        hash: Vec<u8>,
        algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>, ResponseStatus> {
        info!("Handling SignHash request");
        let proto_req = SignHashIn {
            handle: 0,
            hash,
            alg: algorithm.try_into()?,
        };
        let SignHashOut { signature } = self.send_request_with_key(proto_req, key_id)?;

        Ok(signature)
    }

    /// Verify a signature on a hash with an asymmetric key given its ID and the signing algorithm.
    pub fn verify_hash(
        &self,
        key_id: u32,
        hash: Vec<u8>,
        signature: Vec<u8>,
        algorithm: AsymmetricSignature,
    ) -> Result<(), ResponseStatus> {
        info!("Handling VerifyHash request");
        let proto_req = VerifyHashIn {
            handle: 0,
            hash,
            signature,
            alg: algorithm.try_into()?,
        };
        self.send_request_with_key(proto_req, key_id)?;

        Ok(())
    }
}
