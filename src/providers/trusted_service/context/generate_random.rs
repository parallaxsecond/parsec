// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::error::Error;
use super::ts_protobuf::{GenerateRandomIn, GenerateRandomOut};
use super::Context;
use log::info;
use std::{convert::TryInto, mem};

impl Context {
    pub fn generate_random(&self, size: usize) -> Result<Vec<u8>, Error> {
        info!("Handling GenerateRandom request");
        let open_req: GenerateRandomIn = GenerateRandomIn {
            size: size.try_into()?,
        };
        let result: GenerateRandomOut =
            self.send_request(&open_req, mem::size_of::<GenerateRandomOut>())?;
        Ok(result.random_bytes)
    }
}
