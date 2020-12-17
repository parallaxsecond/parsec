// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Microchip CryptoAuthentication Library provider
//!
//! This provider is a hardware based implementation of PSA Crypto, Mbed Crypto.
use super::Provide;
use crate::key_info_managers::ManageKeyInfo;
use derivative::Derivative;
use log::trace;
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};

const SUPPORTED_OPCODES: [Opcode; 0] = [];

/// CryptoAuthLib provider structure
#[derive(Derivative)]
#[derivative(Debug, Clone, Copy)]
pub struct Provider {
    // device: rust_cryptoauthlib::AtcaDevice,
}

impl Provider {
    /// Creates and initialise a new instance of CryptoAuthLibProvider
    fn new(_key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>) -> Option<Provider> {
        Some(Provider {})
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: b8ba81e2-e9f7-4bdd-b096-a29d0019960c
            uuid: Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("User space hardware provider, utilizing MicrochipTech CryptoAuthentication Library for ATECCx08 chips"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::CryptoAuthLib,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }
}

/// CryptoAuthentication Library Provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
}

impl ProviderBuilder {
    /// Create a new CryptoAuthLib builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(
        mut self,
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Attempt to build CryptoAuthLib Provider
    pub fn build(self) -> std::io::Result<Provider> {
        Provider::new(
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "CryptoAuthLib Provider initialization failed",
            )
        })
    }
}
