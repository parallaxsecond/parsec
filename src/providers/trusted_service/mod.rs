// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Trusted Service provider
//!
//! This provider is backed by a crypto Trusted Service deployed in TrustZone
use crate::key_info_managers::ManageKeyInfo;
use crate::providers::Provide;
use context::Context;
use derivative::Derivative;
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::psa_key_attributes::{Attributes, Id};
use parsec_interface::requests::{Opcode, ProviderID, Result};
use psa_crypto::types::key;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{atomic::AtomicU32, Arc, RwLock};
use uuid::Uuid;

mod context;

const SUPPORTED_OPCODES: [Opcode; 0] = [];

/// Trusted Service provider structure
///
/// Currently the provider only supports volatile keys due to limitations in the stack
/// underneath us. Therefore none of the key information is persisted, being kept instead
/// in a map for fast access.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    context: Context,
    // When calling write on a reference of key_info_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyInfo + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyInfo + Send + Sync and then
    // reference it to match with the method prototypes.
    #[derivative(Debug = "ignore")]
    key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    key_attr_map: HashMap<String, (Id, Attributes)>,

    // Holds the highest ID of all keys (including destroyed keys). New keys will receive an ID of
    // id_counter + 1. Once id_counter reaches the highest allowed ID, no more keys can be created.
    id_counter: AtomicU32,
}

impl Provider {
    /// Creates and initialise a new instance of Provider.
    fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> anyhow::Result<Provider> {
        let ts_provider = Provider {
            key_info_store,
            context: Context::connect()?,
            key_attr_map: HashMap::new(),
            id_counter: AtomicU32::new(key::PSA_KEY_ID_USER_MIN),
        };
        Ok(ts_provider)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        Ok((ProviderInfo {
            // Assigned UUID for this provider: 1c1139dc-ad7c-47dc-ad6b-db6fdb466552
            uuid: Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552")?,
            description: String::from("Provider exposing functionality provided by the Crypto Trusted Service running in a Trusted Execution Environment"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::TrustedService,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }
}

/// Trusted Service provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
}

impl ProviderBuilder {
    /// Create a new provider builder
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

    /// Build into a TrustedService
    pub fn build(self) -> anyhow::Result<Provider> {
        Provider::new(self.key_info_store.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing key info store")
        })?)
    }
}
