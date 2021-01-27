// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core information source for the service
//!
//! The core provider acts as a source of information for the Parsec service,
//! aiding clients in discovering the capabilities offered by their underlying
//! platform.
use super::Provide;
use crate::authenticators::ApplicationName;
use derivative::Derivative;
use log::{error, trace};
use parsec_interface::operations::{
    delete_client, list_authenticators, list_clients, list_keys, list_opcodes, list_providers,
    ping, psa_destroy_key,
};
use parsec_interface::operations::{
    list_authenticators::AuthenticatorInfo, list_keys::KeyInfo, list_providers::ProviderInfo,
};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use version::{version, Version};

const SUPPORTED_OPCODES: [Opcode; 5] = [
    Opcode::ListProviders,
    Opcode::ListOpcodes,
    Opcode::Ping,
    Opcode::ListAuthenticators,
    Opcode::ListKeys,
];

/// Service information provider
///
/// The core provider is a non-cryptographic provider tasked with offering
/// structured information about the status of the service and the providers
/// available.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    wire_protocol_version_min: u8,
    wire_protocol_version_maj: u8,
    provider_info: Vec<ProviderInfo>,
    provider_opcodes: HashMap<ProviderID, HashSet<Opcode>>,
    authenticator_info: Vec<AuthenticatorInfo>,
    #[derivative(Debug = "ignore")]
    prov_list: Vec<Arc<dyn Provide + Send + Sync>>,
}

impl Provide for Provider {
    fn list_opcodes(&self, op: list_opcodes::Operation) -> Result<list_opcodes::Result> {
        trace!("list_opcodes ingress");
        Ok(list_opcodes::Result {
            opcodes: self
                .provider_opcodes
                .get(&op.provider_id)
                .ok_or(ResponseStatus::ProviderNotRegistered)?
                .clone(),
        })
    }

    fn list_providers(&self, _op: list_providers::Operation) -> Result<list_providers::Result> {
        trace!("list_providers ingress");
        Ok(list_providers::Result {
            providers: self.provider_info.clone(),
        })
    }

    fn list_authenticators(
        &self,
        _op: list_authenticators::Operation,
    ) -> Result<list_authenticators::Result> {
        trace!("list_authenticators ingress");
        Ok(list_authenticators::Result {
            authenticators: self.authenticator_info.clone(),
        })
    }

    fn list_keys(
        &self,
        app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");

        let mut keys: Vec<KeyInfo> = Vec::new();
        for provider in &self.prov_list {
            let id = if let Ok((provider_info, _)) = provider.describe() {
                provider_info.id.to_string()
            } else {
                "unknown".to_string()
            };
            let mut result = provider
                .list_keys(app_name.clone(), _op)
                .unwrap_or_else(|e| {
                    error!("list_keys failed on provider {} with {}", id, e);
                    list_keys::Result { keys: Vec::new() }
                });
            keys.append(&mut result.keys);
        }

        Ok(list_keys::Result { keys })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");

        let mut clients: Vec<String> = Vec::new();
        for provider in &self.prov_list {
            let mut result = provider.list_clients(_op).unwrap_or_else(|e| {
                let id = if let Ok((provider_info, _)) = provider.describe() {
                    provider_info.id.to_string()
                } else {
                    "unknown".to_string()
                };
                error!("list_clients failed on provider {} with {}", id, e);
                list_clients::Result {
                    clients: Vec::new(),
                }
            });
            clients.append(&mut result.clients);
        }
        clients.sort();
        clients.dedup();

        Ok(list_clients::Result { clients })
    }

    fn delete_client(&self, op: delete_client::Operation) -> Result<delete_client::Result> {
        trace!("delete_client ingress");

        let client = op.client;

        for provider in &self.prov_list {
            let id = if let Ok((provider_info, _)) = provider.describe() {
                provider_info.id.to_string()
            } else {
                "unknown".to_string()
            };
            // Currently Parsec only stores keys, we delete all of them.
            let keys = provider
                .list_keys(
                    ApplicationName::from_name(client.clone()),
                    list_keys::Operation {},
                )
                .unwrap_or_else(|e| {
                    error!("list_keys failed on provider {} with {}", id, e);
                    list_keys::Result { keys: Vec::new() }
                })
                .keys;
            for key in keys {
                let key_name = key.name;
                let _ = provider
                    .psa_destroy_key(
                        ApplicationName::from_name(client.clone()),
                        psa_destroy_key::Operation { key_name },
                    )
                    .unwrap_or_else(|e| {
                        error!("psa_destroy_key failed on provider {} with {}", id, e);
                        psa_destroy_key::Result {}
                    });
            }
        }

        Ok(delete_client::Result {})
    }

    fn ping(&self, _op: ping::Operation) -> Result<ping::Result> {
        trace!("ping ingress");
        let result = ping::Result {
            wire_protocol_version_maj: self.wire_protocol_version_maj,
            wire_protocol_version_min: self.wire_protocol_version_min,
        };

        Ok(result)
    }

    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        unreachable!()
    }
}

/// Builder for CoreProvider
#[derive(Derivative, Default)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    version_maj: Option<u8>,
    version_min: Option<u8>,
    #[derivative(Debug = "ignore")]
    prov_list: Vec<Arc<dyn Provide + Send + Sync>>,
    #[derivative(Debug = "ignore")]
    authenticator_info: Vec<AuthenticatorInfo>,
}

impl ProviderBuilder {
    /// Create a new CoreProvider builder
    pub fn new() -> Self {
        ProviderBuilder {
            version_maj: None,
            version_min: None,
            prov_list: Vec::new(),
            authenticator_info: Vec::new(),
        }
    }

    /// Add the wire protocol version used by the service
    pub fn with_wire_protocol_version(mut self, version_min: u8, version_maj: u8) -> Self {
        self.version_maj = Some(version_maj);
        self.version_min = Some(version_min);

        self
    }

    /// Add a provider used
    pub fn with_provider(mut self, provider: Arc<dyn Provide + Send + Sync>) -> Self {
        self.prov_list.push(provider);

        self
    }

    /// Add the authenticator information
    pub fn with_authenticator_info(mut self, authenticator_info: AuthenticatorInfo) -> Self {
        self.authenticator_info.push(authenticator_info);

        self
    }

    /// Build into a CoreProvider
    pub fn build(self) -> std::io::Result<Provider> {
        let mut provider_opcodes = HashMap::new();
        let _ = provider_opcodes.insert(
            ProviderID::Core,
            SUPPORTED_OPCODES.iter().copied().collect(),
        );

        let mut provider_info_vec = Vec::new();
        for provider in &self.prov_list {
            let (provider_info, opcodes) = provider
                .describe()
                .map_err(|_| Error::new(ErrorKind::Other, "Failed to describe provider"))?;
            let _ = provider_opcodes.insert(provider_info.id, opcodes);
            provider_info_vec.push(provider_info);
        }

        let crate_version: Version = Version::from_str(version!()).map_err(|e| {
            format_error!("Error parsing the crate version", e);
            Error::new(
                ErrorKind::InvalidData,
                "crate version number has invalid format",
            )
        })?;
        provider_info_vec.push(ProviderInfo {
            // Assigned UUID for this provider: 47049873-2a43-4845-9d72-831eab668784
            uuid: Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").map_err(|_| Error::new(
                ErrorKind::InvalidData,
                "provider UUID is invalid",
            ))?,
            description: String::from("Software provider that implements only administrative (i.e. no cryptographic) operations"),
            vendor: String::new(),
            version_maj: crate_version.major,
            version_min: crate_version.minor,
            version_rev: crate_version.patch,
            id: ProviderID::Core,
        });

        let core_provider = Provider {
            wire_protocol_version_maj: self
                .version_maj
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version maj is missing"))?,
            wire_protocol_version_min: self
                .version_min
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version min is missing"))?,
            provider_opcodes,
            provider_info: provider_info_vec,
            authenticator_info: self.authenticator_info,
            prov_list: self.prov_list,
        };

        Ok(core_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let provider = Provider {
            wire_protocol_version_min: 8,
            wire_protocol_version_maj: 10,
            provider_info: Vec::new(),
            authenticator_info: Vec::new(),
            provider_opcodes: HashMap::new(),
            prov_list: Vec::new(),
        };
        let op = ping::Operation {};
        let result = provider.ping(op).unwrap();
        assert_eq!(
            result.wire_protocol_version_maj,
            provider.wire_protocol_version_maj
        );
        assert_eq!(
            result.wire_protocol_version_min,
            provider.wire_protocol_version_min
        );
    }
}
