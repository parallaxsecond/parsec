// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core information source for the service
//!
//! The core provider acts as a source of information for the Parsec service,
//! aiding clients in discovering the capabilities offered by their underlying
//! platform.
use super::Provide;
use log::trace;
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{list_opcodes, list_providers, ping};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use uuid::Uuid;
use version::{version, Version};

const SUPPORTED_OPCODES: [Opcode; 3] = [Opcode::ListProviders, Opcode::ListOpcodes, Opcode::Ping];

/// Service information provider
///
/// The core provider is a non-cryptographic provider tasked with offering
/// structured information about the status of the service and the providers
/// available.
#[derive(Debug)]
pub struct CoreProvider {
    wire_protocol_version_min: u8,
    wire_protocol_version_maj: u8,
    provider_info: Vec<ProviderInfo>,
    provider_opcodes: HashMap<ProviderID, HashSet<Opcode>>,
}

impl Provide for CoreProvider {
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

    fn ping(&self, _op: ping::Operation) -> Result<ping::Result> {
        trace!("ping ingress");
        let result = ping::Result {
            wire_protocol_version_maj: self.wire_protocol_version_maj,
            wire_protocol_version_min: self.wire_protocol_version_min,
        };

        Ok(result)
    }
}

/// Builder for CoreProvider
#[derive(Debug, Default)]
pub struct CoreProviderBuilder {
    version_maj: Option<u8>,
    version_min: Option<u8>,
    provider_info: Vec<ProviderInfo>,
    provider_opcodes: HashMap<ProviderID, HashSet<Opcode>>,
}

impl CoreProviderBuilder {
    pub fn new() -> Self {
        let mut provider_opcodes = HashMap::new();
        let _ = provider_opcodes.insert(
            ProviderID::Core,
            SUPPORTED_OPCODES.iter().copied().collect(),
        );

        CoreProviderBuilder {
            version_maj: None,
            version_min: None,
            provider_info: Vec::new(),
            provider_opcodes,
        }
    }

    pub fn with_wire_protocol_version(mut self, version_min: u8, version_maj: u8) -> Self {
        self.version_maj = Some(version_maj);
        self.version_min = Some(version_min);

        self
    }

    pub fn with_provider_details(
        mut self,
        provider_info: ProviderInfo,
        opcodes: HashSet<Opcode>,
    ) -> Self {
        let _ = self.provider_opcodes.insert(provider_info.id, opcodes);
        self.provider_info.push(provider_info);

        self
    }

    pub fn build(mut self) -> std::io::Result<CoreProvider> {
        let crate_version: Version = Version::from_str(version!()).map_err(|e| {
            format_error!("Error parsing the crate version", e);
            Error::new(
                ErrorKind::InvalidData,
                "crate version number has invalid format",
            )
        })?;
        self.provider_info.push(ProviderInfo {
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

        let core_provider = CoreProvider {
            wire_protocol_version_maj: self
                .version_maj
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version maj is missing"))?,
            wire_protocol_version_min: self
                .version_min
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version min is missing"))?,
            provider_opcodes: self.provider_opcodes,
            provider_info: self.provider_info,
        };

        Ok(core_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let provider = CoreProvider {
            wire_protocol_version_min: 8,
            wire_protocol_version_maj: 10,
            provider_info: Vec::new(),
            provider_opcodes: HashMap::new(),
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
