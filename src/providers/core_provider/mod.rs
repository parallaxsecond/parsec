// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core information source for the service
//!
//! The core provider acts as a source of information for the Parsec service,
//! aiding clients in discovering the capabilities offered by their underlying
//! platform.
use super::Provide;
use log::error;
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{list_opcodes, list_providers, ping};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
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
    providers: Vec<ProviderInfo>,
}

impl Provide for CoreProvider {
    fn list_opcodes(&self, _op: list_opcodes::Operation) -> Result<list_opcodes::Result> {
        Ok(list_opcodes::Result {
            opcodes: SUPPORTED_OPCODES.iter().copied().collect(),
        })
    }

    fn list_providers(&self, _op: list_providers::Operation) -> Result<list_providers::Result> {
        Ok(list_providers::Result {
            providers: self.providers.clone(),
        })
    }

    fn describe(&self) -> Result<ProviderInfo> {
        let crate_version: Version = Version::from_str(version!()).or_else(|e| {
            error!("Error parsing the crate version: {}.", e);
            Err(ResponseStatus::InvalidEncoding)
        })?;

        Ok(ProviderInfo {
            // Assigned UUID for this provider: 47049873-2a43-4845-9d72-831eab668784
            uuid: Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("Software provider that implements only administrative (i.e. no cryptographic) operations"),
            vendor: String::new(),
            version_maj: crate_version.major,
            version_min: crate_version.minor,
            version_rev: crate_version.patch,
            id: ProviderID::Core,
        })
    }

    fn ping(&self, _op: ping::Operation) -> Result<ping::Result> {
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
    providers: Option<Vec<ProviderInfo>>,
}

impl CoreProviderBuilder {
    pub fn new() -> Self {
        CoreProviderBuilder {
            version_maj: None,
            version_min: None,
            providers: None,
        }
    }

    pub fn with_wire_protocol_version(mut self, version_min: u8, version_maj: u8) -> Self {
        self.version_maj = Some(version_maj);
        self.version_min = Some(version_min);

        self
    }

    pub fn with_provider_info(mut self, provider_info: ProviderInfo) -> Self {
        match self.providers {
            Some(mut providers) => {
                providers.push(provider_info);
                self.providers = Some(providers);
            }
            None => {
                let mut providers = Vec::new();
                providers.push(provider_info);
                self.providers = Some(providers);
            }
        }

        self
    }

    pub fn build(self) -> std::io::Result<CoreProvider> {
        let mut core_provider = CoreProvider {
            wire_protocol_version_maj: self
                .version_maj
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version maj is missing"))?,
            wire_protocol_version_min: self
                .version_min
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "version min is missing"))?,
            providers: self
                .providers
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "provider info is missing"))?,
        };

        core_provider
            .providers
            .push(core_provider.describe().or_else(|_| {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "error describing Core provider",
                ))
            })?);

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
            providers: Vec::new(),
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
