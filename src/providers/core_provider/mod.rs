// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use super::Provide;
use log::error;
use parsec_interface::operations::ProviderInfo;
use parsec_interface::operations::{OpListOpcodes, ResultListOpcodes};
use parsec_interface::operations::{OpListProviders, ResultListProviders};
use parsec_interface::operations::{OpPing, ResultPing};
use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use uuid::Uuid;
use version::{version, Version};

const SUPPORTED_OPCODES: [Opcode; 3] = [Opcode::ListProviders, Opcode::ListOpcodes, Opcode::Ping];

#[derive(Debug)]
pub struct CoreProvider {
    wire_protocol_version_min: u8,
    wire_protocol_version_maj: u8,
    providers: Vec<ProviderInfo>,
}

impl Provide for CoreProvider {
    fn list_opcodes(&self, _op: OpListOpcodes) -> Result<ResultListOpcodes> {
        Ok(ResultListOpcodes {
            opcodes: SUPPORTED_OPCODES.iter().copied().collect(),
        })
    }

    fn list_providers(&self, _op: OpListProviders) -> Result<ResultListProviders> {
        Ok(ResultListProviders {
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
            id: ProviderID::CoreProvider,
        })
    }

    fn ping(&self, _op: OpPing) -> Result<ResultPing> {
        let result = ResultPing {
            supp_version_maj: self.wire_protocol_version_maj,
            supp_version_min: self.wire_protocol_version_min,
        };

        Ok(result)
    }
}

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
        let op = OpPing {};
        let result = provider.ping(op).unwrap();
        assert_eq!(result.supp_version_maj, provider.wire_protocol_version_maj);
        assert_eq!(result.supp_version_min, provider.wire_protocol_version_min);
    }
}
