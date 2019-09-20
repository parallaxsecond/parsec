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
use interface::operations::ProviderInfo;
use interface::operations::{OpListProviders, ResultListProviders};
use interface::operations::{OpPing, ResultPing};
use interface::requests::{ProviderID, Result};

pub struct CoreProvider {
    version_min: u8,
    version_maj: u8,
    providers: Vec<ProviderInfo>,
}

impl Provide for CoreProvider {
    fn list_providers(&self, _op: OpListProviders) -> Result<ResultListProviders> {
        Ok(ResultListProviders {
            providers: self.providers.clone(),
        })
    }

    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            id: ProviderID::CoreProvider,
            description: String::from("Software provider that implements only administrative (i.e. no cryptographic) operations"),
        }
    }

    fn ping(&self, _op: OpPing) -> Result<ResultPing> {
        let result = ResultPing {
            supp_version_maj: self.version_maj,
            supp_version_min: self.version_min,
        };

        Ok(result)
    }
}

#[derive(Default)]
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

    pub fn with_version(mut self, version_min: u8, version_maj: u8) -> Self {
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

    pub fn build(self) -> CoreProvider {
        let mut core_provider = CoreProvider {
            version_maj: self.version_maj.expect("Version Maj missing"),
            version_min: self.version_min.expect("Version Min missing"),
            providers: self.providers.expect("Providers info is missing"),
        };

        core_provider.providers.push(core_provider.describe());

        core_provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let provider = CoreProvider {
            version_min: 8,
            version_maj: 10,
            providers: Vec::new(),
        };
        let op = OpPing {};
        let result = provider.ping(op).unwrap();
        assert_eq!(result.supp_version_maj, provider.version_maj);
        assert_eq!(result.supp_version_min, provider.version_min);
    }
}
