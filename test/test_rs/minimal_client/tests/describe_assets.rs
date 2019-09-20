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
#[cfg(test)]
mod tests {
    use interface::operations::{NativeOperation, NativeResult, OpListOpcodes, OpListProviders};
    use interface::requests::request::{Request, RequestBody};
    use interface::requests::Opcode;
    use interface::requests::ProviderID;
    use interface::requests::ResponseStatus;
    use minimal_client::MinimalClient;
    use std::collections::HashSet;

    #[test]
    fn list_providers() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let list_providers = OpListProviders {};
        let result = client
            .send_operation(NativeOperation::ListProviders(list_providers))
            .expect("list providers failed");
        if let NativeResult::ListProviders(list_result) = result {
            assert_eq!(list_result.providers.len(), 2);
            let mut ids: HashSet<ProviderID> = HashSet::new();
            ids.insert(list_result.providers[0].id);
            ids.insert(list_result.providers[1].id);
            assert!(ids.contains(&ProviderID::CoreProvider));
            assert!(ids.contains(&ProviderID::MbedProvider));
        } else {
            panic!("Got wrong type of result!");
        }
    }

    #[test]
    fn list_opcodes() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let list_opcodes = OpListOpcodes {};
        let result = client
            .send_operation(NativeOperation::ListOpcodes(list_opcodes))
            .expect("list providers failed");
        if let NativeResult::ListOpcodes(list_result) = result {
            assert_eq!(list_result.opcodes.len(), 7);
        } else {
            panic!("Got wrong type of result!");
        }
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mangled_list_providers() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();
        req.header.version_maj = 1;
        req.header.provider = ProviderID::CoreProvider;
        req.header.opcode = Opcode::ListProviders;

        req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        let resp = client.send_request(req);
        assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
    }
}
