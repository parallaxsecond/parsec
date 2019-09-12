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
    use interface::operations::{NativeOperation, NativeResult, OpPing};
    use interface::requests::request::{Request, RequestBody};
    use interface::requests::Opcode;
    use interface::requests::ProviderID;
    use interface::requests::ResponseStatus;
    use minimal_client::MinimalClient;

    #[test]
    fn test_ping() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let ping = OpPing {};
        let result = client
            .send_operation(NativeOperation::Ping(ping))
            .expect("ping failed");
        if let NativeResult::Ping(ping_result) = result {
            assert!(ping_result.supp_version_maj == 1);
            assert!(ping_result.supp_version_min == 0);
        } else {
            panic!("Got wrong type of result!");
        }
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mangled_ping() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();
        req.header.version_maj = 1;
        req.header.provider = ProviderID::CoreProvider;
        req.header.opcode = Opcode::Ping;

        req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        let resp = client.send_request(req);
        assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
    }
}
