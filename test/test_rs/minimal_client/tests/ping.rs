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
    use interface::operations::{ConvertOperation, ConvertResult, OpPing};
    use interface::requests::request::RequestBody;
    use minimal_client::MinimalClient;

    #[test]
    fn test_ping() {
        let mut client = MinimalClient::new();
        let ping = OpPing {};
        let result = client.process_operation(ConvertOperation::Ping(ping));
        let ConvertResult::Ping(ping_result) = result;
        assert!(ping_result.supp_version_maj == 1);
        assert!(ping_result.supp_version_min == 0);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mangled_ping() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.set_body(RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]));

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
    }
}
