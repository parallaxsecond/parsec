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
    use interface::requests::request::{Request, RequestBody};
    use interface::requests::Opcode;
    use interface::requests::ProviderID;
    use interface::requests::{ResponseStatus, Result};
    use minimal_client::RequestTestClient;
    use minimal_client::TestClient;

    #[test]
    fn test_ping() -> Result<()> {
        let mut client = TestClient::new();
        let version = client.ping(ProviderID::CoreProvider)?;
        assert_eq!(version.0, 0);
        assert_eq!(version.1, 1);

        Ok(())
    }

    #[test]
    fn mangled_ping() {
        let mut client = RequestTestClient::new();
        let mut req = Request::new();
        req.header.version_maj = 1;
        req.header.provider = ProviderID::CoreProvider;
        req.header.opcode = Opcode::Ping;

        req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        let resp = client.send_request(req).expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
    }
}
