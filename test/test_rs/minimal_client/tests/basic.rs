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
    use interface::operations::{ConvertOperation, OpPing};
    use minimal_client::MinimalClient;

    #[test]
    fn invalid_version() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.version_maj = 0xff;

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
        assert_eq!(resp.header.opcode, 0);
    }

    #[test]
    fn invalid_provider() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.provider = 0xff;

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
        assert_eq!(resp.header.opcode, 0);
    }

    #[test]
    fn invalid_content_type() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.content_type = 0xff;

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
        assert_eq!(resp.header.opcode, 0);
    }

    #[test]
    fn invalid_accept_type() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.content_type = 0xff;

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
        assert_eq!(resp.header.opcode, 0);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn invalid_body_len() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.set_body_len(0xff_ff);

        client.process_req_no_resp(req);

        let mut client = MinimalClient::new();
        client.process_operation(ConvertOperation::Ping(OpPing {}));
    }

    #[cfg(feature = "testing")]
    #[test]
    fn invalid_auth_len() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.set_auth_len(0xff_ff);

        client.process_req_no_resp(req);

        let mut client = MinimalClient::new();
        client.process_operation(ConvertOperation::Ping(OpPing {}));
    }

    #[test]
    fn invalid_opcode() {
        let mut client = MinimalClient::new();
        let mut req = client.req_from_op(ConvertOperation::Ping(OpPing {}));

        req.header.opcode = 0xff_ff;

        let resp = client.process_request(req);
        assert!(resp.header.status != 0);
    }
}
