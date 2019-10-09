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
    use parsec_client_test::RequestTestClient;
    use parsec_client_test::TestClient;
    use parsec_interface::requests::request::RawHeader;
    use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus};

    #[test]
    fn invalid_version() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 0xff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::VersionTooBig);
        assert_eq!(resp.header.opcode, Opcode::Ping);
    }

    #[test]
    fn invalid_provider() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = 0xff;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 0xff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::ProviderDoesNotExist);
        assert_eq!(resp.header.opcode, Opcode::Ping);
    }

    #[test]
    fn invalid_content_type() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 1;
        req_hdr.content_type = 0xff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::ContentTypeNotSupported);
        assert_eq!(resp.header.opcode, Opcode::Ping);
    }

    #[test]
    fn invalid_accept_type() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 1;

        req_hdr.accept_type = 0xff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::AcceptTypeNotSupported);
        assert_eq!(resp.header.opcode, Opcode::Ping);
    }

    #[test]
    fn invalid_body_len() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 1;

        req_hdr.body_len = 0xff_ff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::ConnectionError);
    }

    #[test]
    fn invalid_auth_len() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = Opcode::Ping as u16;
        req_hdr.version_maj = 1;

        req_hdr.auth_len = 0xff_ff;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::ConnectionError);
    }

    #[test]
    fn invalid_opcode() {
        let mut client = RequestTestClient::new();
        let mut req_hdr = RawHeader::new();

        req_hdr.provider = ProviderID::CoreProvider as u8;
        req_hdr.opcode = 0xff_ff;
        req_hdr.version_maj = 1;

        let resp = client
            .send_raw_request(req_hdr, Vec::new())
            .expect("Failed to read Response");
        assert_eq!(resp.header.status, ResponseStatus::OpcodeDoesNotExist);
    }

    #[test]
    fn wrong_provider_core() {
        let mut client = TestClient::new();
        client.set_provider(Some(ProviderID::CoreProvider));

        let response_status = client
            .destroy_key(String::new())
            .expect_err("Core Provider should not support DestroyKey operation!");
        assert_eq!(response_status, ResponseStatus::UnsupportedOperation);
    }
}
