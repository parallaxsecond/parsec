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
    use interface::operations::{
        key_attributes::KeyLifetime, ConvertOperation, OpDestroyKey, OpPing,
    };
    use interface::requests::{request::Request, response::ResponseStatus, Opcode, ProviderID};
    use minimal_client::MinimalClient;

    #[test]
    fn invalid_version() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 0xff;

        let resp = client.send_request(req);
        assert_eq!(resp.header.status(), ResponseStatus::VersionTooBig);
        assert_eq!(resp.header.opcode(), Opcode::Ping);
    }

    #[test]
    fn invalid_provider() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = 0xff;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 0xff;

        let resp = client.send_request(req);
        assert_eq!(resp.header.status(), ResponseStatus::ProviderDoesNotExist);
        assert_eq!(resp.header.opcode(), Opcode::Ping);
    }

    #[test]
    fn invalid_content_type() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 1;
        req.header.content_type = 0xff;

        let resp = client.send_request(req);
        assert_eq!(
            resp.header.status(),
            ResponseStatus::ContentTypeNotSupported
        );
        assert_eq!(resp.header.opcode(), Opcode::Ping);
    }

    #[test]
    fn invalid_accept_type() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 1;

        req.header.accept_type = 0xff;

        let resp = client.send_request(req);
        assert_eq!(resp.header.status(), ResponseStatus::AcceptTypeNotSupported);
        assert_eq!(resp.header.opcode(), Opcode::Ping);
    }

    #[cfg(feature = "testing")]
    #[test]
    #[should_panic]
    fn invalid_body_len() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 1;

        req.header.set_body_len(0xff_ff);

        client.send_request(req);
    }

    #[cfg(feature = "testing")]
    #[test]
    #[should_panic]
    fn invalid_auth_len() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = Opcode::Ping as u16;
        req.header.version_maj = 1;

        req.header.set_auth_len(0xff_ff);

        client.send_request(req);
    }

    #[test]
    fn invalid_opcode() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);
        let mut req = Request::new();

        req.header.provider = ProviderID::CoreProvider as u8;
        req.header.opcode = 0xff_ff;
        req.header.version_maj = 1;

        let resp = client.send_request(req);
        assert_eq!(resp.header.status(), ResponseStatus::OpcodeDoesNotExist);
    }

    #[test]
    fn wrong_provider_mbed() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let ping = OpPing {};
        let response_status = match client.send_operation(ConvertOperation::Ping(ping)) {
            Ok(_) => panic!("Mbed Provider should not support Ping operation!"),
            Err(response_status) => response_status,
        };
        assert_eq!(response_status, ResponseStatus::UnsupportedOperation);
    }

    #[test]
    fn wrong_provider_core() {
        let mut client = MinimalClient::new(ProviderID::CoreProvider);

        let op = OpDestroyKey {
            key_name: String::new(),
            key_lifetime: KeyLifetime::Persistent,
        };
        let response_status = match client.send_operation(ConvertOperation::DestroyKey(op)) {
            Ok(_) => panic!("Core Provider should not support DestroyKey operation!"),
            Err(response_status) => response_status,
        };
        assert_eq!(response_status, ResponseStatus::UnsupportedOperation);
    }
}
