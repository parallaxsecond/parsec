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
    use interface::operations::key_attributes::*;
    use interface::operations::{ConvertOperation, OpCreateKey, OpDestroyKey};
    use interface::requests::request::RequestAuth;
    use interface::requests::response::ResponseStatus;
    use interface::requests::ProviderID;
    use minimal_client::MinimalClient;

    #[test]
    fn two_auths_same_key_name() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        client.auth(RequestAuth::from_bytes(
            String::from("first_client").into_bytes(),
        ));

        let create_key = OpCreateKey {
            key_name: String::from("two_auths_same_key_name"),
            key_attributes: KeyAttributes {
                key_lifetime: KeyLifetime::Persistent,
                key_type: KeyType::RsaKeypair,
                ecc_curve: None,
                algorithm: Algorithm::sign(SignAlgorithm::RsaPkcs1v15Sign, None),
                key_size: 1024,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
        };
        client
            .send_operation(ConvertOperation::CreateKey(create_key.clone()))
            .unwrap();

        client.auth(RequestAuth::from_bytes(
            String::from("second_client").into_bytes(),
        ));
        client
            .send_operation(ConvertOperation::CreateKey(create_key))
            .unwrap();

        client.auth(RequestAuth::from_bytes(
            String::from("first_client").into_bytes(),
        ));
        let destroy_key = OpDestroyKey {
            key_name: String::from("two_auths_same_key_name"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key.clone()))
            .unwrap();

        client.auth(RequestAuth::from_bytes(
            String::from("second_client").into_bytes(),
        ));
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key.clone()))
            .unwrap();
    }

    #[test]
    fn delete_wrong_key() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        client.auth(RequestAuth::from_bytes(
            String::from("first_client").into_bytes(),
        ));

        let create_key = OpCreateKey {
            key_name: String::from("delete_wrong_key"),
            key_attributes: KeyAttributes {
                key_lifetime: KeyLifetime::Persistent,
                key_type: KeyType::RsaKeypair,
                ecc_curve: None,
                algorithm: Algorithm::sign(SignAlgorithm::RsaPkcs1v15Sign, None),
                key_size: 1024,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
        };
        client
            .send_operation(ConvertOperation::CreateKey(create_key.clone()))
            .unwrap();

        client.auth(RequestAuth::from_bytes(
            String::from("second_client").into_bytes(),
        ));
        let destroy_key = OpDestroyKey {
            key_name: String::from("delete_wrong_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        let status = client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .expect_err("Key should not exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);

        client.auth(RequestAuth::from_bytes(
            String::from("first_client").into_bytes(),
        ));
        let destroy_key = OpDestroyKey {
            key_name: String::from("delete_wrong_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .unwrap();
    }
}
