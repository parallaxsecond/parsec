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
    use interface::operations::{ConvertOperation, OpAsymSign, OpCreateKey, OpDestroyKey};
    use interface::requests::ProviderID;
    use interface::requests::ResponseStatus;
    use minimal_client::MinimalClient;

    #[test]
    fn create_and_destroy() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);

        let create_key = OpCreateKey {
            key_name: String::from("create_and_destroy"),
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
            .send_operation(ConvertOperation::CreateKey(create_key))
            .unwrap();

        let destroy_key = OpDestroyKey {
            key_name: String::from("create_and_destroy"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .unwrap();
    }

    #[test]
    fn create_twice() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);

        let create_key = OpCreateKey {
            key_name: String::from("create_twice"),
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
        let status = client
            .send_operation(ConvertOperation::CreateKey(create_key))
            .expect_err("A key with the same name can not be created twice.");
        assert_eq!(status, ResponseStatus::KeyAlreadyExists);

        let destroy_key = OpDestroyKey {
            key_name: String::from("create_twice"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .unwrap();
    }

    #[test]
    fn destroy_without_create() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);

        let destroy_key = OpDestroyKey {
            key_name: String::from("destroy_without_create"),
            key_lifetime: KeyLifetime::Persistent,
        };
        let status = client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .expect_err("The key should not already exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn create_destroy_and_operation() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);

        let create_key = OpCreateKey {
            key_name: String::from("create_destroy_and_operation"),
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
            .send_operation(ConvertOperation::CreateKey(create_key))
            .unwrap();

        let destroy_key = OpDestroyKey {
            key_name: String::from("create_destroy_and_operation"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key))
            .unwrap();

        let asym_sign = OpAsymSign {
            key_name: String::from("create_destroy_and_operation"),
            key_lifetime: KeyLifetime::Persistent,
            hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let status = client
            .send_operation(ConvertOperation::AsymSign(asym_sign))
            .expect_err("The key used by this operation should have been deleted.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn create_destroy_twice() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);

        let create_key_1 = OpCreateKey {
            key_name: String::from("create_destroy_twice_1"),
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
        let mut create_key_2 = create_key_1.clone();
        create_key_2.key_name = String::from("create_destroy_twice_2");
        client
            .send_operation(ConvertOperation::CreateKey(create_key_1))
            .unwrap();
        client
            .send_operation(ConvertOperation::CreateKey(create_key_2))
            .unwrap();

        let destroy_key_1 = OpDestroyKey {
            key_name: String::from("create_destroy_twice_1"),
            key_lifetime: KeyLifetime::Persistent,
        };
        let mut destroy_key_2 = destroy_key_1.clone();
        destroy_key_2.key_name = String::from("create_destroy_twice_2");
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key_1))
            .unwrap();
        client
            .send_operation(ConvertOperation::DestroyKey(destroy_key_2))
            .unwrap();
    }
}
