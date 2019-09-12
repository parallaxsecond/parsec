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
    use interface::operations::{
        NativeOperation, NativeResult, OpAsymSign, OpAsymVerify, OpCreateKey, OpDestroyKey,
    };
    use interface::requests::ProviderID;
    use interface::requests::ResponseStatus;
    use minimal_client::MinimalClient;

    #[test]
    fn asym_sign_no_key() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let asym_sign = OpAsymSign {
            key_name: String::from("asym_sign_no_key"),
            key_lifetime: KeyLifetime::Persistent,
            hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let status = client
            .send_operation(NativeOperation::AsymSign(asym_sign))
            .expect_err("Key should not exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn asym_verify_no_key() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let asym_verify = OpAsymVerify {
            key_name: String::from("asym_verify_no_key"),
            key_lifetime: KeyLifetime::Persistent,
            hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let status = client
            .send_operation(NativeOperation::AsymVerify(asym_verify))
            .expect_err("Key should not exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn asym_sign_and_verify() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let create_key = OpCreateKey {
            key_name: String::from("asym_sign_and_verify"),
            key_attributes: KeyAttributes {
                key_lifetime: KeyLifetime::Persistent,
                key_type: KeyType::RsaKeypair,
                ecc_curve: None,
                algorithm: Algorithm::sign(
                    SignAlgorithm::RsaPkcs1v15Sign,
                    Some(HashAlgorithm::Sha256),
                ),
                key_size: 1024,
                permit_sign: true,
                permit_verify: true,
                permit_export: false,
                permit_derive: false,
                permit_encrypt: false,
                permit_decrypt: false,
            },
        };
        client
            .send_operation(NativeOperation::CreateKey(create_key))
            .unwrap();

        let hash = vec![
            0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37,
            0x84, 0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18,
            0xE8, 0x81, 0x37, 0x78,
        ];
        let asym_sign = OpAsymSign {
            key_name: String::from("asym_sign_and_verify"),
            key_lifetime: KeyLifetime::Persistent,
            hash: hash.clone(),
        };
        let convert_result = client
            .send_operation(NativeOperation::AsymSign(asym_sign))
            .unwrap();
        if let NativeResult::AsymSign(result) = convert_result {
            let signature = result.signature;
            let asym_verify = OpAsymVerify {
                key_name: String::from("asym_sign_and_verify"),
                key_lifetime: KeyLifetime::Persistent,
                hash,
                signature,
            };
            client
                .send_operation(NativeOperation::AsymVerify(asym_verify))
                .unwrap();
        }

        let destroy_key = OpDestroyKey {
            key_name: String::from("asym_sign_and_verify"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(NativeOperation::DestroyKey(destroy_key))
            .unwrap();
    }
}
