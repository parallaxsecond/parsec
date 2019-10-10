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

// These functions test for the service persistency to shutdown. They will be executed before the
// service is shutdown and before the persistent_after tests are executed.
#[cfg(test)]
mod tests {
    use parsec_client_test::TestClient;
    use parsec_interface::requests::Result;

    const HASH: [u8; 32] = [
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0x37, 0x78,
    ];

    #[test]
    fn create_and_verify() -> Result<()> {
        let mut client = TestClient::new();
        client.do_not_destroy_keys();

        let key_name = String::from("🤡 Clown's Master Key 🤡");
        client.create_rsa_sign_key(key_name.clone())?;
        let signature = client.sign(key_name.clone(), HASH.to_vec())?;

        client.verify(key_name.clone(), HASH.to_vec(), signature)
    }
}
