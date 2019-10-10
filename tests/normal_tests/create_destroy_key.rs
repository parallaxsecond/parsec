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
    use parsec_client_test::TestClient;
    use parsec_interface::requests::{ResponseStatus, Result};

    #[test]
    fn create_and_destroy() -> Result<()> {
        let mut client = TestClient::new();
        let key_name = String::from("create_and_destroy");

        client.create_rsa_sign_key(key_name.clone())?;

        client.destroy_key(key_name)
    }

    #[test]
    fn create_twice() -> Result<()> {
        let mut client = TestClient::new();
        let key_name = String::from("create_twice");

        client.create_rsa_sign_key(key_name.clone())?;
        let status = client
            .create_rsa_sign_key(key_name.clone())
            .expect_err("A key with the same name can not be created twice.");
        assert_eq!(status, ResponseStatus::KeyAlreadyExists);

        Ok(())
    }

    #[test]
    fn destroy_without_create() {
        let mut client = TestClient::new();
        let key_name = String::from("destroy_without_create");

        let status = client
            .destroy_key(key_name)
            .expect_err("The key should not already exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn create_destroy_and_operation() -> Result<()> {
        let mut client = TestClient::new();
        let hash = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let key_name = String::from("create_destroy_and_operation");

        client.create_rsa_sign_key(key_name.clone())?;

        client.destroy_key(key_name.clone())?;

        let status = client
            .sign(key_name, hash)
            .expect_err("The key used by this operation should have been deleted.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);

        Ok(())
    }

    #[test]
    fn create_destroy_twice() -> Result<()> {
        let mut client = TestClient::new();
        let key_name = String::from("create_destroy_twice_1");
        let key_name_2 = String::from("create_destroy_twice_2");

        client.create_rsa_sign_key(key_name.clone())?;
        client.create_rsa_sign_key(key_name_2.clone())?;

        client.destroy_key(key_name)?;
        client.destroy_key(key_name_2)
    }
}
