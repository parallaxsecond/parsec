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
    use parsec_interface::requests::ProviderID;
    use parsec_interface::requests::{ResponseStatus, Result};

    #[test]
    fn two_auths_same_key_name() -> Result<()> {
        let key_name = String::from("two_auths_same_key_name");
        let mut client = TestClient::new();
        client.set_provider(Some(ProviderID::MbedProvider));
        let auth1 = String::from("first_client").into_bytes();
        let auth2 = String::from("second_client").into_bytes();

        client.set_auth(auth1.clone());
        client.create_rsa_sign_key(key_name.clone())?;

        client.set_auth(auth2.clone());
        client.create_rsa_sign_key(key_name.clone())
    }

    #[test]
    fn delete_wrong_key() -> Result<()> {
        let key_name = String::from("delete_wrong_key");
        let mut client = TestClient::new();
        client.set_provider(Some(ProviderID::MbedProvider));
        let auth1 = String::from("first_client").into_bytes();
        let auth2 = String::from("second_client").into_bytes();

        client.set_auth(auth1.clone());
        client.create_rsa_sign_key(key_name.clone())?;

        client.set_auth(auth2.clone());
        let status = client
            .destroy_key(key_name.clone())
            .expect_err("Destroying key should have failed");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);

        Ok(())
    }
}
