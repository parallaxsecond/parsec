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
    use parsec_interface::requests::Result;
    use std::collections::HashSet;

    //TODO: put those two first tests in a separate target which is executed with an
    //appropriate config file so that all providers are there.

    #[test]
    #[ignore]
    fn list_providers() {
        let mut client = TestClient::new();
        let providers = client.list_providers().expect("list providers failed");
        assert_eq!(providers.len(), 3);
        let ids: HashSet<ProviderID> = providers.iter().map(|p| p.id).collect();
        assert!(ids.contains(&ProviderID::CoreProvider));
        assert!(ids.contains(&ProviderID::MbedProvider));
        assert!(ids.contains(&ProviderID::Pkcs11Provider));
    }

    #[test]
    #[ignore]
    fn list_opcodes() {
        let mut client = TestClient::new();
        client.set_provider(Some(ProviderID::MbedProvider));
        let opcodes = client
            .list_opcodes(ProviderID::MbedProvider)
            .expect("list providers failed");
        assert_eq!(opcodes.len(), 7);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mangled_list_providers() {
        let mut client = RequestTestClient::new();
        let mut req = Request::new();
        req.header.version_maj = 1;
        req.header.provider = ProviderID::CoreProvider;
        req.header.opcode = Opcode::ListProviders;

        req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        let resp = client.send_request(req).expect("Failed to read response");
        assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
    }

    #[test]
    fn sign_verify_with_provider_discovery() -> Result<()> {
        let mut client = TestClient::new();
        let key_name = String::from("sign_verify_with_provider_discovery");
        client.create_rsa_sign_key(key_name.clone())
    }
}
