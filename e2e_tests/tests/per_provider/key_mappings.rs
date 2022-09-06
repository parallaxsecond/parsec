// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::TestClient;
use parsec_client::core::interface::requests::Result;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

const PLAINTEXT_MESSAGE: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

// This test tries to use the keys created in the Docker image via the generate-keys.sh script.
// Each provider has a "ecc" and "rsa" key created by the Parsec Tool.
// The ci.sh script also adds fake mappings (mappings which do not link to an existing key) in all
// providers except the TPM one (as for this provider the mapping IS the key).

#[test]
fn use_and_check() -> Result<()> {
    let mut client = TestClient::new();

    client.set_default_auth(Some(String::from("parsec-tool")));

    let keys = client.list_keys()?;
    assert!(!keys.is_empty());

    for key in keys {
        if key.name.contains("rsa") {
            let ciphertext = client
                .asymmetric_encrypt_message_with_rsapkcs1v15(
                    key.name.clone(),
                    PLAINTEXT_MESSAGE.to_vec(),
                )
                .unwrap();
            let plaintext = client
                .asymmetric_decrypt_message_with_rsapkcs1v15(key.name.clone(), ciphertext)
                .unwrap();
            assert_eq!(PLAINTEXT_MESSAGE.to_vec(), plaintext);
        } else if key.name.contains("ecc") {
            let signature = client.sign_with_ecdsa_sha256(key.name.clone(), HASH.to_vec())?;
            client.verify_with_ecdsa_sha256(key.name.clone(), HASH.to_vec(), signature)?;
        } else {
            // If another key than "ecc" or "rsa" is read, it means that the fake mapping was not
            // deleted by the provider and this is an error.
            panic!(
                "The key {} should have been deleted as a fake mapping was created for it.",
                key.name
            );
        }

        if client.is_operation_supported(Opcode::PsaExportKey) {
            assert_eq!(
                client.export_key(key.name.clone()).unwrap_err(),
                ResponseStatus::PsaErrorNotPermitted
            );
        }
    }

    Ok(())
}
