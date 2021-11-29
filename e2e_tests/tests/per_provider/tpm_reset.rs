// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// These tests track a potential regression where the TPM provider
// was unable to handle stored keys after a TPM reset.
//
// `before_tpm_reset` creates keys that should be usable post-TPM-reset,
// in `after_tpm_reset`.
//
// See: https://github.com/parallaxsecond/parsec/issues/504
use e2e_tests::TestClient;

const RSA_KEY_NAME: &str = "tpm-reset-rsa";
const ECC_KEY_NAME: &str = "tpm-reset-ecc";

#[test]
fn before_tpm_reset() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();

    let rsa_key_name = String::from(RSA_KEY_NAME);
    let ecc_key_name = String::from(ECC_KEY_NAME);

    client.generate_rsa_sign_key(rsa_key_name).unwrap();
    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(ecc_key_name)
        .unwrap();
}

#[test]
fn after_tpm_reset() {
    let mut client = TestClient::new();

    let rsa_key_name = String::from(RSA_KEY_NAME);
    let ecc_key_name = String::from(ECC_KEY_NAME);

    let _ = client
        .sign_with_rsa_sha256(rsa_key_name, vec![0xff; 32])
        .unwrap();
    let _ = client
        .sign_with_ecdsa_sha256(ecc_key_name, vec![0xff; 32])
        .unwrap();
}
