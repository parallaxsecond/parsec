// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::RawKeyAgreement;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

const PEER_PUBLIC_KEY_SECPR1: [u8; 65] = [
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c,
    0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf,
    0x63, 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d,
    0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72,
    0xab,
];

const OUR_KEY_DATA_SECPR1: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];

const EXPECTED_OUTPUT_SECPR1: [u8; 32] = [
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde,
];

const OUR_KEY_DATA_BRAINPOOL_R1: [u8; 32] = [
    0x81, 0xdb, 0x1e, 0xe1, 0x00, 0x15, 0x0f, 0xf2, 0xea, 0x33, 0x8d, 0x70, 0x82, 0x71, 0xbe, 0x38,
    0x30, 0x0c, 0xb5, 0x42, 0x41, 0xd7, 0x99, 0x50, 0xf7, 0x7b, 0x06, 0x30, 0x39, 0x80, 0x4f, 0x1d,
];

const PEER_PUBLIC_KEY_BRAINPOOL_R1: [u8; 65] = [
    0x04, 0x8d, 0x2d, 0x68, 0x8c, 0x6c, 0xf9, 0x3e, 0x11, 0x60, 0xad, 0x04, 0xcc, 0x44, 0x29, 0x11,
    0x7d, 0xc2, 0xc4, 0x18, 0x25, 0xe1, 0xe9, 0xfc, 0xa0, 0xad, 0xdd, 0x34, 0xe6, 0xf1, 0xb3, 0x9f,
    0x7b, 0x99, 0x0c, 0x57, 0x52, 0x08, 0x12, 0xbe, 0x51, 0x26, 0x41, 0xe4, 0x70, 0x34, 0x83, 0x21,
    0x06, 0xbc, 0x7d, 0x3e, 0x8d, 0xd0, 0xe4, 0xc7, 0xf1, 0x13, 0x6d, 0x70, 0x06, 0x54, 0x7c, 0xec,
    0x6a,
];

const EXPECTED_OUTPUT_BRAINPOOL_R1: [u8; 32] = [
    0x89, 0xaf, 0xc3, 0x9d, 0x41, 0xd3, 0xb3, 0x27, 0x81, 0x4b, 0x80, 0x94, 0x0b, 0x04, 0x25, 0x90,
    0xf9, 0x65, 0x56, 0xec, 0x91, 0xe6, 0xae, 0x79, 0x39, 0xbc, 0xe3, 0x1f, 0x3a, 0x18, 0xbf, 0x2b,
];

#[test]
fn key_agreement_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaRawKeyAgreement) {
        assert_eq!(
            client
                .raw_key_agreement(
                    RawKeyAgreement::Ecdh,
                    String::from("some key"),
                    &PEER_PUBLIC_KEY_SECPR1
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

#[test]
fn simple_raw_key_agreement() {
    let key_name = String::from("simple_raw_key_agreement");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaRawKeyAgreement) {
        return;
    }

    client
        .generate_ecc_pair_secp_r1_key(key_name.clone())
        .unwrap();
    let _shared_secret = client
        .raw_key_agreement(RawKeyAgreement::Ecdh, key_name, &PEER_PUBLIC_KEY_SECPR1)
        .unwrap();
}

#[test]
fn raw_key_agreement_secpr1() {
    let key_name = String::from("raw_key_agreement_secpr1");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaRawKeyAgreement) {
        return;
    }

    client
        .import_ecc_pair_secp_r1_key(key_name.clone(), OUR_KEY_DATA_SECPR1.to_vec())
        .unwrap();
    let shared_secret = client
        .raw_key_agreement(RawKeyAgreement::Ecdh, key_name, &PEER_PUBLIC_KEY_SECPR1)
        .unwrap();

    assert_eq!(&EXPECTED_OUTPUT_SECPR1, shared_secret.as_slice());
}

#[test]
fn raw_key_agreement_brainpoolpr1() {
    let key_name = String::from("raw_key_agreement_brainpoolr1");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaRawKeyAgreement) {
        return;
    }

    client
        .import_ecc_pair_brainpoolpr1_key(key_name.clone(), OUR_KEY_DATA_BRAINPOOL_R1.to_vec())
        .unwrap();
    let shared_secret = client
        .raw_key_agreement(
            RawKeyAgreement::Ecdh,
            key_name,
            &PEER_PUBLIC_KEY_BRAINPOOL_R1,
        )
        .unwrap();

    assert_eq!(&EXPECTED_OUTPUT_BRAINPOOL_R1, shared_secret.as_slice());
}

#[test]
fn raw_key_agreement_two_generated_parties() {
    let key_name_1 = String::from("key_1");
    let key_name_2 = String::from("key_2");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaRawKeyAgreement) {
        return;
    }

    client
        .generate_ecc_pair_secp_r1_key(key_name_1.clone())
        .unwrap();
    client
        .generate_ecc_pair_secp_r1_key(key_name_2.clone())
        .unwrap();

    let public_key_1 = client.export_public_key(key_name_1.clone()).unwrap();
    let public_key_2 = client.export_public_key(key_name_2.clone()).unwrap();

    let shared_secret_1_then_2 = client
        .raw_key_agreement(RawKeyAgreement::Ecdh, key_name_1, &public_key_2)
        .unwrap();
    let shared_secret_2_then_1 = client
        .raw_key_agreement(RawKeyAgreement::Ecdh, key_name_2, &public_key_1)
        .unwrap();
    assert_eq!(shared_secret_1_then_2, shared_secret_2_then_1);
}
