// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::Hash;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus, Result};

const MESSAGE: [u8; 14] = [
    0x49, 0x20, 0x61, 0x6d, 0x20, 0x61, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
];
const SHA_256: [u8; 32] = [
    0x0d, 0xc4, 0xbc, 0x13, 0xfd, 0x91, 0x74, 0x52, 0x92, 0x24, 0xc3, 0x8e, 0x0e, 0xe0, 0x75, 0xfa,
    0x9e, 0xd8, 0x0b, 0x78, 0x47, 0xe6, 0xae, 0xa7, 0x6a, 0xe9, 0x8c, 0xf9, 0xdd, 0xd9, 0x26, 0x69,
];

#[test]
fn hash_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompute) {
        assert_eq!(
            client.hash_compute(Hash::Sha256, &[],).unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        assert_eq!(
            client.hash_compare(Hash::Sha256, &[], &[]).unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

#[test]
fn hash_compute_sha256() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompute) {
        return;
    }

    let hash = client.hash_compute(Hash::Sha256, &MESSAGE).unwrap();
    assert_eq!(&SHA_256[..], hash.as_slice())
}

#[test]
fn hash_compare_sha256() -> Result<()> {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        return Ok(());
    }

    client.hash_compare(Hash::Sha256, &MESSAGE, &SHA_256)
}

#[test]
fn hash_compare_false() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        return;
    }

    let _ = client
        .hash_compare(Hash::Sha512, &MESSAGE, &SHA_256)
        .unwrap_err();
}
