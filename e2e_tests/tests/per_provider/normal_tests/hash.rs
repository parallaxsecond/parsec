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
#[cfg(not(feature = "cryptoauthlib-provider"))]
const RIPE_MD160: [u8; 20] = [
    0xa6, 0xf1, 0xa8, 0xf5, 0x26, 0x04, 0x69, 0xb3, 0x67, 0xa3, 0xae, 0xc6, 0x9f, 0x73, 0x47, 0x9b,
    0xb7, 0xbd, 0x02, 0xb8,
];
#[cfg(not(feature = "cryptoauthlib-provider"))]
const SHA_512: [u8; 64] = [
    0x54, 0x1f, 0x9e, 0x85, 0xd4, 0xe6, 0xc2, 0x36, 0xf9, 0xb5, 0xef, 0x2e, 0x6d, 0x27, 0xd4, 0x97,
    0x56, 0xda, 0x00, 0xb2, 0x6e, 0xe2, 0x6f, 0xc8, 0x6a, 0x30, 0x47, 0xd3, 0x7f, 0x09, 0xbd, 0xe9,
    0x0a, 0x99, 0x14, 0xf7, 0x3d, 0xf6, 0xe7, 0x01, 0x1c, 0x97, 0x0b, 0x74, 0x84, 0x26, 0xfa, 0x0c,
    0x84, 0x4c, 0xc3, 0xa1, 0x8f, 0x9d, 0x5b, 0x74, 0x01, 0xa4, 0x66, 0x8f, 0x75, 0x73, 0x65, 0xc5,
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

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn hash_compute_ripe_md160() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompute) {
        return;
    }

    let hash = client.hash_compute(Hash::Ripemd160, &MESSAGE).unwrap();
    assert_eq!(&RIPE_MD160[..], hash.as_slice());
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn hash_compute_sha512() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompute) {
        return;
    }

    let hash = client.hash_compute(Hash::Sha512, &MESSAGE).unwrap();
    assert_eq!(&SHA_512[..], hash.as_slice());
}

#[test]
fn hash_compare_sha256() -> Result<()> {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        return Ok(());
    }

    client.hash_compare(Hash::Sha256, &MESSAGE, &SHA_256)
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn hash_compare_ripe_md160() -> Result<()> {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        return Ok(());
    }

    client.hash_compare(Hash::Ripemd160, &MESSAGE, &RIPE_MD160)
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn hash_compare_sha512() -> Result<()> {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaHashCompare) {
        return Ok(());
    }

    client.hash_compare(Hash::Sha512, &MESSAGE, &SHA_512)
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
