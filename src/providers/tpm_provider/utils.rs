// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::{ResponseStatus, Result};
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::RSAPublicKey;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tss_esapi::abstraction::transient::KeyParams;
use tss_esapi::constants::algorithm::{EllipticCurve, HashingAlgorithm};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::utils::{AsymSchemeUnion, PublicKey, Signature, SignatureData, TpmsContext};
use tss_esapi::Error;
use zeroize::Zeroizing;
const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// Convert the TSS library specific error values to ResponseStatus values that are returned on
/// the wire protocol
///
/// Most of them are PsaErrorCommunicationFailure as, in the general case, the calls to the TSS
/// library should suceed with the values crafted by the provider.
/// If an error happens in the TSS library, it means that it was badly used by the provider or that
/// it failed in an unexpected way and hence the PsaErrorCommunicationFailure error.
/// The errors translated to response status are related with signature verification failure, lack
/// of memory, hardware failure, corruption detection, lack of entropy and unsupported operations.
pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::WrapperError(e) => {
            format_error!("Conversion to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Tss2Error(e) => {
            if let Some(kind) = e.kind() {
                match kind {
                    Tss2ResponseCodeKind::Success => ResponseStatus::Success,
                    Tss2ResponseCodeKind::Signature => ResponseStatus::PsaErrorInvalidSignature,
                    Tss2ResponseCodeKind::ObjectMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::SessionMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::Memory => ResponseStatus::PsaErrorInsufficientMemory,
                    Tss2ResponseCodeKind::Retry => ResponseStatus::PsaErrorHardwareFailure,
                    s @ Tss2ResponseCodeKind::Asymmetric
                    | s @ Tss2ResponseCodeKind::Hash
                    | s @ Tss2ResponseCodeKind::KeySize
                    | s @ Tss2ResponseCodeKind::Mgf
                    | s @ Tss2ResponseCodeKind::Mode
                    | s @ Tss2ResponseCodeKind::Kdf
                    | s @ Tss2ResponseCodeKind::Scheme
                    | s @ Tss2ResponseCodeKind::Symmetric
                    | s @ Tss2ResponseCodeKind::Curve => {
                        if crate::utils::GlobalConfig::log_error_details() {
                            error!("Not supported value ({:?})", s);
                        }
                        ResponseStatus::PsaErrorNotSupported
                    }
                    e => {
                        if crate::utils::GlobalConfig::log_error_details() {
                            error!(
                                "Error \"{:?}\" converted to PsaErrorCommunicationFailure.",
                                e
                            );
                        } else {
                            error!("Error converted to PsaErrorCommunicationFailure.");
                        }
                        ResponseStatus::PsaErrorCommunicationFailure
                    }
                }
            } else {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Can not encode value {} into on of the possible TSS return values.",
                        e
                    );
                } else {
                    error!("Can not encode value into on of the possible TSS return values.");
                }
                ResponseStatus::InvalidEncoding
            }
        }
    }
}

// The PasswordContext is what is stored by the Key Info Manager.
#[derive(Serialize, Deserialize)]
pub struct PasswordContext {
    pub context: TpmsContext,
    /// This value is confidential and needs to be zeroized by its new owner.
    pub auth_value: Vec<u8>,
}

pub fn parsec_to_tpm_params(attributes: Attributes) -> Result<KeyParams> {
    match attributes.key_type {
        Type::RsaKeyPair => {
            let size = match attributes.bits {
                x @ 1024 | x @ 2048 | x @ 3072 | x @ 4096 => x.try_into().unwrap(), // will not fail on the matched values
                _ => return Err(ResponseStatus::PsaErrorInvalidArgument),
            };
            if attributes.is_encrypt_permitted() || attributes.is_decrypt_permitted() {
                Ok(KeyParams::RsaEncrypt {
                    size,
                    pub_exponent: 0,
                })
            } else if attributes.is_hash_signable() || attributes.is_hash_verifiable() {
                Ok(KeyParams::RsaSign {
                    size,
                    scheme: convert_asym_scheme_to_tpm(attributes.policy.permitted_algorithms)?,
                    pub_exponent: 0,
                })
            } else {
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
        Type::EccKeyPair { .. } => Ok(KeyParams::Ecc {
            scheme: convert_asym_scheme_to_tpm(attributes.policy.permitted_algorithms)?,
            curve: convert_curve_to_tpm(attributes)?,
        }),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

pub fn convert_asym_scheme_to_tpm(algorithm: Algorithm) -> Result<AsymSchemeUnion> {
    match algorithm {
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(hash_alg),
        }) => Ok(AsymSchemeUnion::RSASSA(convert_hash_to_tpm(hash_alg)?)),
        Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: SignHash::Specific(hash_alg),
        }) => Ok(AsymSchemeUnion::ECDSA(convert_hash_to_tpm(hash_alg)?)),
        Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt) => {
            Ok(AsymSchemeUnion::RSAES)
        }
        Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaOaep { hash_alg }) => {
            Ok(AsymSchemeUnion::RSAOAEP(convert_hash_to_tpm(hash_alg)?))
        }
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

#[allow(deprecated)]
fn convert_hash_to_tpm(hash: Hash) -> Result<HashingAlgorithm> {
    match hash {
        Hash::Sha1 => Ok(HashingAlgorithm::Sha1),
        Hash::Sha256 => Ok(HashingAlgorithm::Sha256),
        Hash::Sha384 => Ok(HashingAlgorithm::Sha384),
        Hash::Sha512 => Ok(HashingAlgorithm::Sha512),
        Hash::Sha3_256 => Ok(HashingAlgorithm::Sha3_256),
        Hash::Sha3_384 => Ok(HashingAlgorithm::Sha3_384),
        Hash::Sha3_512 => Ok(HashingAlgorithm::Sha3_512),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

fn convert_curve_to_tpm(key_attributes: Attributes) -> Result<EllipticCurve> {
    match key_attributes.key_type {
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        }
        | Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        } => match key_attributes.bits {
            192 => Ok(EllipticCurve::NistP192),
            224 => Ok(EllipticCurve::NistP224),
            256 => Ok(EllipticCurve::NistP256),
            384 => Ok(EllipticCurve::NistP384),
            512 => Ok(EllipticCurve::NistP521),
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        },
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

pub fn pub_key_to_bytes(pub_key: PublicKey, key_attributes: Attributes) -> Result<Vec<u8>> {
    match pub_key {
        PublicKey::Rsa(key) => picky_asn1_der::to_vec(&RSAPublicKey {
            modulus: IntegerAsn1::from_bytes_be_unsigned(key),
            public_exponent: IntegerAsn1::from_bytes_be_signed(PUBLIC_EXPONENT.to_vec()),
        })
        .or(Err(ResponseStatus::PsaErrorGenericError)),
        PublicKey::Ecc { x, y } => {
            let p_byte_size = key_attributes.bits / 8; // should not fail for valid keys
            if x.len() != p_byte_size || y.len() != p_byte_size {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Received ECC public key with invalid size: x - {} bytes; y - {} bytes",
                        x.len(),
                        y.len()
                    );
                } else {
                    error!("Received ECC public key with invalid size.");
                }
                return Err(ResponseStatus::PsaErrorCommunicationFailure);
            }
            Ok(elliptic_curve_point_to_octet_string(x, y))
        }
    }
}

// Points on elliptic curves are represented as defined in section 2.3.3 of https://www.secg.org/sec1-v2.pdf
// The (uncompressed) representation is [ 0x04 || x || y ] where x and y are the coordinates of the point
fn elliptic_curve_point_to_octet_string(mut x: Vec<u8>, mut y: Vec<u8>) -> Vec<u8> {
    let mut octet_string = vec![0x04];
    octet_string.append(&mut x);
    octet_string.append(&mut y);
    octet_string
}

pub fn signature_data_to_bytes(data: SignatureData, key_attributes: Attributes) -> Result<Vec<u8>> {
    match data {
        SignatureData::RsaSignature(signature) => Ok(signature),
        SignatureData::EcdsaSignature { mut r, mut s } => {
            // ECDSA signature data is represented the concatenation of the two result values, r and s,
            // in big endian format, as described here:
            // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_algorithm.html#asymmetricsignature-algorithm
            let p_byte_size = key_attributes.bits / 8; // should not fail for valid keys
            if r.len() != p_byte_size || s.len() != p_byte_size {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Received ECC signature with invalid size: r - {} bytes; s - {} bytes",
                        r.len(),
                        s.len()
                    );
                } else {
                    error!("Received ECC signature with invalid size.");
                }
                return Err(ResponseStatus::PsaErrorGenericError);
            }

            let mut signature = vec![];
            signature.append(&mut r);
            signature.append(&mut s);
            Ok(signature)
        }
    }
}

pub fn parsec_to_tpm_signature(
    data: Zeroizing<Vec<u8>>,
    key_attributes: Attributes,
    signature_alg: AsymmetricSignature,
) -> Result<Signature> {
    Ok(Signature {
        scheme: convert_asym_scheme_to_tpm(Algorithm::AsymmetricSignature(signature_alg))?,
        signature: bytes_to_signature_data(data, key_attributes)?,
    })
}

fn bytes_to_signature_data(
    data: Zeroizing<Vec<u8>>,
    key_attributes: Attributes,
) -> Result<SignatureData> {
    match key_attributes.key_type {
        Type::RsaKeyPair | Type::RsaPublicKey => Ok(SignatureData::RsaSignature(data.to_vec())),
        Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => {
            // ECDSA signature data is represented the concatenation of the two result values, r and s,
            // in big endian format, as described here:
            // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_algorithm.html#asymmetricsignature-algorithm
            let p_size = key_attributes.bits / 8;
            if data.len() != p_size * 2 {
                return Err(ResponseStatus::PsaErrorInvalidArgument);
            }

            let mut r = data.to_vec();
            let s = r.split_off(p_size);
            Ok(SignatureData::EcdsaSignature { r, s })
        }
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}
