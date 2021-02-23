// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::{ResponseStatus, Result};
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::{RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tss_esapi::abstraction::transient::KeyParams;
use tss_esapi::constants::algorithm::{EllipticCurve, HashingAlgorithm};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::utils::{
    AsymSchemeUnion, PublicKey, Signature, SignatureData, TpmsContext, RSA_KEY_SIZES,
};
use tss_esapi::Error;
use zeroize::{Zeroize, Zeroizing};
pub const PUBLIC_EXPONENT: u32 = 0x10001;
const PUBLIC_EXPONENT_BYTES: [u8; 3] = [0x01, 0x00, 0x01];

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
#[derive(Serialize, Deserialize, Zeroize)]
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
            public_exponent: IntegerAsn1::from_bytes_be_signed(PUBLIC_EXPONENT_BYTES.to_vec()),
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

/// Validates an RSAPublicKey against the attributes we expect. Returns ok on success, otherwise
/// returns an error.
pub fn validate_public_key(public_key: &RSAPublicKey, attributes: &Attributes) -> Result<()> {
    if public_key.modulus.is_negative() || public_key.public_exponent.is_negative() {
        error!("Only positive modulus and public exponent are supported.");
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    if public_key.public_exponent.as_unsigned_bytes_be() != PUBLIC_EXPONENT_BYTES {
        if crate::utils::GlobalConfig::log_error_details() {
            error!("The TPM Provider only supports 0x10001 as public exponent for RSA public keys, {:?} given.", public_key.public_exponent.as_unsigned_bytes_be());
        } else {
            error!("The TPM Provider only supports 0x10001 as public exponent for RSA public keys");
        }
        return Err(ResponseStatus::PsaErrorNotSupported);
    }
    let key_data = public_key.modulus.as_unsigned_bytes_be();
    let len = key_data.len();

    let key_bits = attributes.bits;
    if key_bits != 0 && len * 8 != key_bits {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                    "`bits` field of key attributes (value: {}) must be either 0 or equal to the size of the key in `data` (value: {}).",
                    attributes.bits,
                    len * 8
                );
        } else {
            error!("`bits` field of key attributes must be either 0 or equal to the size of the key in `data`.");
        }
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    let valid_key_sizes_vec = RSA_KEY_SIZES.to_vec();
    if !valid_key_sizes_vec.contains(&((len * 8) as u16)) {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                "The TPM provider only supports RSA public keys of size {:?} bits ({} bits given).",
                valid_key_sizes_vec,
                len * 8,
            );
        } else {
            error!(
                "The TPM provider only supports RSA public keys of size {:?} bits",
                valid_key_sizes_vec,
            );
        }
        return Err(ResponseStatus::PsaErrorNotSupported);
    }

    Ok(())
}

/// Validates an RSAPrivateKey against the attributes we expect. Returns ok on success, otherwise
/// returns an error.
pub fn validate_private_key(private_key: &RSAPrivateKey, attributes: &Attributes) -> Result<()> {
    // NOTE: potentially incomplete, but any errors that aren't caught here should be caught
    //       further down the stack (i.e. in the tss crate).

    // The public exponent must be exactly 0x10001 -- that is the only value supported by the TPM
    // provider. Reject everything else.
    let given_public_exponent = private_key.public_exponent.as_unsigned_bytes_be();
    if given_public_exponent != PUBLIC_EXPONENT_BYTES {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                "Unexpected public exponent in private key (expected: {:?}, got: {:?}).",
                PUBLIC_EXPONENT_BYTES, given_public_exponent
            );
        } else {
            error!("Unexpected public exponent in private key.");
        }
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    // The key prime's length in bits should be exactly half of the size of the size of the key's
    // public modulus.
    let key_prime = private_key.prime_1.as_unsigned_bytes_be();
    let key_prime_len_bits = key_prime.len() * 8;
    if key_prime_len_bits != attributes.bits / 2 {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                "The key prime is not of the expected size (expected {}, got {}).",
                attributes.bits / 2,
                key_prime_len_bits,
            );
        } else {
            error!("The key prime is not of the expected size.",);
        }
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }
    Ok(())
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
