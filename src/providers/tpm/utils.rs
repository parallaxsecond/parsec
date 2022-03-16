// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]

use log::error;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::{ResponseStatus, Result};
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use tss_esapi::abstraction::transient::{KeyMaterial, KeyParams};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::interface_types::{
    algorithm::HashingAlgorithm, ecc::EccCurve, key_bits::RsaKeyBits,
};
use tss_esapi::structures::{
    EccScheme, EccSignature, HashScheme, RsaExponent, RsaScheme, RsaSignature, Signature,
};
use tss_esapi::tss2_esys::TPMS_CONTEXT;
use tss_esapi::utils::{PublicKey, TpmsContext};
use tss_esapi::Error;
use zeroize::{Zeroize, Zeroizing};
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
    /// This value is kept for legacy purposes, to aid in the migration process
    context: TpmsContext,
    /// This value is confidential and needs to be zeroized by its new owner.
    auth_value: Vec<u8>,
    /// Public and private parts of the key
    key_material: KeyMaterial,
}

impl PasswordContext {
    /// Create a new [PasswordContext]
    pub fn new(key_material: KeyMaterial, auth_value: Vec<u8>) -> Self {
        PasswordContext {
            context: TPMS_CONTEXT::default().try_into().unwrap(), // the default value is guaranteed to work
            auth_value,
            key_material,
        }
    }

    /// Get a slice of bytes representing the authentication value of the key
    pub fn auth_value(&self) -> &[u8] {
        &self.auth_value
    }

    /// Get reference to the [KeyMaterial] of the key
    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }
}

// LegacyPasswordContext that stored key contexts only.
#[deprecated]
#[derive(Serialize, Deserialize, Zeroize)]
pub struct LegacyPasswordContext {
    pub context: TpmsContext,
    /// This value is confidential and needs to be zeroized by its new owner.
    pub auth_value: Vec<u8>,
}

pub fn parsec_to_tpm_params(attributes: Attributes) -> Result<KeyParams> {
    match attributes.key_type {
        Type::RsaKeyPair | Type::RsaPublicKey => {
            let size = rsa_key_bits(attributes.bits)?;
            match attributes.policy.permitted_algorithms {
                Algorithm::AsymmetricSignature(alg) if alg.is_rsa_alg() => Ok(KeyParams::Rsa {
                    size,
                    scheme: match alg {
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: SignHash::Specific(hash),
                        } => RsaScheme::RsaSsa(HashScheme::new(convert_hash_to_tpm(hash)?)),
                        AsymmetricSignature::RsaPss {
                            hash_alg: SignHash::Specific(hash),
                        } => RsaScheme::RsaPss(HashScheme::new(convert_hash_to_tpm(hash)?)),
                        _ => return Err(ResponseStatus::PsaErrorNotSupported),
                    },
                    pub_exponent: RsaExponent::create(0).unwrap(),
                }),
                Algorithm::AsymmetricEncryption(alg) => Ok(KeyParams::Rsa {
                    size,
                    scheme: match alg {
                        AsymmetricEncryption::RsaPkcs1v15Crypt => RsaScheme::RsaEs,
                        AsymmetricEncryption::RsaOaep { hash_alg } => {
                            RsaScheme::Oaep(HashScheme::new(convert_hash_to_tpm(hash_alg)?))
                        }
                    },
                    pub_exponent: RsaExponent::create(0).unwrap(),
                }),
                alg => {
                    error!(
                        "Permitted algorithm {:?} not supported with RSA key pair.",
                        alg
                    );
                    Err(ResponseStatus::PsaErrorInvalidArgument)
                }
            }
        }
        Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => Ok(KeyParams::Ecc {
            scheme: match attributes.policy.permitted_algorithms {
                Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: SignHash::Specific(hash),
                }) => EccScheme::EcDsa(HashScheme::new(convert_hash_to_tpm(hash)?)),
                Algorithm::AsymmetricSignature(AsymmetricSignature::EcdsaAny)
                | Algorithm::AsymmetricSignature(AsymmetricSignature::DeterministicEcdsa {
                    ..
                }) => return Err(ResponseStatus::PsaErrorNotSupported),
                _ => {
                    error!(
                        "Wrong algorithm provided for ECC key: {:?}",
                        attributes.policy.permitted_algorithms
                    );
                    return Err(ResponseStatus::PsaErrorInvalidArgument);
                }
            },
            curve: convert_curve_to_tpm(attributes)?,
        }),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Modifies the `bits` field of the key attributes to match the key length.
///
/// This is a problem when importing a key where its number of bits is left
/// unspecified and up to the service to deduce.
pub fn adjust_attributes_key_bits(
    mut attributes: Attributes,
    key_data: &[u8],
) -> Result<Attributes> {
    if attributes.bits != 0 {
        return Ok(attributes);
    }

    // For a breakdown of the key formats we support see:
    // * for public keys: https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html#description
    // * private keys currently not supported
    match attributes.key_type {
        Type::RsaPublicKey => {
            let public_key: RsaPublicKey = picky_asn1_der::from_bytes(key_data).map_err(|err| {
                format_error!("Could not deserialise key elements", err);
                ResponseStatus::PsaErrorInvalidArgument
            })?;
            attributes.bits = public_key.modulus.as_unsigned_bytes_be().len() * 8;
            Ok(attributes)
        }
        Type::EccPublicKey { .. } => {
            if key_data.is_empty() || key_data.len() % 2 == 0 {
                return Err(ResponseStatus::PsaErrorInvalidArgument);
            }

            attributes.bits = ((key_data.len() - 1) / 2) * 8;
            Ok(attributes)
        }
        _ => Ok(attributes),
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
        _ => {
            error!("Requested hash is not supported ({:?})", hash);
            Err(ResponseStatus::PsaErrorNotSupported)
        }
    }
}

pub fn rsa_key_bits(bits: usize) -> Result<RsaKeyBits> {
    let size_u16 = u16::try_from(bits).map_err(|_| {
        error!("Requested RSA key size is not supported ({})", bits);
        ResponseStatus::PsaErrorInvalidArgument
    })?;
    RsaKeyBits::try_from(size_u16).map_err(|_| {
        error!("Requested RSA key size is not supported ({})", size_u16);
        ResponseStatus::PsaErrorInvalidArgument
    })
}

pub fn convert_curve_to_tpm(key_attributes: Attributes) -> Result<EccCurve> {
    match key_attributes.key_type {
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        }
        | Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        } => match key_attributes.bits {
            192 => Ok(EccCurve::NistP192),
            224 => Ok(EccCurve::NistP224),
            256 => Ok(EccCurve::NistP256),
            384 => Ok(EccCurve::NistP384),
            521 => Ok(EccCurve::NistP521),
            _ => {
                error!(
                    "Requested ECC key size is not supported ({})",
                    key_attributes.bits
                );
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        },
        _ => {
            error!(
                "Requested key type is not supported ({:?})",
                key_attributes.key_type
            );
            Err(ResponseStatus::PsaErrorNotSupported)
        }
    }
}

pub fn pub_key_to_bytes(pub_key: PublicKey, key_attributes: Attributes) -> Result<Vec<u8>> {
    match pub_key {
        PublicKey::Rsa(key) => picky_asn1_der::to_vec(&RsaPublicKey {
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

pub fn bytes_to_pub_key(key_data: Vec<u8>, key_attributes: &Attributes) -> Result<PublicKey> {
    match key_attributes.key_type {
        Type::RsaPublicKey => {
            let public_key: RsaPublicKey =
                picky_asn1_der::from_bytes(&key_data).map_err(|err| {
                    format_error!("Could not deserialise key elements", err);
                    ResponseStatus::PsaErrorInvalidArgument
                })?;

            validate_rsa_public_key(&public_key, key_attributes)?;

            Ok(PublicKey::Rsa(
                public_key.modulus.as_unsigned_bytes_be().to_vec(),
            ))
        }
        Type::EccPublicKey { .. } => {
            validate_ecc_public_key(&key_data, key_attributes)?;

            let (x, y) = octet_string_to_elliptic_curve_point(key_data);
            Ok(PublicKey::Ecc { x, y })
        }
        _ => Err(ResponseStatus::PsaErrorInvalidArgument),
    }
}

// Points on elliptic curves are represented as defined in section 2.3.3 of https://www.secg.org/sec1-v2.pdf
// The (uncompressed) representation is [ 0x04 || x || y ] where x and y are the coordinates of the point
fn octet_string_to_elliptic_curve_point(mut data: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut data = data.split_off(1);
    let key_len = data.len();
    let y = data.split_off(key_len / 2);
    let x = data.to_vec();
    (x, y)
}

pub fn signature_data_to_bytes(data: Signature, key_attributes: Attributes) -> Result<Vec<u8>> {
    match data {
        Signature::RsaSsa(rsa_signature) | Signature::RsaPss(rsa_signature) => {
            Ok(rsa_signature.signature().value().to_vec())
        }
        Signature::EcDsa(ecc_signature) => {
            // ECDSA signature data is represented the concatenation of the two result values, r and s,
            // in big endian format, as described here:
            // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_algorithm.html#asymmetricsignature-algorithm
            let p_byte_size = key_attributes.bits / 8; // should not fail for valid keys
            if ecc_signature.signature_r().value().len() != p_byte_size
                || ecc_signature.signature_s().value().len() != p_byte_size
            {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Received ECC signature with invalid size: r - {} bytes; s - {} bytes",
                        ecc_signature.signature_r().value().len(),
                        ecc_signature.signature_s().value().len()
                    );
                } else {
                    error!("Received ECC signature with invalid size.");
                }
                return Err(ResponseStatus::PsaErrorGenericError);
            }

            let mut signature = vec![];
            signature.append(&mut ecc_signature.signature_r().value().to_vec());
            signature.append(&mut ecc_signature.signature_s().value().to_vec());
            Ok(signature)
        }
        _ => {
            error!("Unsupported signature type received from TPM");
            Err(ResponseStatus::PsaErrorGenericError)
        }
    }
}

pub fn parsec_to_tpm_signature(
    data: Zeroizing<Vec<u8>>,
    key_attributes: Attributes,
    signature_alg: AsymmetricSignature,
) -> Result<Signature> {
    // Ok(Signature {
    //     scheme: convert_asym_scheme_to_tpm(Algorithm::AsymmetricSignature(signature_alg))?,
    //     signature: bytes_to_signature_data(data, key_attributes)?,
    // })
    Ok(match signature_alg {
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(hash),
        } => Signature::RsaSsa(
            RsaSignature::create(
                convert_hash_to_tpm(hash)?,
                data.to_vec().try_into().map_err(to_response_status)?,
            )
            .map_err(to_response_status)?,
        ),
        AsymmetricSignature::RsaPss {
            hash_alg: SignHash::Specific(hash),
        } => Signature::RsaPss(
            RsaSignature::create(
                convert_hash_to_tpm(hash)?,
                data.to_vec().try_into().map_err(to_response_status)?,
            )
            .map_err(to_response_status)?,
        ),
        AsymmetricSignature::Ecdsa {
            hash_alg: SignHash::Specific(hash),
        } => {
            // ECDSA signature data is represented as the concatenation of the two result values, r and s,
            // in big endian format, as described here:
            // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_algorithm.html#asymmetricsignature-algorithm
            let p_size = key_attributes.bits / 8;
            if data.len() != p_size * 2 {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Signature is not of the correct size - expected {} bytes, got {}.",
                        p_size * 2,
                        data.len()
                    );
                } else {
                    error!("Signature is not of the correct size.");
                }
                return Err(ResponseStatus::PsaErrorInvalidArgument);
            }

            let mut r = data.to_vec();
            let s = r.split_off(p_size);
            Signature::EcDsa(
                EccSignature::create(
                    convert_hash_to_tpm(hash)?,
                    r.try_into().map_err(to_response_status)?,
                    s.try_into().map_err(to_response_status)?,
                )
                .map_err(to_response_status)?,
            )
        }
        _ => {
            error!("Signature type not supported: {:?}", signature_alg);
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
    })
}

/// Validates an RsaPublicKey against the attributes we expect. Returns ok on success, otherwise
/// returns an error.
fn validate_rsa_public_key(public_key: &RsaPublicKey, attributes: &Attributes) -> Result<()> {
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
                    "`bits` field of key attributes (value: {}) must be either 0 or equal to the size of the key in `data` (value: {}) for RSA keys.",
                    attributes.bits,
                    len * 8
                );
        } else {
            error!("`bits` field of key attributes must be either 0 or equal to the size of the key in `data` for RSA keys.");
        }
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    if RsaKeyBits::try_from((len * 8) as u16).is_err() {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                "The TPM provider only supports RSA public keys of size 1024, 2048, 3072 and 4096 bits ({} bits given).",
                len * 8,
            );
        } else {
            error!(
                "The TPM provider only supports RSA public keys of size 1024, 2048, 3072 and 4096 bits"
            );
        }
        return Err(ResponseStatus::PsaErrorNotSupported);
    }

    Ok(())
}

fn validate_ecc_public_key(public_key: &[u8], attributes: &Attributes) -> Result<()> {
    if public_key.is_empty() {
        error!("Public key buffer is empty.");
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    // For the format of ECC public keys, see:
    // https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html#description
    if public_key[0] != 0x04 {
        error!("ECC public key buffer is incorrectly formatted.");
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    let len = public_key.len() - 1; // discard the first byte
    if attributes.bits != 0 && (len * 8) / 2 != attributes.bits {
        if crate::utils::GlobalConfig::log_error_details() {
            error!(
                    "`bits` field of key attributes (value: {}) must be either 0 or equal to half the size of the key in `data` (value: {}) for Weierstrass curves.",
                    attributes.bits,
                    len * 8
                );
        } else {
            error!("`bits` field of key attributes must be either 0 or equal to half the size of the key in `data` for Weierstrass curves.");
        }
        return Err(ResponseStatus::PsaErrorInvalidArgument);
    }

    Ok(())
}

pub(super) fn ek_pub_key_to_bytes(ek_public: PublicKey) -> Result<Vec<u8>> {
    pub_key_to_bytes(
        ek_public,
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 2048,
            policy: Policy {
                usage_flags: Default::default(),
                permitted_algorithms: Algorithm::None,
            },
        },
    )
}
