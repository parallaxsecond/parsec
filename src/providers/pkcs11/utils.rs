// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::rsa;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use log::error;
use parsec_interface::operations::psa_algorithm::{AsymmetricSignature, Hash, SignHash};

use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::Result as ResponseResult;
use picky_asn1::wrapper::ObjectIdentifierAsn1;
use picky_asn1_x509::{
    algorithm_identifier::EcParameters, AlgorithmIdentifier, DigestInfo, ShaVariant,
};
use std::convert::TryInto;
// Public exponent value for all RSA keys.
pub const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// Convert the PKCS 11 library specific error values to ResponseStatus values that are returned on
/// the wire protocol
///
/// Most of them are PsaErrorCommunicationFailure as, in the general case, the calls to the PKCS11
/// library should suceed with the values crafted by the provider.
/// If an error happens in the PKCS11 library, it means that it was badly used by the provider or
/// that it failed in an unexpected way and hence the PsaErrorCommunicationFailure error.
/// The errors translated to response status are related with signature verification failure, lack
/// of memory, hardware failure, corruption detection, lack of entropy and unsupported operations.
pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::LibraryLoading(e) => {
            format_error!("Conversion of error to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Pkcs11(ck_rv) => rv_to_response_status(ck_rv),
        Error::NotSupported => ResponseStatus::PsaErrorNotSupported,
        Error::TryFromInt(e) => ResponseStatus::from(e),
        Error::TryFromSlice(e) => ResponseStatus::from(e),
        Error::NulError(e) => ResponseStatus::from(e),
        error => {
            format_error!("Conversion of error to PsaErrorCommunicationFailure", error);
            ResponseStatus::PsaErrorCommunicationFailure
        }
    }
}

pub fn rv_to_response_status(rv: RvError) -> ResponseStatus {
    match rv {
        RvError::HostMemory => ResponseStatus::PsaErrorInsufficientMemory,
        RvError::DeviceError => ResponseStatus::PsaErrorHardwareFailure,
        RvError::DeviceMemory => ResponseStatus::PsaErrorInsufficientStorage,
        RvError::DeviceRemoved => ResponseStatus::PsaErrorHardwareFailure,
        RvError::SignatureInvalid => ResponseStatus::PsaErrorInvalidSignature,
        RvError::SignatureLenRange => ResponseStatus::PsaErrorInvalidSignature,
        RvError::TokenNotPresent => ResponseStatus::PsaErrorHardwareFailure,
        RvError::TokenNotRecognized => ResponseStatus::PsaErrorHardwareFailure,
        RvError::RandomNoRng => ResponseStatus::PsaErrorInsufficientEntropy,
        RvError::StateUnsaveable => ResponseStatus::PsaErrorHardwareFailure,
        s @ RvError::CurveNotSupported
        | s @ RvError::DomainParamsInvalid
        | s @ RvError::FunctionNotSupported => {
            if crate::utils::GlobalConfig::log_error_details() {
                error!("Not supported value ({:?})", s);
            }
            ResponseStatus::PsaErrorNotSupported
        }
        e => {
            format_error!("Error converted to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
    }
}

// For PKCS 11, a key pair consists of two independant public and private keys. Both will share the
// same key ID.
pub enum KeyPairType {
    PublicKey,
    PrivateKey,
    Any,
}

pub fn key_pair_usage_flags_to_pkcs11_attributes(
    usage_flags: UsageFlags,
    pub_template: &mut Vec<Attribute>,
    priv_template: &mut Vec<Attribute>,
) {
    priv_template.push(Attribute::Sign(
        (usage_flags.sign_hash() || usage_flags.sign_message()).into(),
    ));
    pub_template.push(Attribute::Verify(
        (usage_flags.verify_hash() || usage_flags.verify_message()).into(),
    ));
    pub_template.push(Attribute::Encrypt((usage_flags.encrypt()).into()));
    priv_template.push(Attribute::Decrypt((usage_flags.decrypt()).into()));
    priv_template.push(Attribute::Derive((usage_flags.derive()).into()));
    priv_template.push(Attribute::Extractable((usage_flags.export()).into()));
    priv_template.push(Attribute::Sensitive((!usage_flags.export()).into()));
    priv_template.push(Attribute::Copyable((usage_flags.copy()).into()));
    pub_template.push(Attribute::Copyable((usage_flags.copy()).into()));
}

/// Format the input data into ASN1 DigestInfo bytes
pub fn digest_info(alg: AsymmetricSignature, hash: Vec<u8>) -> ResponseResult<Vec<u8>> {
    let oid = match alg {
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha224),
        } => AlgorithmIdentifier::new_sha(ShaVariant::SHA2_224),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha256),
        } => AlgorithmIdentifier::new_sha(ShaVariant::SHA2_256),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha384),
        } => AlgorithmIdentifier::new_sha(ShaVariant::SHA2_384),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha512),
        } => AlgorithmIdentifier::new_sha(ShaVariant::SHA2_512),
        _ => return Err(ResponseStatus::PsaErrorNotSupported),
    };
    picky_asn1_der::to_vec(&DigestInfo {
        oid,
        digest: hash.into(),
    })
    // should not fail - if it does, there's some error in our stack
    .map_err(|_| ResponseStatus::PsaErrorGenericError)
}

pub fn ec_params(ecc_family: EccFamily, bits: usize) -> ResponseResult<EcParameters> {
    Ok(EcParameters::NamedCurve(match (ecc_family, bits) {
        // The following "unwrap()" should be ok, as they cover constant conversions
        (EccFamily::SecpR1, 192) => {
            ObjectIdentifierAsn1(String::from("1.2.840.10045.3.1.1").try_into().unwrap())
        }
        (EccFamily::SecpR1, 224) => {
            ObjectIdentifierAsn1(String::from("1.3.132.0.33").try_into().unwrap())
        }
        (EccFamily::SecpR1, 256) => {
            ObjectIdentifierAsn1(String::from("1.2.840.10045.3.1.7").try_into().unwrap())
        }
        (EccFamily::SecpR1, 384) => {
            ObjectIdentifierAsn1(String::from("1.3.132.0.34").try_into().unwrap())
        }
        (EccFamily::SecpR1, 521) => {
            ObjectIdentifierAsn1(String::from("1.3.132.0.35").try_into().unwrap())
        }
        _ => return Err(ResponseStatus::PsaErrorNotSupported),
    }))
}

#[allow(deprecated)]
/// Convert a PSA Crypto Hash algorithm to a MGF type
pub fn pkcsmgftype_from_psa_crypto_hash(alg: Hash) -> Result<rsa::PkcsMgfType, Error> {
    match alg {
        Hash::Sha1 => Ok(rsa::PkcsMgfType::MGF1_SHA1),
        Hash::Sha224 => Ok(rsa::PkcsMgfType::MGF1_SHA224),
        Hash::Sha256 => Ok(rsa::PkcsMgfType::MGF1_SHA256),
        Hash::Sha384 => Ok(rsa::PkcsMgfType::MGF1_SHA384),
        Hash::Sha512 => Ok(rsa::PkcsMgfType::MGF1_SHA512),
        alg => {
            error!("{:?} is not a supported MGF1 algorithm", alg);
            Err(Error::NotSupported)
        }
    }
}

#[allow(deprecated)]
pub fn algorithm_to_mechanism<'a>(
    alg: psa_crypto::types::algorithm::Algorithm,
) -> Result<Mechanism<'a>, Error> {
    use psa_crypto::types::algorithm::{Algorithm, AsymmetricEncryption};

    match alg {
        Algorithm::Hash(Hash::Sha1) => Ok(Mechanism::Sha1),
        Algorithm::Hash(Hash::Sha256) => Ok(Mechanism::Sha256),
        Algorithm::Hash(Hash::Sha384) => Ok(Mechanism::Sha384),
        Algorithm::Hash(Hash::Sha512) => Ok(Mechanism::Sha512),
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign { .. })
        | Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt { .. }) => {
            Ok(Mechanism::RsaPkcs)
        }
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPss {
            hash_alg: SignHash::Specific(hash_alg),
        }) => Ok(Mechanism::RsaPkcsPss(rsa::PkcsPssParams {
            hash_alg: algorithm_to_mechanism(Algorithm::from(hash_alg))?.mechanism_type(),
            mgf: pkcsmgftype_from_psa_crypto_hash(hash_alg)?,
            s_len: hash_alg.hash_length().try_into()?,
        })),
        Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa { .. }) => Ok(Mechanism::Ecdsa),
        Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaOaep { hash_alg }) => {
            Ok(Mechanism::from(rsa::PkcsOaepParams::new(
                algorithm_to_mechanism(Algorithm::from(hash_alg))?.mechanism_type(),
                pkcsmgftype_from_psa_crypto_hash(hash_alg)?,
                rsa::PkcsOaepSource::empty(),
            )))
        }
        alg => {
            error!("{:?} is not a supported algorithm", alg);
            Err(Error::NotSupported)
        }
    }
}
