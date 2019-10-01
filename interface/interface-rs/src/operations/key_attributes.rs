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
use num_derive::FromPrimitive;

/// Enumeration of possible algorithm definitions that can be attached to
/// cryptographic keys.
///
/// Each variant of the enum contains a main algorithm type (which is required for
/// that variant), as well as configuration fields as allowed by each algorithm in
/// part.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AlgorithmInner {
    Cipher(CipherAlgorithm),
    AsymmetricEncryption(AsymmetricEncryptionAlgorithm, Option<HashAlgorithm>),
    Mac(MacAlgorithm, Option<HashAlgorithm>, Option<u32>),
    Aead(AeadAlgorithm, Option<u32>),
    Sign(SignAlgorithm, Option<HashAlgorithm>),
    KeyAgreement(
        KeyAgreementAlgorithm,
        KeyDerivationFunction,
        Option<HashAlgorithm>,
    ),
    KeyDerivation(KeyDerivationFunction, Option<HashAlgorithm>),
    Hash(HashAlgorithm),
}

/// Wrapper around `AlgorithmInner`, used to statically ensure that any algorithm used
/// in `KeyAttributes` is a valid combination of algorithms and options.
#[derive(Clone)]
pub struct Algorithm(AlgorithmInner);

impl Algorithm {
    pub fn cipher(cipher: CipherAlgorithm) -> Algorithm {
        Algorithm(AlgorithmInner::Cipher(cipher))
    }

    pub fn asymmetric_encryption(
        enc: AsymmetricEncryptionAlgorithm,
        hash: Option<HashAlgorithm>,
    ) -> Algorithm {
        Algorithm(AlgorithmInner::AsymmetricEncryption(enc, hash))
    }

    pub fn mac(mac: MacAlgorithm, hash: Option<HashAlgorithm>, tag_len: Option<u32>) -> Algorithm {
        Algorithm(AlgorithmInner::Mac(mac, hash, tag_len))
    }

    pub fn aead(aead: AeadAlgorithm, tag_len: Option<u32>) -> Algorithm {
        Algorithm(AlgorithmInner::Aead(aead, tag_len))
    }

    pub fn sign(sign: SignAlgorithm, hash: Option<HashAlgorithm>) -> Algorithm {
        Algorithm(AlgorithmInner::Sign(sign, hash))
    }

    pub fn key_derivation(
        key_derivation: KeyDerivationFunction,
        hash: Option<HashAlgorithm>,
    ) -> Algorithm {
        Algorithm(AlgorithmInner::KeyDerivation(key_derivation, hash))
    }

    pub fn key_agreement(
        key_agreement: KeyAgreementAlgorithm,
        key_derivation: KeyDerivationFunction,
        hash: Option<HashAlgorithm>,
    ) -> Algorithm {
        Algorithm(AlgorithmInner::KeyAgreement(
            key_agreement,
            key_derivation,
            hash,
        ))
    }

    pub fn hash(hash: HashAlgorithm) -> Algorithm {
        Algorithm(AlgorithmInner::Hash(hash))
    }

    pub fn inner(&self) -> &AlgorithmInner {
        &self.0
    }
}

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Clone)]
pub struct KeyAttributes {
    pub key_lifetime: KeyLifetime,
    pub key_type: KeyType,
    pub ecc_curve: Option<EccCurve>,
    pub algorithm: Algorithm,
    pub key_size: u32,
    pub permit_export: bool,
    pub permit_encrypt: bool,
    pub permit_decrypt: bool,
    pub permit_sign: bool,
    pub permit_verify: bool,
    pub permit_derive: bool,
}

#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum KeyLifetime {
    Volatile = 0,
    Persistent = 1,
}

/// Enumeration of key types supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum KeyType {
    HmacKey = 0,
    DeriveKey = 1,
    AesKey = 2,
    DesKey = 3,
    CamelliaKey = 4,
    Arc4Key = 5,
    RsaPublicKey = 6,
    RsaKeypair = 7,
    DsaPublicKey = 8,
    DsaKeypair = 9,
    EccPublicKey = 10,
    EccKeypair = 11,
}

/// Enumeration of elliptic curves supported.
///
/// Should only be used for keys with `key_type` either `EccPublicKey`
/// or `EccKeypair`.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum EccCurve {
    Sect163k1 = 1,
    Sect163r1 = 2,
    Sect163r2 = 3,
    Sect193r1 = 4,
    Sect193r2 = 5,
    Sect233k1 = 6,
    Sect233r1 = 7,
    Sect239k1 = 8,
    Sect283k1 = 9,
    Sect283r1 = 10,
    Sect409k1 = 11,
    Sect409r1 = 12,
    Sect571k1 = 13,
    Sect571r1 = 14,
    Secp160k1 = 15,
    Secp160r1 = 16,
    Secp160r2 = 17,
    Secp192k1 = 18,
    Secp192r1 = 19,
    Secp224k1 = 20,
    Secp224r1 = 21,
    Secp256k1 = 22,
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    BrainpoolP256r1 = 26,
    BrainpoolP384r1 = 27,
    BrainpoolP512r1 = 28,
    Curve25519 = 29,
    Curve448 = 30,
}

/// Enumeration of symmetric encryption algorithms supported.
///
/// Includes both specific algorithms (ARC4) and modes of operation
/// for algorithms defined through the key type (e.g. `AesKey`).
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum CipherAlgorithm {
    Arc4 = 0,
    Ctr = 1,
    Cfb = 2,
    Ofb = 3,
    Xts = 4,
    CbcNoPadding = 5,
    CbcPkcs7 = 6,
}

/// Enumeration of asymmetric encryption algorithms supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum AsymmetricEncryptionAlgorithm {
    RsaPkcs1v15Crypt = 0,
    RsaOaep = 1,
}

/// Enumeration of message authentication code algorithms supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum MacAlgorithm {
    Hmac = 0,
    CbcMac = 1,
    Cmac = 2,
    Gmac = 3,
}

/// Enumeration of authenticated encryption with additional data algorithms
/// supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum AeadAlgorithm {
    Ccm = 0,
    Gcm = 1,
}

/// Enumeration of asymmetric signing algorithms supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum SignAlgorithm {
    RsaPkcs1v15Sign = 0,
    RsaPss = 1,
    Dsa = 2,
    DeterministicDsa = 3,
    Ecdsa = 4,
    DeterministicEcdsa = 5,
}

/// Enumeration of key agreement algorithms supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum KeyAgreementAlgorithm {
    Ffdh = 0,
    Ecdh = 1,
}

/// Enumeration of hash algorithms supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum HashAlgorithm {
    Md2 = 1,
    Md4 = 2,
    Md5 = 3,
    Ripemd160 = 4,
    Sha1 = 5,
    Sha224 = 6,
    Sha256 = 7,
    Sha384 = 8,
    Sha512 = 9,
    Sha512224 = 10,
    Sha512256 = 11,
    Sha3224 = 12,
    Sha3256 = 13,
    Sha3384 = 14,
    Sha3512 = 15,
}

/// Enumeration of key derivation functions supported.
#[derive(FromPrimitive, Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(i32)]
pub enum KeyDerivationFunction {
    Hkdf = 0,
    Tls12Prf = 1,
    Tls12PskToMs = 2,
    SelectRaw = 3,
}
