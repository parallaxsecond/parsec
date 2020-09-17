// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Pkcs11Provider;
use log::error;
use log::{info, trace, warn};
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::Result;
use parsec_interface::secrecy::ExposeSecret;
use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo, SHAVariant};
use pkcs11::errors::Error;
use pkcs11::types::*;
use pkcs11::types::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER};
use std::convert::{TryFrom, TryInto};
use std::pin::Pin;
use zeroize::Zeroize;

// Public exponent value for all RSA keys.
const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// Abstraction over CK_MECHANISM_TYPE
#[derive(Debug, Copy, Clone)]
pub enum CkMechanismType {
    CkmRsaPkcs,
    CkmRsaPkcsPss,
    CkmRsaPkcsOaep,
    CkmSha1,
    CkmSha256,
    CkmSha384,
    CkmSha512,
}

impl From<CkMechanismType> for CK_MECHANISM_TYPE {
    fn from(mech_type: CkMechanismType) -> Self {
        match mech_type {
            CkMechanismType::CkmRsaPkcs => CKM_RSA_PKCS,
            CkMechanismType::CkmRsaPkcsPss => CKM_RSA_PKCS_PSS,
            CkMechanismType::CkmRsaPkcsOaep => CKM_RSA_PKCS_OAEP,
            CkMechanismType::CkmSha1 => CKM_SHA_1,
            CkMechanismType::CkmSha256 => CKM_SHA256,
            CkMechanismType::CkmSha384 => CKM_SHA384,
            CkMechanismType::CkmSha512 => CKM_SHA512,
        }
    }
}

pub fn mech_type_to_allowed_mech_attribute(mech_type: &mut CK_MECHANISM_TYPE) -> CK_ATTRIBUTE {
    let param: CK_MECHANISM_TYPE_PTR = mech_type;
    let mut allowed_mechanisms_attr = CK_ATTRIBUTE::new(CKA_ALLOWED_MECHANISMS);
    allowed_mechanisms_attr.ulValueLen = ::std::mem::size_of::<CK_MECHANISM_TYPE>() as u64;
    allowed_mechanisms_attr.pValue = param as CK_VOID_PTR;
    allowed_mechanisms_attr
}

/// Abstraction over CK_MECHANISM
///
/// The parameters are only there if needed.
#[derive(Debug)]
pub enum CkMechanism {
    CkmRsaPkcs,
    CkmRsaPkcsPss(CkRsaPkcsPssParams),
    CkmRsaPkcsOaep(CkRsaPkcsOaepParams),
    CkmSha1,
    CkmSha256,
    CkmSha384,
    CkmSha512,
}

#[derive(Debug)]
pub enum CParams {
    CkmRsaPkcsPssParams(Pin<Box<CK_RSA_PKCS_PSS_PARAMS>>),
    CkmRsaPkcsOaepParams(Pin<Box<CK_RSA_PKCS_OAEP_PARAMS>>),
}

#[derive(Debug)]
pub struct CkRsaPkcsPssParams {
    hash_alg: CkMechanismType,
    mgf: CkRsaPkcsMgfType,
    s_len: usize,
}

impl CkRsaPkcsPssParams {
    pub fn as_c_type(&self) -> CK_RSA_PKCS_PSS_PARAMS {
        CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: self.hash_alg.into(),
            mgf: self.mgf.into(),
            sLen: self.s_len as u64,
        }
    }
}

#[derive(Debug)]
pub struct CkRsaPkcsOaepParams {
    hash_alg: CkMechanismType,
    mgf: CkRsaPkcsMgfType,
    source: CkRsaPkcsOaepSourceType,
    source_data: Vec<u8>,
}

impl CkRsaPkcsOaepParams {
    pub fn as_c_type(&mut self) -> CK_RSA_PKCS_OAEP_PARAMS {
        CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: self.hash_alg.into(),
            mgf: self.mgf.into(),
            source: self.source.into(),
            pSourceData: if self.source_data.is_empty() {
                std::ptr::null_mut()
            } else {
                self.source_data.as_mut_ptr() as CK_VOID_PTR
            },
            ulSourceDataLen: self.source_data.len() as u64,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CkRsaPkcsOaepSourceType {
    CkzDataSpecified,
}

impl From<CkRsaPkcsOaepSourceType> for CK_RSA_PKCS_OAEP_SOURCE_TYPE {
    fn from(source: CkRsaPkcsOaepSourceType) -> Self {
        match source {
            CkRsaPkcsOaepSourceType::CkzDataSpecified => CKZ_DATA_SPECIFIED,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CkRsaPkcsMgfType {
    CkgMgf1Sha1,
    CkgMgf1Sha256,
    CkgMgf1Sha384,
    CkgMgf1Sha512,
    CkgMgf1Sha224,
}

impl From<CkRsaPkcsMgfType> for CK_RSA_PKCS_MGF_TYPE {
    fn from(mgf: CkRsaPkcsMgfType) -> Self {
        match mgf {
            CkRsaPkcsMgfType::CkgMgf1Sha1 => CKG_MGF1_SHA1,
            CkRsaPkcsMgfType::CkgMgf1Sha256 => CKG_MGF1_SHA256,
            CkRsaPkcsMgfType::CkgMgf1Sha384 => CKG_MGF1_SHA384,
            CkRsaPkcsMgfType::CkgMgf1Sha512 => CKG_MGF1_SHA512,
            CkRsaPkcsMgfType::CkgMgf1Sha224 => CKG_MGF1_SHA224,
        }
    }
}

impl CkMechanism {
    /// Get the mechanism type
    fn mech_type(&self) -> CkMechanismType {
        match self {
            CkMechanism::CkmRsaPkcs => CkMechanismType::CkmRsaPkcs,
            CkMechanism::CkmRsaPkcsPss(_) => CkMechanismType::CkmRsaPkcsPss,
            CkMechanism::CkmRsaPkcsOaep(_) => CkMechanismType::CkmRsaPkcsOaep,
            CkMechanism::CkmSha1 => CkMechanismType::CkmSha1,
            CkMechanism::CkmSha256 => CkMechanismType::CkmSha256,
            CkMechanism::CkmSha384 => CkMechanismType::CkmSha384,
            CkMechanism::CkmSha512 => CkMechanismType::CkmSha512,
        }
    }
}

impl TryFrom<Hash> for CkMechanism {
    type Error = ResponseStatus;

    fn try_from(alg: Hash) -> Result<Self> {
        match alg {
            #[allow(deprecated)]
            Hash::Sha1 => Ok(CkMechanism::CkmSha1),
            Hash::Sha256 => Ok(CkMechanism::CkmSha256),
            Hash::Sha384 => Ok(CkMechanism::CkmSha384),
            Hash::Sha512 => Ok(CkMechanism::CkmSha512),
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}

impl TryFrom<Hash> for CkRsaPkcsMgfType {
    type Error = ResponseStatus;

    fn try_from(alg: Hash) -> Result<Self> {
        match alg {
            #[allow(deprecated)]
            Hash::Sha1 => Ok(CkRsaPkcsMgfType::CkgMgf1Sha1),
            Hash::Sha256 => Ok(CkRsaPkcsMgfType::CkgMgf1Sha256),
            Hash::Sha384 => Ok(CkRsaPkcsMgfType::CkgMgf1Sha384),
            Hash::Sha512 => Ok(CkRsaPkcsMgfType::CkgMgf1Sha512),
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}

impl TryFrom<Algorithm> for CkMechanism {
    type Error = ResponseStatus;

    fn try_from(alg: Algorithm) -> Result<Self> {
        match alg {
            Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign { .. })
            | Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt { .. }) => {
                Ok(CkMechanism::CkmRsaPkcs)
            }
            Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPss {
                hash_alg: SignHash::Specific(hash_alg),
            }) => Ok(CkMechanism::CkmRsaPkcsPss(CkRsaPkcsPssParams {
                hash_alg: CkMechanism::try_from(hash_alg)?.mech_type(),
                mgf: hash_alg.try_into()?,
                s_len: hash_alg.hash_length(),
            })),
            Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaOaep { hash_alg }) => {
                Ok(CkMechanism::CkmRsaPkcsOaep(CkRsaPkcsOaepParams {
                    hash_alg: CkMechanism::try_from(hash_alg)?.mech_type(),
                    mgf: hash_alg.try_into()?,
                    source: CkRsaPkcsOaepSourceType::CkzDataSpecified,
                    source_data: Vec::new(),
                }))
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}

impl CkMechanism {
    pub fn as_c_type(&mut self) -> (CK_MECHANISM, Option<CParams>) {
        match self {
            CkMechanism::CkmRsaPkcs
            | CkMechanism::CkmSha1
            | CkMechanism::CkmSha256
            | CkMechanism::CkmSha384
            | CkMechanism::CkmSha512 => (
                CK_MECHANISM {
                    mechanism: self.mech_type().into(),
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
                None,
            ),
            CkMechanism::CkmRsaPkcsPss(ref params) => {
                let mut params = Box::pin(params.as_c_type());
                let len = ::std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>();
                let p_params: CK_RSA_PKCS_PSS_PARAMS_PTR = params.as_mut().get_mut();
                (
                    CK_MECHANISM {
                        mechanism: self.mech_type().into(),
                        pParameter: p_params as CK_VOID_PTR,
                        ulParameterLen: len as u64,
                    },
                    Some(CParams::CkmRsaPkcsPssParams(params)),
                )
            }
            CkMechanism::CkmRsaPkcsOaep(ref mut params) => {
                let mut params = Box::pin(params.as_c_type());
                let len = ::std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>();
                //ERROR: that does not work because the address of params might change when it is
                //moved out of the function.
                //I think raw pointers must be made only if the object pointed at will not move
                //before the pointer is dereferenced.
                //That would mean that raw pointers must be made in the same lifetime than the
                //PKCS11 that will use them.
                let p_params: CK_RSA_PKCS_OAEP_PARAMS_PTR = params.as_mut().get_mut();
                (
                    CK_MECHANISM {
                        mechanism: self.mech_type().into(),
                        pParameter: p_params as CK_VOID_PTR,
                        ulParameterLen: len as u64,
                    },
                    Some(CParams::CkmRsaPkcsOaepParams(params)),
                )
            }
        }
    }
}

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
        Error::Io(e) => ResponseStatus::from(e),
        Error::Module(e) | Error::InvalidInput(e) => {
            format_error!("Conversion of error to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Pkcs11(ck_rv) => rv_to_response_status(ck_rv),
        Error::UnavailableInformation => {
            error!("Conversion of UnavailableInformation to PsaErrorCommunicationFailure");
            ResponseStatus::PsaErrorCommunicationFailure
        }
    }
}

pub fn rv_to_response_status(rv: CK_RV) -> ResponseStatus {
    match rv {
        CKR_OK => ResponseStatus::Success,
        CKR_HOST_MEMORY => ResponseStatus::PsaErrorInsufficientMemory,
        CKR_DEVICE_ERROR => ResponseStatus::PsaErrorHardwareFailure,
        CKR_DEVICE_MEMORY => ResponseStatus::PsaErrorInsufficientStorage,
        CKR_DEVICE_REMOVED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_SIGNATURE_INVALID => ResponseStatus::PsaErrorInvalidSignature,
        CKR_SIGNATURE_LEN_RANGE => ResponseStatus::PsaErrorInvalidSignature,
        CKR_TOKEN_NOT_PRESENT => ResponseStatus::PsaErrorHardwareFailure,
        CKR_TOKEN_NOT_RECOGNIZED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_RANDOM_NO_RNG => ResponseStatus::PsaErrorInsufficientEntropy,
        CKR_STATE_UNSAVEABLE => ResponseStatus::PsaErrorHardwareFailure,
        s @ CKR_CURVE_NOT_SUPPORTED
        | s @ CKR_DOMAIN_PARAMS_INVALID
        | s @ CKR_FUNCTION_NOT_SUPPORTED => {
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

// Representation of a PKCS 11 session.
pub struct Session<'a> {
    provider: &'a Pkcs11Provider,
    session_handle: CK_SESSION_HANDLE,
    // This information is necessary to log out when dropped.
    is_logged_in: bool,
}

#[derive(PartialEq, Zeroize)]
#[zeroize(drop)]
pub enum ReadWriteSession {
    ReadOnly,
    ReadWrite,
}

impl Session<'_> {
    pub fn new(provider: &Pkcs11Provider, read_write: ReadWriteSession) -> Result<Session> {
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Opening session on slot {}", provider.slot_number);
        }

        let mut session_flags = CKF_SERIAL_SESSION;
        if read_write == ReadWriteSession::ReadWrite {
            session_flags |= CKF_RW_SESSION;
        }

        trace!("OpenSession command");
        match provider
            .backend
            .open_session(provider.slot_number, session_flags, None, None)
        {
            Ok(session_handle) => {
                let mut session = Session {
                    provider,
                    session_handle,
                    is_logged_in: false,
                };

                // The stress tests revealed bugs when sessions were concurrently running and some
                // of them where logging in and out during their execution. These bugs seemed to
                // disappear when *all* sessions are logged in by default.
                // See https://github.com/opendnssec/SoftHSMv2/issues/509 for reference.
                // This has security implications and should be disclosed.
                session.login()?;

                Ok(session)
            }
            Err(e) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Error opening session for slot {}; error: {}.",
                        provider.slot_number, e
                    );
                } else {
                    error!("Error opening session for slot {}", provider.slot_number);
                }
                Err(to_response_status(e))
            }
        }
    }

    pub fn session_handle(&self) -> CK_SESSION_HANDLE {
        self.session_handle
    }

    fn login(&mut self) -> Result<()> {
        #[allow(clippy::mutex_atomic)]
        let mut logged_sessions_counter = self
            .provider
            .logged_sessions_counter
            .lock()
            .expect("Error while locking mutex.");

        if self.is_logged_in {
            if crate::utils::GlobalConfig::log_error_details() {
                info!(
                    "This session ({}) has already requested authentication.",
                    self.session_handle
                );
            }
            Ok(())
        } else if *logged_sessions_counter > 0 {
            info!(
                "Logging in ignored as {} sessions are already requiring authentication.",
                *logged_sessions_counter
            );
            *logged_sessions_counter += 1;
            self.is_logged_in = true;
            Ok(())
        } else if let Some(user_pin) = self.provider.user_pin.as_ref() {
            trace!("Login command");
            match self.provider.backend.login(
                self.session_handle,
                CKU_USER,
                Some(user_pin.expose_secret()),
            ) {
                Ok(_) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        info!("Logging in session {}.", self.session_handle);
                    }
                    *logged_sessions_counter += 1;
                    self.is_logged_in = true;
                    Ok(())
                }
                Err(e) => {
                    format_error!("Login operation failed", e);
                    Err(to_response_status(e))
                }
            }
        } else {
            warn!("Authentication requested but the provider has no user pin set!");
            Ok(())
        }
    }

    fn logout(&mut self) -> Result<()> {
        #[allow(clippy::mutex_atomic)]
        let mut logged_sessions_counter = self
            .provider
            .logged_sessions_counter
            .lock()
            .expect("Error while locking mutex.");

        if !self.is_logged_in {
            if crate::utils::GlobalConfig::log_error_details() {
                info!("Session {} has already logged out.", self.session_handle);
            }
            Ok(())
        } else if *logged_sessions_counter == 0 {
            info!("The user is already logged out, ignoring.");
            Ok(())
        } else if *logged_sessions_counter == 1 {
            // Only this session requires authentication.
            trace!("Logout command");
            match self.provider.backend.logout(self.session_handle) {
                Ok(_) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        info!("Logged out in session {}.", self.session_handle);
                    }
                    *logged_sessions_counter -= 1;
                    self.is_logged_in = false;
                    Ok(())
                }
                Err(e) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        error!(
                            "Failed to log out from session {} due to error {}. Continuing...",
                            self.session_handle, e
                        );
                    } else {
                        error!("Failed to log out from session. Continuing...");
                    }
                    Err(to_response_status(e))
                }
            }
        } else {
            info!(
                "{} sessions are still requiring authentication, not logging out.",
                *logged_sessions_counter
            );
            *logged_sessions_counter -= 1;
            self.is_logged_in = false;
            Ok(())
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if self.logout().is_err() {
            error!("Error while logging out. Continuing...");
        }
        trace!("CloseSession command");
        match self.provider.backend.close_session(self.session_handle) {
            Ok(_) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    info!("Session {} closed.", self.session_handle);
                }
            }
            // Treat this as best effort.
            Err(e) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Failed to log out from session {} due to error {}. Continuing...",
                        self.session_handle, e
                    );
                } else {
                    error!("Failed to log out from session. Continuing...");
                }
            }
        }
        self.session_handle.zeroize();
        self.is_logged_in.zeroize();
    }
}

/// This function converts key parameters from Parsec flavour to PKCS11 flavour
///
/// The return type is a tuple with:
/// * mechanism for key generation
/// * attributes list for public key
/// * attributes list for private key
/// * allowed mechanism for the two halves of the key
pub fn parsec_to_pkcs11_params(
    attributes: Attributes,
    key_id: &[u8],
    modulus_bits: &u64,
) -> Result<(
    CK_MECHANISM,
    Vec<CK_ATTRIBUTE>,
    Vec<CK_ATTRIBUTE>,
    CK_MECHANISM_TYPE,
)> {
    match attributes.key_type {
        Type::RsaKeyPair => {
            let mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };

            let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();
            priv_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
            priv_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id));

            let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
            pub_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id));
            pub_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
            pub_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_FALSE));
            pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(&PUBLIC_EXPONENT));
            pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(modulus_bits));

            key_pair_usage_flags_to_pkcs11_attributes(
                attributes.policy.usage_flags,
                &mut pub_template,
                &mut priv_template,
            );

            Ok((
                mechanism,
                pub_template,
                priv_template,
                CkMechanism::try_from(attributes.policy.permitted_algorithms)?
                    .mech_type()
                    .into(),
            ))
        }
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

fn key_pair_usage_flags_to_pkcs11_attributes(
    usage_flags: UsageFlags,
    pub_template: &mut Vec<CK_ATTRIBUTE>,
    priv_template: &mut Vec<CK_ATTRIBUTE>,
) {
    if usage_flags.sign_hash || usage_flags.sign_message {
        priv_template.push(CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_TRUE));
    } else {
        priv_template.push(CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_FALSE));
    }

    if usage_flags.verify_hash || usage_flags.verify_message {
        pub_template.push(CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_TRUE));
    } else {
        pub_template.push(CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_FALSE));
    }

    if usage_flags.encrypt {
        pub_template.push(CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_TRUE));
    } else {
        pub_template.push(CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_FALSE));
    }

    if usage_flags.decrypt {
        priv_template.push(CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_TRUE));
    } else {
        priv_template.push(CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_FALSE));
    }

    if usage_flags.derive {
        priv_template.push(CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&CK_TRUE));
    } else {
        priv_template.push(CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&CK_FALSE));
    }

    if usage_flags.export {
        priv_template.push(CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE));
    } else {
        priv_template.push(CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_FALSE));
    }

    if usage_flags.copy {
        priv_template.push(CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&CK_TRUE));
    } else {
        priv_template.push(CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&CK_FALSE));
    }
}

/// Format the input data into ASN1 DigestInfo bytes
pub fn digest_info(alg: AsymmetricSignature, hash: Vec<u8>) -> Result<Vec<u8>> {
    let oid = match alg {
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha224),
        } => AlgorithmIdentifier::new_sha(SHAVariant::SHA2_224),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha256),
        } => AlgorithmIdentifier::new_sha(SHAVariant::SHA2_256),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha384),
        } => AlgorithmIdentifier::new_sha(SHAVariant::SHA2_384),
        AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Specific(Hash::Sha512),
        } => AlgorithmIdentifier::new_sha(SHAVariant::SHA2_512),
        _ => return Err(ResponseStatus::PsaErrorNotSupported),
    };
    picky_asn1_der::to_vec(&DigestInfo {
        oid,
        digest: hash.into(),
    })
    // should not fail - if it does, there's some error in our stack
    .map_err(|_| ResponseStatus::PsaErrorGenericError)
}
