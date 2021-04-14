// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Assemble the service from a user-defined config
//!
//! The service builder is required to bootstrap all the components based on a
//! provided configuration.
use super::global_config::GlobalConfigBuilder;
use crate::authenticators::{Authenticate, AuthenticatorConfig};
use crate::back::{
    backend_handler::{BackEndHandler, BackEndHandlerBuilder},
    dispatcher::DispatcherBuilder,
};
use crate::front::listener::{ListenerConfig, ListenerType};
use crate::front::{
    domain_socket::DomainSocketListenerBuilder, front_end::FrontEndHandler,
    front_end::FrontEndHandlerBuilder, listener::Listen,
};
use crate::key_info_managers::{KeyInfoManagerConfig, KeyInfoManagerFactory};
use crate::providers::{core::ProviderBuilder as CoreProviderBuilder, Provide, ProviderConfig};
use anyhow::Result;
use log::{error, warn, LevelFilter};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;
use threadpool::{Builder as ThreadPoolBuilder, ThreadPool};

#[cfg(feature = "direct-authenticator")]
use crate::authenticators::direct_authenticator::DirectAuthenticator;
#[cfg(feature = "unix-peer-credentials-authenticator")]
use crate::authenticators::unix_peer_credentials_authenticator::UnixPeerCredentialsAuthenticator;

#[cfg(feature = "cryptoauthlib-provider")]
use crate::providers::cryptoauthlib::ProviderBuilder as CryptoAuthLibProviderBuilder;
#[cfg(feature = "mbed-crypto-provider")]
use crate::providers::mbed_crypto::ProviderBuilder as MbedCryptoProviderBuilder;
#[cfg(feature = "pkcs11-provider")]
use crate::providers::pkcs11::ProviderBuilder as Pkcs11ProviderBuilder;
#[cfg(feature = "tpm-provider")]
use crate::providers::tpm::ProviderBuilder as TpmProviderBuilder;
#[cfg(feature = "trusted-service-provider")]
use crate::providers::trusted_service::ProviderBuilder as TrustedServiceProviderBuilder;

#[cfg(any(
    feature = "mbed-crypto-provider",
    feature = "pkcs11-provider",
    feature = "tpm-provider",
    feature = "cryptoauthlib-provider",
    feature = "trusted-service-provider"
))]
use log::info;

const WIRE_PROTOCOL_VERSION_MINOR: u8 = 0;
const WIRE_PROTOCOL_VERSION_MAJOR: u8 = 1;

/// Default value for the limit on the request body size (in bytes) - equal to 1MB
const DEFAULT_BODY_LEN_LIMIT: usize = 1 << 20;

/// Default value for the limit on the buffer size for response (in bytes) - equal to 1MB
pub const DEFAULT_BUFFER_SIZE_LIMIT: usize = 1 << 20;

type Provider = Arc<dyn Provide + Send + Sync>;
type Authenticator = Box<dyn Authenticate + Send + Sync>;

/// Core settings
///
/// See the config.toml file for a description of each field.
#[derive(Copy, Clone, Deserialize, Debug)]
#[allow(missing_docs)]
pub struct CoreSettings {
    pub thread_pool_size: Option<usize>,
    pub idle_listener_sleep_duration: Option<u64>,
    pub log_level: Option<LevelFilter>,
    pub log_timestamp: Option<bool>,
    pub body_len_limit: Option<usize>,
    pub log_error_details: Option<bool>,
    pub allow_root: Option<bool>,
    pub buffer_size_limit: Option<usize>,
}

/// Configuration of Parsec
///
/// See the config.toml file for a description of each field.
#[derive(Deserialize, Debug)]
#[allow(missing_docs)]
pub struct ServiceConfig {
    pub core_settings: CoreSettings,
    pub listener: ListenerConfig,
    pub authenticator: AuthenticatorConfig,
    pub key_manager: Option<Vec<KeyInfoManagerConfig>>,
    pub provider: Option<Vec<ProviderConfig>>,
}

/// Service component builder and assembler
///
/// Entity responsible for converting a Parsec service configuration into a fully formed service.
/// Each component is independently created after which its ownership can be passed to the previous
/// component in the ownership chain. The service's ownership is then passed in the form of
/// ownership of a `FrontEndHandler` instance.
#[derive(Copy, Clone, Debug)]
pub struct ServiceBuilder;

impl ServiceBuilder {
    /// Evaluate the provided configuration and assemble a service based on it. If the configuration contains
    /// any errors or inconsistencies, an `Err` is returned.
    ///
    /// # Errors
    /// * if any of the fields specified in the configuration are inconsistent (e.g. key info manager with name 'X'
    /// requested for a certain provider does not exist) or if required fields are missing, an error of kind
    /// `InvalidData` is returned with a string describing the cause more accurately.
    pub fn build_service(config: &ServiceConfig) -> Result<FrontEndHandler> {
        GlobalConfigBuilder::new()
            .with_log_error_details(config.core_settings.log_error_details.unwrap_or(false))
            .with_buffer_size_limit(
                config
                    .core_settings
                    .buffer_size_limit
                    .unwrap_or(DEFAULT_BUFFER_SIZE_LIMIT),
            )
            .build();

        let key_info_manager_builders =
            gey_key_info_manager_builders(config.key_manager.as_ref().unwrap_or(&Vec::new()))?;

        let providers = build_providers(
            config.provider.as_ref().unwrap_or(&Vec::new()),
            key_info_manager_builders,
        )?;

        if providers.is_empty() {
            error!("Parsec needs at least one provider to start. No valid provider could be created from the configuration.");
            return Err(Error::new(ErrorKind::InvalidData, "need one provider").into());
        }

        let authenticators = build_authenticators(&config.authenticator)?;

        if authenticators[0].0 == AuthType::Direct {
            warn!("Direct authenticator has been set as the default one. It is only secure under specific requirements. Please make sure to read the Recommendations on a Secure Parsec Deployment at https://parallaxsecond.github.io/parsec-book/parsec_security/secure_deployment.html");
        }

        let backend_handlers = build_backend_handlers(providers, &authenticators)?;

        let dispatcher = DispatcherBuilder::new()
            .with_backends(backend_handlers)
            .build()?;

        let mut front_end_handler_builder = FrontEndHandlerBuilder::new();
        for (auth_type, authenticator) in authenticators {
            front_end_handler_builder =
                front_end_handler_builder.with_authenticator(auth_type, authenticator);
        }
        front_end_handler_builder = front_end_handler_builder
            .with_dispatcher(dispatcher)
            .with_body_len_limit(
                config
                    .core_settings
                    .body_len_limit
                    .unwrap_or(DEFAULT_BODY_LEN_LIMIT),
            );

        Ok(front_end_handler_builder.build()?)
    }

    /// Construct the service IPC front component and return ownership to it.
    pub fn start_listener(config: ListenerConfig) -> Result<Box<dyn Listen>> {
        let listener = match config.listener_type {
            ListenerType::DomainSocket => DomainSocketListenerBuilder::new()
                .with_timeout(Duration::from_millis(config.timeout))
                .with_socket_path(config.socket_path.map(|s| s.into()))
                .build(),
        }?;

        Ok(Box::new(listener))
    }

    /// Construct the thread pool that will be used to process all service requests.
    pub fn build_threadpool(num_threads: Option<usize>) -> ThreadPool {
        let mut threadpool_builder = ThreadPoolBuilder::new();
        if let Some(num_threads) = num_threads {
            threadpool_builder = threadpool_builder.num_threads(num_threads);
        }
        threadpool_builder.build()
    }
}

fn build_backend_handlers(
    mut providers: Vec<(ProviderID, Provider)>,
    authenticators: &[(AuthType, Authenticator)],
) -> Result<HashMap<ProviderID, BackEndHandler>> {
    let mut map = HashMap::new();

    let mut core_provider_builder = CoreProviderBuilder::new()
        .with_wire_protocol_version(WIRE_PROTOCOL_VERSION_MINOR, WIRE_PROTOCOL_VERSION_MAJOR);

    for (_auth_type, authenticator) in authenticators {
        let authenticator_info = authenticator
            .describe()
            .map_err(|_| Error::new(ErrorKind::Other, "Failed to describe authenticator"))?;
        core_provider_builder = core_provider_builder.with_authenticator_info(authenticator_info);
    }

    for (provider_id, provider) in providers.drain(..) {
        core_provider_builder = core_provider_builder.with_provider(provider.clone());

        let backend_handler = BackEndHandlerBuilder::new()
            .with_provider(provider)
            .with_converter(Box::from(ProtobufConverter {}))
            .with_provider_id(provider_id)
            .with_content_type(BodyType::Protobuf)
            .with_accept_type(BodyType::Protobuf)
            .build()?;
        let _ = map.insert(provider_id, backend_handler);
    }

    let core_provider_backend = BackEndHandlerBuilder::new()
        .with_provider(Arc::new(core_provider_builder.build()?))
        .with_converter(Box::from(ProtobufConverter {}))
        .with_provider_id(ProviderID::Core)
        .with_content_type(BodyType::Protobuf)
        .with_accept_type(BodyType::Protobuf)
        .build()?;

    let _ = map.insert(ProviderID::Core, core_provider_backend);

    Ok(map)
}

fn build_providers(
    configs: &[ProviderConfig],
    kim_factorys: HashMap<String, KeyInfoManagerFactory>,
) -> Result<Vec<(ProviderID, Provider)>> {
    let mut list = Vec::new();
    for config in configs {
        let provider_id = config.provider_id();
        if list.iter().any(|(id, _)| *id == provider_id) {
            error!("Parsec currently only supports one instance of each provider type, but {} was supplied twice. Please check your config.toml file.", provider_id);
            return Err(Error::new(
                ErrorKind::InvalidData,
                "only one provider per type is supported",
            )
            .into());
        }

        let kim_factory = match kim_factorys.get(config.key_info_manager()) {
            Some(kim_factory) => kim_factory,
            None => {
                format_error!(
                    "Key info manager builder with specified name was not found",
                    config.key_info_manager()
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "key info manager builder not found",
                )
                .into());
            }
        };
        // The safety is checked by the fact that only one instance per provider type is enforced.
        let provider = match unsafe { get_provider(config, kim_factory) } {
            Ok(provider) => provider,
            Err(e) => {
                format_error!(
                    &format!("Provider with ID {} cannot be created", provider_id),
                    e
                );
                return Err(Error::new(ErrorKind::Other, "failed to create provider").into());
            }
        };
        let _ = list.push((provider_id, provider));
    }

    Ok(list)
}

// This cfg_attr is used to allow the fact that key_info_manager is not used when there is no
// providers.
#[cfg_attr(
    not(all(
        feature = "mbed-crypto-provider",
        feature = "pkcs11-provider",
        feature = "tpm-provider",
        feature = "cryptoauthlib-provider",
        feature = "trusted-service-provider"
    )),
    allow(unused_variables),
    allow(clippy::match_single_binding)
)]
unsafe fn get_provider(
    config: &ProviderConfig,
    kim_factory: &KeyInfoManagerFactory,
) -> Result<Provider> {
    match config {
        #[cfg(feature = "mbed-crypto-provider")]
        ProviderConfig::MbedCrypto { .. } => {
            info!("Creating a Mbed Crypto Provider.");
            Ok(Arc::new(
                MbedCryptoProviderBuilder::new()
                    .with_key_info_store(kim_factory.build_client(ProviderID::MbedCrypto))
                    .build()?,
            ))
        }
        #[cfg(feature = "pkcs11-provider")]
        ProviderConfig::Pkcs11 {
            library_path,
            slot_number,
            user_pin,
            software_public_operations,
            ..
        } => {
            use std::convert::TryInto;

            info!("Creating a PKCS 11 Provider.");
            Ok(Arc::new(
                Pkcs11ProviderBuilder::new()
                    .with_key_info_store(kim_factory.build_client(ProviderID::Pkcs11))
                    .with_pkcs11_library_path(library_path.clone())
                    .with_slot_number((*slot_number).try_into()?)
                    .with_user_pin(user_pin.clone())
                    .with_software_public_operations(*software_public_operations)
                    .build()?,
            ))
        }
        #[cfg(feature = "tpm-provider")]
        ProviderConfig::Tpm {
            tcti,
            owner_hierarchy_auth,
            ..
        } => {
            info!("Creating a TPM Provider.");
            Ok(Arc::new(
                TpmProviderBuilder::new()
                    .with_key_info_store(kim_factory.build_client(ProviderID::Tpm))
                    .with_tcti(tcti)
                    .with_owner_hierarchy_auth(owner_hierarchy_auth.clone())
                    .build()?,
            ))
        }
        #[cfg(feature = "cryptoauthlib-provider")]
        ProviderConfig::CryptoAuthLib {
            device_type,
            iface_type,
            wake_delay,
            rx_retries,
            slave_address,
            bus,
            baud,
            ..
        } => {
            info!("Creating a CryptoAuthentication Library Provider.");
            Ok(Arc::new(
                CryptoAuthLibProviderBuilder::new()
                    .with_key_info_store(kim_factory.build_client(ProviderID::CryptoAuthLib))
                    .with_device_type(device_type.to_string())
                    .with_iface_type(iface_type.to_string())
                    .with_wake_delay(*wake_delay)
                    .with_rx_retries(*rx_retries)
                    .with_slave_address(*slave_address)
                    .with_bus(*bus)
                    .with_baud(*baud)
                    .build()?,
            ))
        }
        #[cfg(feature = "trusted-service-provider")]
        ProviderConfig::TrustedService { .. } => {
            info!("Creating a TPM Provider.");
            Ok(Arc::new(
                TrustedServiceProviderBuilder::new()
                    .with_key_info_store(kim_factory.build_client(ProviderID::TrustedService))
                    .build()?,
            ))
        }
        #[cfg(not(all(
            feature = "mbed-crypto-provider",
            feature = "pkcs11-provider",
            feature = "tpm-provider",
            feature = "cryptoauthlib-provider",
            feature = "trusted-service-provider"
        )))]
        _ => {
            error!(
                "Provider \"{:?}\" chosen in the configuration was not compiled in Parsec binary.",
                config
            );
            Err(Error::new(ErrorKind::InvalidData, "provider not compiled").into())
        }
    }
}

fn gey_key_info_manager_builders(
    configs: &[KeyInfoManagerConfig],
) -> Result<HashMap<String, KeyInfoManagerFactory>> {
    let mut map = HashMap::new();
    for config in configs {
        let _ = map.insert(config.name.clone(), KeyInfoManagerFactory::new(config)?);
    }

    Ok(map)
}

// Allowed to simplify the cfg blocks
#[allow(clippy::unnecessary_wraps)]
fn build_authenticators(config: &AuthenticatorConfig) -> Result<Vec<(AuthType, Authenticator)>> {
    // The authenticators supported by the Parsec service.
    // NOTE: order here is important. The order in which the elements are added here is the
    // order in which they will be returned to any client requesting them!
    // Currently only one authenticator is allowed by the Parsec service
    // See parallaxsecond/parsec#271
    let mut authenticators: Vec<(AuthType, Authenticator)> = Vec::new();

    match config {
        #[cfg(feature = "direct-authenticator")]
        AuthenticatorConfig::Direct { admins } => authenticators.push((
            AuthType::Direct,
            Box::from(DirectAuthenticator::new(
                admins.as_ref().cloned().unwrap_or_default(),
            )),
        )),
        #[cfg(feature = "unix-peer-credentials-authenticator")]
        AuthenticatorConfig::UnixPeerCredentials { admins } => authenticators.push((
            AuthType::UnixPeerCredentials,
            Box::from(UnixPeerCredentialsAuthenticator::new(
                admins.as_ref().cloned().unwrap_or_default(),
            )),
        )),
        #[cfg(not(all(
            feature = "direct-authenticator",
            feature = "unix-peer-credentials-authenticator",
        )))]
        _ => {
            error!(
                "Authenticator \"{:?}\" chosen in the configuration was not compiled in Parsec binary.",
                config
            );
            return Err(Error::new(ErrorKind::InvalidData, "authenticator not compiled").into());
        }
    };

    Ok(authenticators)
}
