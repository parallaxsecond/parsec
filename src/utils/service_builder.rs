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
use crate::authenticators::simple_authenticator::SimpleAuthenticator;
use crate::back::{
    backend_handler::{BackEndHandler, BackEndHandlerBuilder},
    dispatcher::DispatcherBuilder,
};
use crate::front::listener::{ListenerConfig, ListenerType};
use crate::front::{
    domain_socket::DomainSocketListenerBuilder, front_end::FrontEndHandler,
    front_end::FrontEndHandlerBuilder, listener::Listen,
};
use crate::key_id_managers::on_disk_manager::{OnDiskKeyIDManagerBuilder, DEFAULT_MAPPINGS_PATH};
use crate::key_id_managers::{KeyIdManagerConfig, KeyIdManagerType, ManageKeyIDs};
use crate::providers::{
    core_provider::CoreProviderBuilder, mbed_provider::MbedProviderBuilder, Provide,
    ProviderConfig, ProviderType,
};
use log::LevelFilter;
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use threadpool::{Builder as ThreadPoolBuilder, ThreadPool};

const VERSION_MINOR: u8 = 0;
const VERSION_MAJOR: u8 = 1;

type KeyIdManager = Arc<RwLock<dyn ManageKeyIDs + Send + Sync>>;
type Provider = Box<dyn Provide + Send + Sync>;

#[derive(Deserialize)]
pub struct CoreSettings {
    pub thread_pool_size: Option<usize>,
    pub idle_listener_sleep_duration: Option<u64>,
    pub log_level: Option<LevelFilter>,
    pub log_timestamp: Option<bool>,
}

#[derive(Deserialize)]
pub struct ServiceConfig {
    pub core_settings: CoreSettings,
    pub listener: ListenerConfig,
    pub key_manager: Vec<KeyIdManagerConfig>,
    pub provider: Vec<ProviderConfig>,
}

pub struct ServiceBuilder;

impl ServiceBuilder {
    pub fn build_service(config: &ServiceConfig) -> FrontEndHandler {
        let key_id_managers = build_key_id_managers(&config.key_manager);

        let providers = build_providers(&config.provider, key_id_managers);

        let backend_handlers = build_backend_handlers(providers);

        let dispatcher = DispatcherBuilder::new()
            .with_backends(backend_handlers)
            .build();

        let simple_authenticator = Box::from(SimpleAuthenticator {});

        FrontEndHandlerBuilder::new()
            .with_dispatcher(dispatcher)
            .with_authenticator(AuthType::Simple, simple_authenticator)
            .build()
    }

    pub fn start_listener(config: &ListenerConfig) -> Box<dyn Listen> {
        let listener = match config.listener_type {
            ListenerType::DomainSocket => DomainSocketListenerBuilder::new()
                .with_timeout(Duration::from_millis(config.timeout))
                .build(),
        };

        Box::new(listener)
    }

    pub fn build_threadpool(num_threads: Option<usize>) -> ThreadPool {
        let mut threadpool_builder = ThreadPoolBuilder::new();
        if let Some(num_threads) = num_threads {
            threadpool_builder = threadpool_builder.num_threads(num_threads);
        }
        threadpool_builder.build()
    }
}

fn build_backend_handlers(
    mut providers: HashMap<ProviderID, Provider>,
) -> HashMap<ProviderID, BackEndHandler> {
    let mut map = HashMap::new();

    let mut core_provider_builder =
        CoreProviderBuilder::new().with_version(VERSION_MINOR, VERSION_MAJOR);

    for (provider_id, provider) in providers.drain() {
        core_provider_builder = core_provider_builder.with_provider_info(provider.describe());

        let backend_handler = BackEndHandlerBuilder::new()
            .with_provider(provider)
            .with_converter(Box::from(ProtobufConverter {}))
            .with_provider_id(provider_id)
            .with_content_type(BodyType::Protobuf)
            .with_accept_type(BodyType::Protobuf)
            .with_version(VERSION_MINOR, VERSION_MAJOR)
            .build();
        map.insert(provider_id, backend_handler);
    }

    let core_provider_backend = BackEndHandlerBuilder::new()
        .with_provider(Box::from(core_provider_builder.build()))
        .with_converter(Box::from(ProtobufConverter {}))
        .with_provider_id(ProviderID::CoreProvider)
        .with_content_type(BodyType::Protobuf)
        .with_accept_type(BodyType::Protobuf)
        .with_version(VERSION_MINOR, VERSION_MAJOR)
        .build();

    map.insert(ProviderID::CoreProvider, core_provider_backend);

    map
}

fn build_providers(
    configs: &[ProviderConfig],
    key_id_managers: HashMap<String, KeyIdManager>,
) -> HashMap<ProviderID, Provider> {
    let mut map = HashMap::new();
    for config in configs {
        let key_id_manager = key_id_managers
            .get(&config.key_id_manager)
            .unwrap_or_else(|| {
                panic!(
                    "Key ID manager with specified name was not found ({})",
                    config.key_id_manager
                )
            });
        map.insert(
            config.provider_type.to_provider_id(),
            get_provider(config, key_id_manager.clone()),
        );
    }

    map
}

fn get_provider(config: &ProviderConfig, key_id_manager: KeyIdManager) -> Provider {
    match config.provider_type {
        ProviderType::MbedProvider => Box::from(
            MbedProviderBuilder::new()
                .with_key_id_store(key_id_manager)
                .build(),
        ),
    }
}

fn build_key_id_managers(configs: &[KeyIdManagerConfig]) -> HashMap<String, KeyIdManager> {
    let mut map = HashMap::new();
    for config in configs {
        map.insert(config.name.clone(), get_key_id_manager(config));
    }

    map
}

fn get_key_id_manager(config: &KeyIdManagerConfig) -> KeyIdManager {
    let manager = match config.manager_type {
        KeyIdManagerType::OnDisk => {
            let store_path = if let Some(store_path) = &config.store_path {
                store_path.to_owned()
            } else {
                DEFAULT_MAPPINGS_PATH.to_string()
            };

            OnDiskKeyIDManagerBuilder::new()
                .with_mappings_dir_path(PathBuf::from(store_path))
                .build()
        }
    };

    Arc::new(RwLock::new(manager))
}
