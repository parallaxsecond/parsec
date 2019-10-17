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
use crate::back::{backend_handler::BackEndHandlerBuilder, dispatcher::DispatcherBuilder};
use crate::front::listener::{ListenerConfig, ListenerType};
use crate::front::{
    domain_socket::DomainSocketListenerBuilder, front_end::FrontEndHandler,
    front_end::FrontEndHandlerBuilder, listener::Listen,
};
use crate::key_id_managers::on_disk_manager::{OnDiskKeyIDManagerBuilder, DEFAULT_MAPPINGS_PATH};
use crate::key_id_managers::{KeyIdManagerConfig, KeyIdManagerType, ManageKeyIDs};
use crate::providers::{
    core_provider::CoreProviderBuilder, mbed_provider::MbedProviderBuilder, Provide,
};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use threadpool::{Builder as ThreadPoolBuilder, ThreadPool};

const VERSION_MINOR: u8 = 0;
const VERSION_MAJOR: u8 = 1;

#[derive(Deserialize)]
pub struct CoreSettings {
    pub thread_pool_size: Option<usize>,

    #[serde(default)]
    pub idle_listener_sleep_duration: Option<u64>,
}

#[derive(Deserialize)]
pub struct ServiceConfig {
    pub core_settings: CoreSettings,
    pub listener: ListenerConfig,
    pub key_manager: KeyIdManagerConfig,
}

pub struct ServiceBuilder;

impl ServiceBuilder {
    pub fn build_service(config: &ServiceConfig) -> FrontEndHandler {
        let on_disk_key_id_manager = get_key_id_manager(&config.key_manager);
        let mbed_provider = MbedProviderBuilder::new()
            .with_key_id_store(on_disk_key_id_manager)
            .build();

        // Store provider descriptions in it.
        let core_provider = CoreProviderBuilder::new()
            .with_version(VERSION_MINOR, VERSION_MAJOR)
            .with_provider_info(mbed_provider.describe())
            .build();

        let mbed_backend_handler = BackEndHandlerBuilder::new()
            .with_provider(Box::from(mbed_provider))
            .with_converter(Box::from(ProtobufConverter {}))
            .with_provider_id(ProviderID::MbedProvider)
            .with_content_type(BodyType::Protobuf)
            .with_accept_type(BodyType::Protobuf)
            .with_version(VERSION_MINOR, VERSION_MAJOR)
            .build();

        let core_provider_backend = BackEndHandlerBuilder::new()
            .with_provider(Box::from(core_provider))
            .with_converter(Box::from(ProtobufConverter {}))
            .with_provider_id(ProviderID::CoreProvider)
            .with_content_type(BodyType::Protobuf)
            .with_accept_type(BodyType::Protobuf)
            .with_version(VERSION_MINOR, VERSION_MAJOR)
            .build();

        let dispatcher = DispatcherBuilder::new()
            .with_backend(ProviderID::CoreProvider, core_provider_backend)
            .with_backend(ProviderID::MbedProvider, mbed_backend_handler)
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

fn get_key_id_manager(config: &KeyIdManagerConfig) -> Arc<RwLock<dyn ManageKeyIDs + Send + Sync>> {
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
