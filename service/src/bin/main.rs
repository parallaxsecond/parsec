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
use interface::operations_protobuf::ProtobufConverter;
use interface::requests::AuthType;
use interface::requests::{BodyType, ProviderID};
use service::authenticators::simple_authenticator::SimpleAuthenticator;
use service::authenticators::Authenticate;
use service::back::{backend_handler::BackEndHandler, dispatcher::Dispatcher};
use service::front::{
    domain_socket::DomainSocketListener, front_end::FrontEndHandler, listener::Listen,
};
use service::key_id_managers::simple_manager::SimpleKeyIDManager;
use service::providers::{core_provider::CoreProvider, mbed_provider::MbedProvider, Provide};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

const VERSION_MINOR: u8 = 0;
const VERSION_MAJOR: u8 = 1;

/// Construct a hardcoded version of the service, containing only the core provider.
fn construct_app() -> Box<dyn Listen> {
    // Create the Core Provider and its associated BackEndHandler
    let core_provider_id = ProviderID::CoreProvider;
    let core_provider_backend = BackEndHandler {
        provider: Box::from(CoreProvider {
            version_min: VERSION_MINOR,
            version_maj: VERSION_MAJOR,
        }),
        converter: Box::from(ProtobufConverter {}),
        provider_id: core_provider_id,
        content_type: BodyType::Protobuf,
        accept_type: BodyType::Protobuf,
        version_min: VERSION_MINOR,
        version_maj: VERSION_MAJOR,
    };

    let mbed_provider = MbedProvider {
        key_id_store: Arc::new(RwLock::new(Box::new(SimpleKeyIDManager {
            key_store: HashMap::new(),
        }))),
        local_ids: RwLock::new(HashSet::new()),
    };
    if mbed_provider.init() {
        println!("Init successful");
    } else {
        panic!("mbed not started");
    }

    let mbed_backend_handler = BackEndHandler {
        provider: Box::from(mbed_provider),
        converter: Box::from(ProtobufConverter {}),
        provider_id: ProviderID::MbedProvider,
        content_type: BodyType::Protobuf,
        accept_type: BodyType::Protobuf,
        version_min: VERSION_MINOR,
        version_maj: VERSION_MAJOR,
    };

    // Add the BackEndHandler structures to the Dispatcher
    let mut backends: HashMap<ProviderID, BackEndHandler> = HashMap::new();
    backends.insert(core_provider_id, core_provider_backend);
    backends.insert(ProviderID::MbedProvider, mbed_backend_handler);

    let dispatcher = Dispatcher { backends };
    let simple_authenticator = Box::from(SimpleAuthenticator {});
    let mut authenticators: HashMap<AuthType, Box<dyn Authenticate + Send + Sync>> = HashMap::new();
    authenticators.insert(AuthType::Simple, simple_authenticator);
    let front_end = FrontEndHandler {
        dispatcher,
        authenticators,
    };

    Box::from(DomainSocketListener {
        front_end_handler: Arc::from(front_end),
        listener: None,
    })
}

fn main() {
    let mut listener = construct_app();

    listener.init();
    listener.run();
}
