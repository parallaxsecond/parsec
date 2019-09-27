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
use parsec::authenticators::simple_authenticator::SimpleAuthenticator;
use parsec::back::{backend_handler::BackEndHandlerBuilder, dispatcher::DispatcherBuilder};
use parsec::front::{
    domain_socket::DomainSocketListenerBuilder, front_end::FrontEndHandler,
    front_end::FrontEndHandlerBuilder, listener::Listen,
};
use parsec::key_id_managers::on_disk_manager::OnDiskKeyIDManager;
use parsec::providers::{core_provider::CoreProviderBuilder, mbed_provider::MbedProvider, Provide};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;

const VERSION_MINOR: u8 = 0;
const VERSION_MAJOR: u8 = 1;

/// Build all the components needed for the service.
//TODO: The component should be configured with a .toml (or similar) kind of file.
fn build_components() -> (FrontEndHandler, impl Listen) {
    let mbed_provider = MbedProvider::new(Arc::new(RwLock::new(
        OnDiskKeyIDManager::new(PathBuf::from("mappings"))
            .expect("Error when loading the Key ID mappings."),
    )))
    .expect("Error when creating the Mbed Provider.");

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

    let front_end = FrontEndHandlerBuilder::new()
        .with_dispatcher(dispatcher)
        .with_authenticator(AuthType::Simple, simple_authenticator)
        .build();

    // This function currently only returns a DomainSocketListener but in the future, depending on
    // the configuration it would return anything implementing Listen.
    let listener = DomainSocketListenerBuilder::new()
        //TODO: this value should come from the configuration.
        .with_timeout(Duration::from_millis(100))
        .build();
    (front_end, listener)
}

fn main() {
    let (front_end_handler, mut listener) = build_components();
    // Multiple threads can not just have a reference of the front end handler because they could
    // outlive the run function. It is needed to give them all ownership of the front end handler
    // through an Arc.
    let front_end_handler = Arc::from(front_end_handler);

    listener.init();

    loop {
        if let Some(stream) = listener.wait_on_connection() {
            let front_end_handler = front_end_handler.clone();
            thread::spawn(move || {
                front_end_handler.handle_request(stream);
            });
        } else {
            println!("Error on establishing last connection, continuing...");
        }
    }
}
