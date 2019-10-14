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
use parsec::key_id_managers::on_disk_manager::OnDiskKeyIDManagerBuilder;
use parsec::providers::{
    core_provider::CoreProviderBuilder, mbed_provider::MbedProviderBuilder, Provide,
};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use signal_hook::flag;
use signal_hook::SIGTERM;
use std::io::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;
use threadpool::Builder;

const VERSION_MINOR: u8 = 0;
const VERSION_MAJOR: u8 = 1;

/// Build all the components needed for the service.
//TODO: The component should be configured with a .toml (or similar) kind of file.
fn build_components() -> (FrontEndHandler, impl Listen) {
    let on_disk_key_id_manager = Arc::new(RwLock::new(
        OnDiskKeyIDManagerBuilder::new()
            .with_mappings_dir_path(PathBuf::from("mappings"))
            .build(),
    ));
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

fn main() -> Result<(), Error> {
    let (front_end_handler, listener) = build_components();
    // Multiple threads can not just have a reference of the front end handler because they could
    // outlive the run function. It is needed to give them all ownership of the front end handler
    // through an Arc.
    let front_end_handler = Arc::from(front_end_handler);

    // Register a boolean set to true when the SIGTERM signal is received.
    let kill_signal = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, kill_signal.clone())?;

    let threadpool = Builder::new().build();

    loop {
        if kill_signal.load(Ordering::Relaxed) {
            println!("SIGTERM signal received.");
            break;
        }

        if let Some(stream) = listener.accept() {
            let front_end_handler = front_end_handler.clone();
            threadpool.execute(move || {
                front_end_handler.handle_request(stream);
            });
        } else {
            //TODO: this value should come from the configuration.
            thread::sleep(Duration::from_millis(10));
        }
    }

    println!("Shutting down PARSEC, waiting for all threads to finish.");
    threadpool.join();

    Ok(())
}
