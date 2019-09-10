<!--
  -- Copyright (c) 2019, Arm Limited, All Rights Reserved
  -- SPDX-License-Identifier: Apache-2.0
  --
  -- Licensed under the Apache License, Version 2.0 (the "License"); you may
  -- not use this file except in compliance with the License.
  -- You may obtain a copy of the License at
  --
  -- http://www.apache.org/licenses/LICENSE-2.0
  --
  -- Unless required by applicable law or agreed to in writing, software
  -- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  -- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  -- See the License for the specific language governing permissions and
  -- limitations under the License.
--->
# Platform AbstRaction for SECurity

The PARSEC project contains code to provide a Linux system daemon that will provide developer APIs to a set of crypto services that closely follow the PSA Crypto APIs.
For more information, please read the following documents:
* [Source Code Structure](docs/source_code_structure.md)
* [Interfaces and Dataflow](docs/interfaces_and_dataflow.md)
* [Wire Protocol](docs/wire_protocol.md)

# DISCLAIMER

PARSEC is a new open source project and is under development. This code repository is being made
available so that the developer community can learn and give feedback about the new interfaces.
The implementation that is provided is suitable for exploratory testing and experimentation only.
This test implementation does not offer any tangible security benefits and therefore is not
suitable for use in production. Documentation pages may be incomplete and are subject to change
without notice. Interfaces may change in such a way as to break compatibility with client code.
Contributions from the developer community are welcome. Please refer to the contribution guidelines.

# License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* serde (Apache-2.0)
* bincode (MIT)
* num-traits (MIT and Apache-2.0)
* num-derive (MIT and Apache-2.0)
* prost-build (Apache-2.0)
* prost (Apache-2.0)
* bytes (MIT)
* num (MIT and Apache-2.0)
* bindgen (BSD-3-Clause)
* cargo\_toml (Apache-2.0)
* toml (MIT and Apache-2.0)
* rand (MIT and Apache-2.0)

This project uses the following third party libraries:
* [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto) (Apache-2.0)

# User Guide

This project is coded in the Rust Programming Language. To build it, you first need to [install Rust](https://www.rust-lang.org/tools/install).
To build and run the service, execute `cargo run` inside `service/`. The service will then wait for clients.

## Testing

You can unit test the `integration-rs` and `service` crates executing `cargo test` inside those.
You can perform an integration test by running the service first and then executing `cargo test` inside the `minimal_client` crate in `test/test_rs/minimal_client`.
The `test/ci/all.sh` script executes all of the unit tests and integration tests.

# Contributing

Please check the [Contributing](CONTRIBUTING.md) to know more about the contribution process.

