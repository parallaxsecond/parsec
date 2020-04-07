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

<p align="center">
  <img src="./doc/images/parsec/ARM1007_PARSEC Logo_ST2_RGB_Stacked_Colour.png" alt="Parsec logo"/>
  <br><br>
  <a href="https://github.com/parallaxsecond/parsec/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/parsec/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
  <a href="https://travis-ci.com/parallaxsecond/parsec"><img src="https://travis-ci.com/parallaxsecond/parsec.svg?branch=master" alt="Travis CI tests"/></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
</p>

# Welcome To PARSEC

**PARSEC** is the **P**latform **A**bst**R**action for **SEC**urity, a new open-source initiative
to provide a common API to hardware security and cryptographic services in a platform-agnostic way. This abstraction layer keeps workloads decoupled from physical platform details, enabling cloud-native delivery flows within the data center and at the edge.

<p align="center">
  <img src="./doc/images/parsec/ParsecConceptDiagram.png" alt="Parsec Concept Diagram"/>
</p>

Read the Parsec documentation [online](https://parallaxsecond.github.io/parsec-book/).

Read the whitepaper [Security for the Infrastructure Edge](https://www.arm.com/-/media/global/people/Security-For-The-Infrastructure-Edge-White-paper-NDA).


# Why PARSEC?

Use Parsec when you need:

- A **portable interface to your platform's Root of Trust** in order to manage keys and perform cryptographic operations without knowledge of the hardware.
- A simple and portable way to access the **best available security** of your platform in your **preferred programming language**.

# What PARSEC Provides

The value proposition of Parsec is that it provides the following:

- **Abstraction** – a common API that is truly agnostic and based on modern cryptographic principles
- **Mediation** – security as a microservice, brokering access to the hardware and providing isolated key stores in a multi-tenant environment
- **Ergonomics** – a client library ecosystem that brings the API to the fingertips of developers in any programming language: “easy to consume, hard to get wrong”
- **Openness** – an open-source project inviting contributions to enhance the ecosystem both within the service and among its client libraries

# Maintainers

PARSEC is a collaborative project. The current list of the individuals and organizations who maintain this project can be found [**here**](./MAINTAINERS.toml).

# Partner Organizations

See who is [**using and contributing to PARSEC**](./PARTNERS.md).

# Disclaimer

Parsec is an open source project and is under development. This code repository is being made
available so that the developer community can learn and give feedback about the new interfaces and the concepts of platform-agnostic security.
The implementation that is provided is suitable for exploratory testing and experimentation only.
This test implementation does not offer any tangible security benefits and therefore is not
suitable for use in production. Documentation pages may be incomplete and are subject to change
without notice. Interfaces may change in such a way as to break compatibility with client code.
Contributions from the developer community are welcome. Please refer to the contribution guidelines.

# Example

Launch the Parsec service with a single software-based provider (using the default configuration):
```bash
$ git clone https://github.com/parallaxsecond/parsec.git
$ cd parsec
$ RUST_LOG=info cargo run
```

Parsec Client Libraries can now communicate with the service. For example using the Rust Test client,
RSA signatures can be done as follows:
```rust
use parsec_client_test::TestClient;

let mut client = TestClient::new();
let key_name = String::from("🔑 What shall I sign? 🔑");
client.create_rsa_sign_key(key_name.clone()).unwrap();
let signature = client.sign(key_name,
                            String::from("Platform AbstRaction for SECurity").into_bytes())
                      .unwrap();
```

Check the [**user**](https://parallaxsecond.github.io/parsec-book/parsec_users.html), [**client developer**](https://parallaxsecond.github.io/parsec-book/parsec_client/index.html) and [**service developer**](https://parallaxsecond.github.io/parsec-book/parsec_service/index.html) guides for more information on building, installing, testing and using Parsec!

# Community Channel and Meetings

Come and talk to us in [our Slack channel](https://app.slack.com/client/T0JK1PCN6/CPMQ9D4H1)!
[Here](http://dockr.ly/slack) is how to join the workspace.

Also join the [**biweekly meeting**](https://calendar.google.com/calendar?cid=ZG9ja2VyLmNvbV9xcHAzbzl2aXBhbmE0NGllcmV1MjlvcHZkNEBncm91cC5jYWxlbmRhci5nb29nbGUuY29t)
with Parsec maintainers and community members.
The meeting is open to the public and everyone is encouraged to attend. We will use the time to
discuss features, integrations, issues, and roadmap. We look forward to seeing you all.

# Contributing

We would be happy for you to contribute to Parsec! Check the [**Contributing**](CONTRIBUTING.md)
file to know more about the contribution process.
Check the [open issues](https://github.com/orgs/parallaxsecond/projects/1) on the board if you
need any ideas 🙂!

# License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* serde (MIT and Apache-2.0)
* bindgen (BSD-3-Clause)
* cargo\_toml (Apache-2.0)
* toml (MIT and Apache-2.0)
* rand (MIT and Apache-2.0)
* base64 (MIT and Apache-2.0)
* uuid (MIT and Apache-2.0)
* threadpool (MIT and Apache-2.0)
* std-semaphore (MIT and Apache-2.0)
* num\_cpus (MIT and Apache-2.0)
* signal-hook (MIT and Apache-2.0)
* sd-notify (MIT and Apache-2.0)
* log (MIT and Apache-2.0)
* env\_logger (MIT and Apache-2.0)
* pkcs11 (Apache-2.0)
* picky-asn1-der (MIT and Apache-2.0)
* picky-asn1 (MIT and Apache-2.0)
* bincode (MIT)
* structopt (MIT and Apache-2.0)
* derivative (MIT and Apache-2.0)
* arbitrary (MIT and Apache-2.0)
* libfuzzer-sys (MIT, Apache-2.0 and NCSA)
* flexi_logger (MIT and Apache-2.0)
* lazy_static (MIT and Apache-2.0)
* version (MIT and Apache-2.0)

This project uses the following third party libraries:
* [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto) (Apache-2.0)
