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

![PARSEC](PARSEC.png)
# **Welcome to PARSEC**

![](https://github.com/parallaxsecond/parsec/workflows/Continuous%20Integration/badge.svg)

**PARSEC** is the **P**latform **A**bst**R**action for **SEC**urity, a new open-source initiative to provide a common API to secure services in a platform-agnostic way.

PARSEC aims to define a universal software standard for interacting with secure object storage and cryptography services, creating a common way to interface with functions that would traditionally have been accessed by more specialised APIs. PARSEC establishes an ecosystem of developer-friendly libraries in a variety of popular programming languages. Each library is designed to be highly ergonomic and simple to consume. This growing ecosystem will put secure facilities at the fingertips of developers across a broad range of use cases in infrastructure computing, edge computing and the secure Internet of Things.

# **Why Platform-Agnostic Security?**
Today's computing platforms have evolved to offer a range of facilities for secure storage and secure operations. There are hardware-backed facilities such as the Hardware Security Module (HSM) or Trusted Platform Module (TPM). There are firmware services running in Trusted Execution Environments (TEE). There are also cloud-based security services. At a bare minimum, security facilities may be provided purely in software, where they are protected by mechanisms provided in the operating system.

Over the years, software standards have emerged to allow developers to use these facilities from their applications. But these standards bring with them the following challenges:

* They are defined with the expectation that the caller is the "owner" of the platform, meaning that it has sole access to the underlying hardware. In reality, this is often not the case, because the caller might reside in a container or virtual machine, where it is sharing the host hardware with other applications. Existing software standards do not cater well for this situation.
* They are defined exhaustively, with lengthy specifications detailing all permissible operations and parameters. They are written from the perspective of the security device and its capabilities, rather than from the perspective of the application and its use case. This can offer a daunting and bewildering experience for developers, who spend a lot of time and effort figuring out how to map their use case onto the API. There is nothing to tailor the API so that it can be consumed easily for common, simple cases.
* They are specific to a programming language such as C. To consume them in other languages, it is necessary to use interoperability layers such as Foreign Function Interface (FFI), which can make the developer experience even more cumbersome and unnatural. Interoperability layers can also be a source of vulnerabilities.
* Standards tend to be adopted based on some knowledge of the target platform. So while it might be possible for code to be portable across multiple HSM vendors, for example, it is much harder to make code portable between an HSM-based platform and a TPM-based platform.

PARSEC inverts this traditional approach to standardizing security interfaces, and it does so by putting applications front and center. It offers an API that is no less comprehensive, but it does so in a way that puts the needs of applications and their common use cases first.

Applications simply want the best-available security, and they want to be able to consume it in a way that is simple, natural, and hard to get wrong.

The following observations can be made about such applications:

* They can be written in a variety of programming languages.

* They may be written with no explicit knowledge of the hardware capabilities of the target platform, such as whether an HSM or TPM is available.

* They are often sharing the target platform hardware with other applications due to the use of virtualization or containerization technology.

* The secure assets owned by one application must be isolated from those owned by another. For example, private keys provisioned on a hardware device must be isolated such that only the provisioning application would be able to perform subsequent operations with those keys.

* They have differing requirements in terms of permissible cryptographic algorithms and key strengths.

These observations motivate the need for a new platform abstraction that offers a common palette of security primitives via a software interface that is both agnostic with respect to the underlying hardware capabilities, and also capable of supporting multiple client applications on the same host, whether those be within containers or within traditional virtual machines.

PARSEC is a new software architecture and ecosystem that addresses this need.

# **Basis in Platform Security Architecture**
PARSEC is founded on the [**Platform Security Architecture (PSA)**](https://developer.arm.com/architectures/security-architectures/platform-security-architecture). The PSA is a holistic set of threat models, security analyses, hardware and firmware architecture specifications, and an open source firmware reference implementation. The PSA provides a recipe, based on industry best practice, that allows security to be consistently designed in, at both a hardware and firmware level.

One of the provisions of the PSA is the [**PSA Crypto API**](https://github.com/ARMmbed/mbed-crypto/blob/psa-crypto-api/docs/PSA_Cryptography_API_Specification.pdf). The PSA Crypto API is a comprehensive library of modern security primitives covering the following functional areas:

* Key provisioning and management
* Hashing
* Signing
* Message Authentication Codes (MAC)
* Asymmetric encryption
* Symmetric encryption
* Authenticated Encryption with Associated Data (AEAD)
* Key derivation
* Entropy (random number generation)

A crucial characteristic of the PSA Crypto API is that applications always reference the keys opaquely, making it ideally suited to implementations where keys are provisioned within hardware and are never exposed.

The PSA Crypto API is defined in the C language. PARSEC adopts the operations and contracts of the C API, and uses them as the basis for a language-independent **wire protocol**. Each operation is defined, along with all of its inputs and outputs, as a serializable contract, making it suitable to be invoked over an Inter-Process Communication (IPC) transport. PARSEC maintains functional equivalence with the PSA Crypto API, but allows for out-of-process callers in any programming language.

# **The PARSEC Service**
The core component of PARSEC is the **security service** (or **security daemon**). This is a background process that runs on the host platform and provides connectivity with the secure facilities of that host and surfaces the wire protocol based on PSA Crypto.

The security service listens on a suitable transport medium. The transport technology is one of PARSEC's many pluggable components, and no single transport is mandated. Choice of transport is dependent on the operating system and the deployment. On Linux-based systems where the client applications are running in containers (isolation with a shared kernel), the transport can be based on Unix sockets.

Client applications make connections with the service by posting API requests to the transport endpoint. This is usually done via a client library that hides the details of both the wire protocol and the transport. This is one of the ways in which the client library simplifies the experience of PARSEC for application developers.

A single instance of the PARSEC service executes on each physical host. In virtualized environments, the PARSEC service may reside on a specially-assigned guest, or potentially within the hypervisor.

The security service does not support remote client applications. Each physical host or node must have its own instance of the service. However, it is possible for the service to initiate outbound remote calls of other services, such as cloud-hosted HSM services.

# **Multitenancy and Access Control**
In addition to surfacing the common API, the PARSEC service is also responsible for brokering access to the underlying security facilities amongst the multiple client applications. The exact way that this is done will vary from one deployment to another. (See the section below on pluggable back-end modules). Some of the brokering functionality may already reside in kernel drivers and other parts of the software stack. The PARSEC service is responsible for creating isolated views of key storage and cryptographic services for each client application. The secure assets of one client must be kept protected from those of another.

Central to this multi-tenant operation is the notion of **application identity** and the need for a separate **identity provider** service. A PARSEC-enabled host must contain an identity provider service in addition to the PARSEC service itself.

For more information about application identities and the identity provider, please refer to the [**system architecture**](docs/system_architecture.md) document.

# **Pluggable Back-End Modules**
The PARSEC service employs a layered architecture, structured into a front-end and a back-end.

The front-end module provides the transport endpoint and listens for connections from clients. The front-end understands the wire protocol and the common API. It is responsible for serialization and de-serialization of the operation contracts.

The back-end modules are known as **providers**. An instance of the PARSEC security service can load one or more providers. Providers implement the API operations using platform-specific or vendor-specific code. They provide the "last mile" of connectivity down to the underlying hardware, software or firmware.

For a deeper dive into the modular structure of the PARSEC service, please take a look at the [**interfaces and dataflow**](docs/interfaces_and_dataflow.md) design document.

Then delve into the [**source code**](docs/source_code_structure.md) to discover the back-end provider modules that exist. If you cannot find one that is compatible with the platform you intend to use, then please consider contributing a new provider.

# **Beautiful Client Libraries**
A key aim of PARSEC is to evolve an ecosystem of developer-friendly client libraries in multiple programming languages.

PARSEC avoids the cumbersome, auto-generated language bindings that are so often a part of standardized interfaces.

PARSEC's client libraries are beautiful.

Each client library is carefully crafted to follow the idioms of the language that it targets. Consuming a PARSEC client library will always feel natural to a developer who works in that language. Everything from naming conventions to object lifecycle will be blended to create a highly-idiomatic developer experience.

But PARSEC's focus on developer ergonomics goes further than this. PARSEC's client interface is filled with conveniences to eliminate complexity unless complexity is required. The PARSEC API is functionally equivalent with the PSA Crypto API, and none of this functional completeness is lost in the client layer. All possible variants of key type and algorithm type are exposed in case they are needed. But the client library offers smart default behaviours so that simple use cases can be achieved with very little code. PARSEC enables client code to be small and elegant. And even if it needs to be less small, it should still be elegant.

# **Writing A Client Library**
If a client library does not already exist in your preferred programming language, you can create one. Writing a new client library is a great way to enhance the PARSEC client ecosystem.

When creating a new client library, please make sure you understand the PARSEC philosophy for client libraries that is set out in the section above. It is very important that you design your client library to provide a highly ergonomic and idiomatic developer experience.

Take a look at the [**client library for Go**](https://github.com/parallaxsecond/parsec-client-go) as an example.

You will need to understand the [**wire protocol specification**](docs/wire_protocol.md) and the [**API specification**](docs/api_overview.md) in depth in order to create a client library.


# **License**

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* serde (Apache-2.0)
* bindgen (BSD-3-Clause)
* cargo\_toml (Apache-2.0)
* toml (MIT and Apache-2.0)
* rand (MIT and Apache-2.0)
* base64 (MIT and Apache-2.0)
* uuid (Apache-2.0)
* threadpool (Apache-2.0)

This project uses the following third party libraries:
* [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto) (Apache-2.0)

# **Source Code Structure**
PARSEC is composed of multiple code repositories. The repository that you are currently viewing contains the PARSEC security service itself. For more information about how the code in the repository is organized, please see the [**source code structure**](docs/source_code_structure.md) document.

# **Building the PARSEC Service**

This project is coded in the Rust Programming Language. To build it, you first need to [install Rust](https://www.rust-lang.org/tools/install).
To build and run the service, execute `cargo run`. `parsec` will then wait for clients.

# **Testing the PARSEC Service**

The `tests/all.sh` script executes all tests.

You can execute unit tests with `cargo test --lib`.

The [test client](https://github.com/parallaxsecond/parsec-client-test) is used for integration
testing. Check that repository for more details.

# **Contributing**

Please check the [**Contributing**](CONTRIBUTING.md) to know more about the contribution process.

# **DISCLAIMER**

PARSEC is a new open source project and is under development. This code repository is being made
available so that the developer community can learn and give feedback about the new interfaces and the concepts of platform-agnostic security.
The implementation that is provided is suitable for exploratory testing and experimentation only.
This test implementation does not offer any tangible security benefits and therefore is not
suitable for use in production. Documentation pages may be incomplete and are subject to change
without notice. Interfaces may change in such a way as to break compatibility with client code.
Contributions from the developer community are welcome. Please refer to the contribution guidelines.
