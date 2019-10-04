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
# **Providers**

This document offers details on the currently supported providers.

For information regarding the function providers play in the Parsec service, read the [*Interfaces and Dataflow*](/interfaces_and_dataflow.md) doc. For details on how the service code is structured around providers, read the [*Source Code Structure*](/source_code_structure.md) doc.

## **Core Provider**
**Provider UUID: 47049873-2a43-4845-9d72-831eab668784**

The core provider is a non-cryptographic provider, tasked with storing and distributing both static and dynamic information about the service. It is the base for 

One instance of the core provider must always be running with a provider ID of 0. 

## **Mbed Provider**
**Provider UUID: 1c1139dc-ad7c-47dc-ad6b-db6fdb466552**

The Mbed provider is a software-based provider built on top of Mbed Crypto - the reference implementation of the PSA cryptography specification. Mbed Crypto is loaded as a static library and executes with the rest of the service in user-space. 

The software version of the Mbed provider is meant as a proof-of-concept and should not be used in real-world environments. Future improvements will expand the security guarantee of Mbed Crypto-based providers. 