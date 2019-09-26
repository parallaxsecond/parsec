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
use super::generated_ops::list_providers::{
    OpListProvidersProto, ProviderInfoProto, ResultListProvidersProto,
};
use crate::operations::{OpListProviders, ProviderInfo, ResultListProviders};
use crate::requests::{ProviderID, ResponseStatus};
use num::FromPrimitive;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OpListProvidersProto> for OpListProviders {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OpListProvidersProto) -> Result<Self, Self::Error> {
        Ok(OpListProviders {})
    }
}

impl TryFrom<OpListProviders> for OpListProvidersProto {
    type Error = ResponseStatus;

    fn try_from(_op: OpListProviders) -> Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<ProviderInfoProto> for ProviderInfo {
    type Error = ResponseStatus;

    fn try_from(proto_info: ProviderInfoProto) -> Result<Self, Self::Error> {
        let id: ProviderID = match FromPrimitive::from_u32(proto_info.id) {
            Some(id) => id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        Ok(ProviderInfo {
            id,
            description: proto_info.description,
        })
    }
}

impl TryFrom<ProviderInfo> for ProviderInfoProto {
    type Error = ResponseStatus;

    fn try_from(info: ProviderInfo) -> Result<Self, Self::Error> {
        Ok(ProviderInfoProto {
            id: info.id as u32,
            description: info.description,
        })
    }
}

impl TryFrom<ResultListProvidersProto> for ResultListProviders {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultListProvidersProto) -> Result<Self, Self::Error> {
        let mut providers: Vec<ProviderInfo> = Vec::new();
        for provider in proto_op.providers {
            providers.push(provider.try_into()?);
        }

        Ok(ResultListProviders { providers })
    }
}

impl TryFrom<ResultListProviders> for ResultListProvidersProto {
    type Error = ResponseStatus;

    fn try_from(op: ResultListProviders) -> Result<Self, Self::Error> {
        let mut providers: Vec<ProviderInfoProto> = Vec::new();
        for provider in op.providers {
            providers.push(provider.try_into()?);
        }

        Ok(ResultListProvidersProto { providers })
    }
}

#[cfg(test)]
mod test {
    // OpListProviders <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_providers::{
        ProviderInfoProto, ResultListProvidersProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        NativeOperation, NativeResult, OpListProviders, ProviderInfo, ResultListProviders,
    };
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, ProviderID};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultListProvidersProto = Default::default();
        let mut provider_info = ProviderInfoProto::default();
        provider_info.id = 1;
        provider_info.description = String::from("provider description");
        proto.providers.push(provider_info);
        let resp: ResultListProviders = proto.try_into().unwrap();

        assert_eq!(resp.providers.len(), 1);
        assert_eq!(resp.providers[0].id, ProviderID::MbedProvider);
        assert_eq!(resp.providers[0].description, "provider description");
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: ResultListProviders = ResultListProviders {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            id: ProviderID::MbedProvider,
            description: String::from("provider description"),
        };
        resp.providers.push(provider_info);

        let proto: ResultListProvidersProto = resp.try_into().unwrap();
        assert_eq!(proto.providers.len(), 1);
        assert_eq!(proto.providers[0].id, 1);
        assert_eq!(proto.providers[0].description, "provider description");
    }

    #[test]
    fn list_providers_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn op_list_providers_from_native() {
        let list_providers = OpListProviders {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListProviders(list_providers))
            .expect("Failed to convert request");
        assert!(body.len() == 0);
    }

    #[test]
    fn op_list_providers_e2e() {
        let list_providers = OpListProviders {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListProviders(list_providers))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_err());
    }

    #[test]
    fn list_providers_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn result_list_providers_from_native() {
        let mut list_providers = ResultListProviders {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            id: ProviderID::MbedProvider,
            description: String::from("provider description"),
        };
        list_providers.providers.push(provider_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListProviders(list_providers))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_providers_result_e2e() {
        let mut list_providers = ResultListProviders {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            id: ProviderID::MbedProvider,
            description: String::from("provider description"),
        };
        list_providers.providers.push(provider_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListProviders(list_providers))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListProviders)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListProviders(result) => {
                assert_eq!(result.providers.len(), 1);
            }
            _ => panic!("Expected list_providers"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListProviders)
            .is_err());
    }
}
