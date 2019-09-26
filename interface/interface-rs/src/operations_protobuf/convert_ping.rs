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
use super::generated_ops::ping::{OpPingProto, ResultPingProto};
use crate::operations;
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OpPingProto> for operations::OpPing {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OpPingProto) -> Result<Self, Self::Error> {
        Ok(operations::OpPing {})
    }
}

impl TryFrom<operations::OpPing> for OpPingProto {
    type Error = ResponseStatus;

    fn try_from(_proto_op: operations::OpPing) -> Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<operations::ResultPing> for ResultPingProto {
    type Error = ResponseStatus;

    fn try_from(result: operations::ResultPing) -> Result<Self, Self::Error> {
        let mut proto_response: ResultPingProto = Default::default();
        proto_response.supported_version_maj = u32::from(result.supp_version_maj);
        proto_response.supported_version_min = u32::from(result.supp_version_min);

        Ok(proto_response)
    }
}

impl TryFrom<ResultPingProto> for operations::ResultPing {
    type Error = ResponseStatus;

    fn try_from(response: ResultPingProto) -> Result<Self, Self::Error> {
        Ok(operations::ResultPing {
            supp_version_maj: u8::try_from(response.supported_version_maj)?,
            supp_version_min: u8::try_from(response.supported_version_min)?,
        })
    }
}

#[cfg(test)]
mod test {
    // OpPing <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::ping::ResultPingProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{NativeOperation, NativeResult, OpPing, ResultPing};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultPingProto = Default::default();
        proto.supported_version_maj = 1;
        proto.supported_version_min = 1;
        let resp: ResultPing = proto.try_into().unwrap();

        assert!(resp.supp_version_maj == 1);
        assert!(resp.supp_version_min == 1);
    }

    #[test]
    fn resp_to_proto() {
        let resp: ResultPing = ResultPing {
            supp_version_maj: 1,
            supp_version_min: 1,
        };

        let proto: ResultPing = resp.into();
        assert!(proto.supp_version_maj == 1);
        assert!(proto.supp_version_min == 1);
    }

    #[test]
    fn ping_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn op_ping_from_native() {
        let ping = OpPing {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::Ping(ping))
            .expect("Failed to convert request");
        assert!(body.len() == 0);
    }

    #[test]
    fn op_ping_e2e() {
        let ping = OpPing {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::Ping(ping))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_err());
    }

    #[test]
    fn ping_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_result(resp_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn result_ping_from_native() {
        let ping = ResultPing {
            supp_version_maj: 1,
            supp_version_min: 0,
        };

        let body = CONVERTER
            .result_to_body(NativeResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn ping_result_e2e() {
        let ping = ResultPing {
            supp_version_maj: 1,
            supp_version_min: 0,
        };

        let body = CONVERTER
            .result_to_body(NativeResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::Ping)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::Ping(result) => {
                assert_eq!(result.supp_version_maj, 1);
                assert_eq!(result.supp_version_min, 0);
            }
            _ => panic!("Expected ping"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER.body_to_result(resp_body, Opcode::Ping).is_err());
    }
}
