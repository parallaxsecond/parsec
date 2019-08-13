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
mod convert_ping;

#[rustfmt::skip]
mod generated_ops;

use crate::operations::{Convert, ConvertOperation, ConvertResult};
use crate::requests::{
    request::RequestBody,
    response::{ResponseBody, ResponseStatus},
    Opcode,
};
use generated_ops::ping::{OpPingProto, ResultPingProto};
use prost::Message;

macro_rules! wire_to_native {
    ($body:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = Default::default();
        if proto.merge($body).is_err() {
            return Err(ResponseStatus::DeserializingBodyFailed);
        }
        proto.into()
    }};
}

macro_rules! native_to_wire {
    ($native_msg:expr, $proto_type:ty) => {{
        let proto: $proto_type = $native_msg.into();
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_to_operation(
        &self,
        body: &RequestBody,
        opcode: Opcode,
    ) -> Result<ConvertOperation, ResponseStatus> {
        match opcode {
            Opcode::Ping => Ok(ConvertOperation::Ping(wire_to_native!(
                body.bytes(),
                OpPingProto
            ))),
        }
    }

    fn body_from_operation(
        &self,
        operation: ConvertOperation,
    ) -> Result<RequestBody, ResponseStatus> {
        match operation {
            ConvertOperation::Ping(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpPingProto
            ))),
        }
    }

    fn body_to_result(
        &self,
        body: &ResponseBody,
        opcode: Opcode,
    ) -> Result<ConvertResult, ResponseStatus> {
        match opcode {
            Opcode::Ping => Ok(ConvertResult::Ping(wire_to_native!(
                body.bytes(),
                ResultPingProto
            ))),
        }
    }

    fn body_from_result(&self, result: ConvertResult) -> Result<ResponseBody, ResponseStatus> {
        match result {
            ConvertResult::Ping(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultPingProto
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Convert, ProtobufConverter};
    use crate::operations::{ConvertOperation, ConvertResult, OpPing, ResultPing};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn ping_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_operation(&req_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn op_ping_from_native() {
        let ping = OpPing {};
        let body = CONVERTER
            .body_from_operation(ConvertOperation::Ping(ping))
            .expect("Failed to convert request");
        assert!(body.len() == 0);
    }

    #[test]
    fn op_ping_e2e() {
        let ping = OpPing {};
        let body = CONVERTER
            .body_from_operation(ConvertOperation::Ping(ping))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_operation(&body, Opcode::Ping).is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(&req_body, Opcode::Ping)
            .is_err());
    }

    #[test]
    fn ping_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_result(&resp_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn result_ping_from_native() {
        let ping = ResultPing {
            supp_version_maj: 1,
            supp_version_min: 0,
        };

        let body = CONVERTER
            .body_from_result(ConvertResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(body.len() != 0);
    }

    #[test]
    fn ping_result_e2e() {
        let ping = ResultPing {
            supp_version_maj: 1,
            supp_version_min: 0,
        };

        let body = CONVERTER
            .body_from_result(ConvertResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(body.len() != 0);

        let result = CONVERTER
            .body_to_result(&body, Opcode::Ping)
            .expect("Failed to convert back to result");

        match result {
            ConvertResult::Ping(result) => {
                assert_eq!(result.supp_version_maj, 1);
                assert_eq!(result.supp_version_min, 0);
            }
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER.body_to_result(&resp_body, Opcode::Ping).is_err());
    }
}
