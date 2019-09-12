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
use super::generated_ops::destroy_key::{OpDestroyKeyProto, ResultDestroyKeyProto};
use crate::operations::{OpDestroyKey, ResultDestroyKey};
use crate::requests::ResponseStatus;
use num::FromPrimitive;
use std::convert::TryFrom;

impl TryFrom<OpDestroyKeyProto> for OpDestroyKey {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpDestroyKeyProto) -> Result<Self, Self::Error> {
        Ok(OpDestroyKey {
            key_name: proto_op.key_name,
            key_lifetime: FromPrimitive::from_i32(proto_op.key_lifetime)
                .expect("Failed to convert key lifetime"),
        })
    }
}

impl TryFrom<OpDestroyKey> for OpDestroyKeyProto {
    type Error = ResponseStatus;

    fn try_from(op: OpDestroyKey) -> Result<Self, Self::Error> {
        Ok(OpDestroyKeyProto {
            key_name: op.key_name,
            key_lifetime: op.key_lifetime as i32,
        })
    }
}

impl TryFrom<ResultDestroyKeyProto> for ResultDestroyKey {
    type Error = ResponseStatus;

    fn try_from(_proto_result: ResultDestroyKeyProto) -> Result<Self, Self::Error> {
        Ok(ResultDestroyKey {})
    }
}

impl TryFrom<ResultDestroyKey> for ResultDestroyKeyProto {
    type Error = ResponseStatus;

    fn try_from(_result: ResultDestroyKey) -> Result<Self, Self::Error> {
        Ok(ResultDestroyKeyProto {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::destroy_key::{OpDestroyKeyProto, ResultDestroyKeyProto};
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{key_attributes, ConvertOperation, OpDestroyKey, ResultDestroyKey};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn destroy_key_proto_to_op() {
        let mut proto: OpDestroyKeyProto = Default::default();
        let key_name = "test name".to_string();
        proto.key_lifetime = key_attributes::KeyLifetime::Persistent as i32;
        proto.key_name = key_name.clone();

        let op: OpDestroyKey = proto.try_into().expect("Failed to convert");

        assert_eq!(op.key_lifetime, key_attributes::KeyLifetime::Persistent);
        assert_eq!(op.key_name, key_name);
    }

    #[test]
    fn destroy_key_op_to_proto() {
        let key_name = "test name".to_string();
        let op = OpDestroyKey {
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: key_name.clone(),
        };

        let proto: OpDestroyKeyProto = op.try_into().expect("Failed to convert");

        assert_eq!(
            proto.key_lifetime,
            key_attributes::KeyLifetime::Persistent as i32
        );
        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn destroy_key_proto_to_resp() {
        let proto: ResultDestroyKeyProto = Default::default();

        let _result: ResultDestroyKey = proto.try_into().expect("Failed to convert");
    }

    #[test]
    fn destroy_key_resp_to_proto() {
        let result = ResultDestroyKey {};

        let _proto: ResultDestroyKeyProto = result.try_into().expect("Failed to convert");
    }

    #[test]
    fn op_destroy_key_e2e() {
        let op = OpDestroyKey {
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: "test name".to_string(),
        };
        let body = CONVERTER
            .body_from_operation(ConvertOperation::DestroyKey(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(&body, Opcode::DestroyKey)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(&resp_body, Opcode::DestroyKey)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(&req_body, Opcode::DestroyKey)
            .is_err());
    }
}
