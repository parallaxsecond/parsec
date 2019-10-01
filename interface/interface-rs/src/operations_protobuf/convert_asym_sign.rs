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
use super::generated_ops::asym_sign::{OpAsymmetricSignProto, ResultAsymmetricSignProto};
use crate::operations::{OpAsymSign, ResultAsymSign};
use crate::requests::ResponseStatus;
use num::FromPrimitive;
use std::convert::TryFrom;

impl TryFrom<OpAsymmetricSignProto> for OpAsymSign {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpAsymmetricSignProto) -> Result<Self, Self::Error> {
        Ok(OpAsymSign {
            key_name: proto_op.key_name,
            key_lifetime: FromPrimitive::from_i32(proto_op.key_lifetime)
                .expect("Failed to convert key lifetime"),
            hash: proto_op.hash,
        })
    }
}

impl TryFrom<OpAsymSign> for OpAsymmetricSignProto {
    type Error = ResponseStatus;

    fn try_from(op: OpAsymSign) -> Result<Self, Self::Error> {
        Ok(OpAsymmetricSignProto {
            key_name: op.key_name,
            key_lifetime: op.key_lifetime as i32,
            hash: op.hash,
        })
    }
}

impl TryFrom<ResultAsymmetricSignProto> for ResultAsymSign {
    type Error = ResponseStatus;

    fn try_from(proto_result: ResultAsymmetricSignProto) -> Result<Self, Self::Error> {
        Ok(ResultAsymSign {
            signature: proto_result.signature,
        })
    }
}

impl TryFrom<ResultAsymSign> for ResultAsymmetricSignProto {
    type Error = ResponseStatus;

    fn try_from(result: ResultAsymSign) -> Result<Self, Self::Error> {
        Ok(ResultAsymmetricSignProto {
            signature: result.signature,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::asym_sign::{
        OpAsymmetricSignProto, ResultAsymmetricSignProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        key_attributes, NativeOperation, NativeResult, OpAsymSign, ResultAsymSign,
    };
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn asym_proto_to_op() {
        let mut proto: OpAsymmetricSignProto = Default::default();
        let hash = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();
        proto.hash = hash.clone();
        proto.key_lifetime = key_attributes::KeyLifetime::Persistent as i32;
        proto.key_name = key_name.clone();

        let op: OpAsymSign = proto.try_into().expect("Failed to convert");

        assert_eq!(op.hash, hash);
        assert_eq!(op.key_lifetime, key_attributes::KeyLifetime::Persistent);
        assert_eq!(op.key_name, key_name);
    }

    #[test]
    fn asym_op_to_proto() {
        let hash = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();

        let op = OpAsymSign {
            hash: hash.clone(),
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: key_name.clone(),
        };

        let proto: OpAsymmetricSignProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.hash, hash);
        assert_eq!(
            proto.key_lifetime,
            key_attributes::KeyLifetime::Persistent as i32
        );
        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn asym_proto_to_resp() {
        let mut proto: ResultAsymmetricSignProto = Default::default();
        let signature = vec![0x11, 0x22, 0x33];
        proto.signature = signature.clone();

        let result: ResultAsymSign = proto.try_into().expect("Failed to convert");

        assert_eq!(result.signature, signature);
    }

    #[test]
    fn asym_resp_to_proto() {
        let signature = vec![0x11, 0x22, 0x33];
        let result = ResultAsymSign {
            signature: signature.clone(),
        };

        let proto: ResultAsymmetricSignProto = result.try_into().expect("Failed to convert");

        assert_eq!(proto.signature, signature);
    }

    #[test]
    fn op_asym_sign_e2e() {
        let op = OpAsymSign {
            hash: vec![0x11, 0x22, 0x33],
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: "test name".to_string(),
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::AsymSign(op))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_operation(body, Opcode::AsymSign).is_ok());
    }

    #[test]
    fn resp_asym_sign_e2e() {
        let result = ResultAsymSign {
            signature: vec![0x11, 0x22, 0x33],
        };
        let body = CONVERTER
            .result_to_body(NativeResult::AsymSign(result))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_result(body, Opcode::AsymSign).is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::AsymSign)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::AsymSign)
            .is_err());
    }
}
