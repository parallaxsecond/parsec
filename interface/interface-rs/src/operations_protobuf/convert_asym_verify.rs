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
use super::generated_ops::asym_verify::{OpAsymmetricVerifyProto, ResultAsymmetricVerifyProto};
use crate::operations::{OpAsymVerify, ResultAsymVerify};
use crate::requests::ResponseStatus;
use num::FromPrimitive;
use std::convert::TryFrom;

impl TryFrom<OpAsymmetricVerifyProto> for OpAsymVerify {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpAsymmetricVerifyProto) -> Result<Self, Self::Error> {
        Ok(OpAsymVerify {
            key_name: proto_op.key_name,
            key_lifetime: FromPrimitive::from_i32(proto_op.key_lifetime)
                .expect("Failed to convert key lifetime"),
            hash: proto_op.hash,
            signature: proto_op.signature,
        })
    }
}

impl TryFrom<OpAsymVerify> for OpAsymmetricVerifyProto {
    type Error = ResponseStatus;

    fn try_from(op: OpAsymVerify) -> Result<Self, Self::Error> {
        Ok(OpAsymmetricVerifyProto {
            key_name: op.key_name,
            key_lifetime: op.key_lifetime as i32,
            hash: op.hash,
            signature: op.signature,
        })
    }
}

impl TryFrom<ResultAsymmetricVerifyProto> for ResultAsymVerify {
    type Error = ResponseStatus;

    fn try_from(_proto_result: ResultAsymmetricVerifyProto) -> Result<Self, Self::Error> {
        Ok(ResultAsymVerify {})
    }
}

impl TryFrom<ResultAsymVerify> for ResultAsymmetricVerifyProto {
    type Error = ResponseStatus;

    fn try_from(_result: ResultAsymVerify) -> Result<Self, Self::Error> {
        Ok(ResultAsymmetricVerifyProto {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::asym_verify::{
        OpAsymmetricVerifyProto, ResultAsymmetricVerifyProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        key_attributes, ConvertOperation, ConvertResult, OpAsymVerify, ResultAsymVerify,
    };
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn asym_proto_to_op() {
        let mut proto: OpAsymmetricVerifyProto = Default::default();
        let hash = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();
        let signature = vec![0x11, 0x22, 0x33];
        proto.hash = hash.clone();
        proto.key_lifetime = key_attributes::KeyLifetime::Persistent as i32;
        proto.key_name = key_name.clone();
        proto.signature = signature.clone();

        let op: OpAsymVerify = proto.try_into().expect("Failed to convert");

        assert_eq!(op.hash, hash);
        assert_eq!(op.key_lifetime, key_attributes::KeyLifetime::Persistent);
        assert_eq!(op.key_name, key_name);
        assert_eq!(op.signature, signature);
    }

    #[test]
    fn asym_op_to_proto() {
        let hash = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();
        let signature = vec![0x11, 0x22, 0x33];

        let op = OpAsymVerify {
            hash: hash.clone(),
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: key_name.clone(),
            signature: signature.clone(),
        };

        let proto: OpAsymmetricVerifyProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.hash, hash);
        assert_eq!(
            proto.key_lifetime,
            key_attributes::KeyLifetime::Persistent as i32
        );
        assert_eq!(proto.key_name, key_name);
        assert_eq!(proto.signature, signature);
    }

    #[test]
    fn asym_proto_to_resp() {
        let proto: ResultAsymmetricVerifyProto = Default::default();

        let _result: ResultAsymVerify = proto.try_into().expect("Failed to convert");
    }

    #[test]
    fn asym_resp_to_proto() {
        let result = ResultAsymVerify {};

        let _proto: ResultAsymmetricVerifyProto = result.try_into().expect("Failed to convert");
    }

    #[test]
    fn op_asym_sign_e2e() {
        let op = OpAsymVerify {
            hash: vec![0x11, 0x22, 0x33],
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: "test name".to_string(),
            signature: vec![0x11, 0x22, 0x33],
        };
        let body = CONVERTER
            .body_from_operation(ConvertOperation::AsymVerify(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(&body, Opcode::AsymVerify)
            .is_ok());
    }

    #[test]
    fn resp_asym_sign_e2e() {
        let result = ResultAsymVerify {};
        let body = CONVERTER
            .body_from_result(ConvertResult::AsymVerify(result))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_result(&body, Opcode::AsymVerify).is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(&resp_body, Opcode::AsymVerify)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(&req_body, Opcode::AsymVerify)
            .is_err());
    }
}
