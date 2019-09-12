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
use super::generated_ops::export_public_key::{OpExportPublicKeyProto, ResultExportPublicKeyProto};
use crate::operations;
use crate::requests::ResponseStatus;
use num::FromPrimitive;
use std::convert::TryFrom;

impl TryFrom<OpExportPublicKeyProto> for operations::OpExportPublicKey {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpExportPublicKeyProto) -> Result<Self, Self::Error> {
        let key_lifetime =
            FromPrimitive::from_i32(proto_op.key_lifetime).expect("Failed to convert key lifetime");

        Ok(operations::OpExportPublicKey {
            key_name: proto_op.key_name,
            key_lifetime,
        })
    }
}

impl TryFrom<operations::OpExportPublicKey> for OpExportPublicKeyProto {
    type Error = ResponseStatus;

    fn try_from(op: operations::OpExportPublicKey) -> Result<Self, Self::Error> {
        Ok(OpExportPublicKeyProto {
            key_name: op.key_name,
            key_lifetime: op.key_lifetime as i32,
        })
    }
}

impl TryFrom<ResultExportPublicKeyProto> for operations::ResultExportPublicKey {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultExportPublicKeyProto) -> Result<Self, Self::Error> {
        Ok(operations::ResultExportPublicKey {
            key_data: proto_op.key_data,
        })
    }
}

impl TryFrom<operations::ResultExportPublicKey> for ResultExportPublicKeyProto {
    type Error = ResponseStatus;

    fn try_from(op: operations::ResultExportPublicKey) -> Result<Self, Self::Error> {
        Ok(ResultExportPublicKeyProto {
            key_data: op.key_data,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::export_public_key::{
        OpExportPublicKeyProto, ResultExportPublicKeyProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        key_attributes, NativeOperation, NativeResult, OpExportPublicKey, ResultExportPublicKey,
    };
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn export_pk_proto_to_op() {
        let mut proto: OpExportPublicKeyProto = Default::default();
        let key_name = "test name".to_string();
        proto.key_lifetime = key_attributes::KeyLifetime::Persistent as i32;
        proto.key_name = key_name.clone();

        let op: OpExportPublicKey = proto.try_into().expect("Failed to convert");

        assert_eq!(op.key_lifetime, key_attributes::KeyLifetime::Persistent);
        assert_eq!(op.key_name, key_name);
    }

    #[test]
    fn asym_op_to_proto() {
        let key_name = "test name".to_string();

        let op = OpExportPublicKey {
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: key_name.clone(),
        };

        let proto: OpExportPublicKeyProto = op.try_into().expect("Failed to convert");

        assert_eq!(
            proto.key_lifetime,
            key_attributes::KeyLifetime::Persistent as i32
        );
        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn asym_proto_to_resp() {
        let mut proto: ResultExportPublicKeyProto = Default::default();
        let key_data = vec![0x11, 0x22, 0x33];
        proto.key_data = key_data.clone();

        let result: ResultExportPublicKey = proto.try_into().expect("Failed to convert");

        assert_eq!(result.key_data, key_data);
    }

    #[test]
    fn asym_resp_to_proto() {
        let key_data = vec![0x11, 0x22, 0x33];
        let result = ResultExportPublicKey {
            key_data: key_data.clone(),
        };

        let proto: ResultExportPublicKeyProto = result.try_into().expect("Failed to convert");

        assert_eq!(proto.key_data, key_data);
    }

    #[test]
    fn op_export_pk_e2e() {
        let op = OpExportPublicKey {
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_name: "test name".to_string(),
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::ExportPublicKey(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::ExportPublicKey)
            .is_ok());
    }

    #[test]
    fn resp_export_pk_e2e() {
        let result = ResultExportPublicKey {
            key_data: vec![0x11, 0x22, 0x33],
        };
        let body = CONVERTER
            .result_to_body(NativeResult::ExportPublicKey(result))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_result(body, Opcode::ExportPublicKey)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ExportPublicKey)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ExportPublicKey)
            .is_err());
    }
}
