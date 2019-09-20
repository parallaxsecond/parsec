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
use super::generated_ops::list_opcodes::{OpListOpcodesProto, ResultListOpcodesProto};
use crate::operations::{OpListOpcodes, ResultListOpcodes};
use crate::requests::{Opcode, ResponseStatus};
use num::FromPrimitive;
use std::collections::HashSet;
use std::convert::TryFrom;

impl TryFrom<OpListOpcodesProto> for OpListOpcodes {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OpListOpcodesProto) -> Result<Self, Self::Error> {
        Ok(OpListOpcodes {})
    }
}

impl TryFrom<OpListOpcodes> for OpListOpcodesProto {
    type Error = ResponseStatus;

    fn try_from(_op: OpListOpcodes) -> Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<ResultListOpcodesProto> for ResultListOpcodes {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultListOpcodesProto) -> Result<Self, Self::Error> {
        let mut opcodes: HashSet<Opcode> = HashSet::new();
        for opcode in proto_op.opcodes {
            let opcode = match FromPrimitive::from_u32(opcode) {
                Some(code) => code,
                None => return Err(ResponseStatus::OpcodeDoesNotExist),
            };
            opcodes.insert(opcode);
        }

        Ok(ResultListOpcodes { opcodes })
    }
}

impl TryFrom<ResultListOpcodes> for ResultListOpcodesProto {
    type Error = ResponseStatus;

    fn try_from(op: ResultListOpcodes) -> Result<Self, Self::Error> {
        let mut opcodes: Vec<u32> = Vec::new();
        for opcode in op.opcodes {
            opcodes.push(opcode as u32);
        }

        Ok(ResultListOpcodesProto { opcodes })
    }
}

#[cfg(test)]
mod test {
    // OpListOpcodes <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_opcodes::ResultListOpcodesProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{NativeOperation, NativeResult, OpListOpcodes, ResultListOpcodes};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::collections::HashSet;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultListOpcodesProto = Default::default();
        proto.opcodes.push(0);
        let resp: ResultListOpcodes = proto.try_into().unwrap();

        assert_eq!(resp.opcodes.len(), 1);
        assert!(resp.opcodes.contains(&Opcode::Ping));
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: ResultListOpcodes = ResultListOpcodes {
            opcodes: HashSet::new(),
        };
        resp.opcodes.insert(Opcode::Ping);

        let proto: ResultListOpcodesProto = resp.try_into().unwrap();
        assert_eq!(proto.opcodes.len(), 1);
        assert_eq!(proto.opcodes[0], 0);
    }

    #[test]
    fn list_opcodes_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn op_list_opcodes_from_native() {
        let list_opcodes = OpListOpcodes {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListOpcodes(list_opcodes))
            .expect("Failed to convert request");
        assert!(body.len() == 0);
    }

    #[test]
    fn op_list_opcodes_e2e() {
        let list_opcodes = OpListOpcodes {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListOpcodes(list_opcodes))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_err());
    }

    #[test]
    fn list_opcodes_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn result_list_opcodes_from_native() {
        let mut list_opcodes = ResultListOpcodes {
            opcodes: HashSet::new(),
        };
        list_opcodes.opcodes.insert(Opcode::Ping);

        let body = CONVERTER
            .result_to_body(NativeResult::ListOpcodes(list_opcodes))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_opcodes_result_e2e() {
        let mut list_opcodes = ResultListOpcodes {
            opcodes: HashSet::new(),
        };
        list_opcodes.opcodes.insert(Opcode::Ping);

        let body = CONVERTER
            .result_to_body(NativeResult::ListOpcodes(list_opcodes))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListOpcodes)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListOpcodes(result) => {
                assert_eq!(result.opcodes.len(), 1);
            }
            _ => panic!("Expected list_opcodes"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListOpcodes)
            .is_err());
    }
}
