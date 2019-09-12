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
use super::generated_ops::create_key::{OpCreateKeyProto, ResultCreateKeyProto};
use crate::operations;
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OpCreateKeyProto> for operations::OpCreateKey {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpCreateKeyProto) -> Result<Self, Self::Error> {
        let key_attributes = match proto_op.key_attributes {
            Some(key_attr) => key_attr,
            None => return Err(ResponseStatus::DeserializingBodyFailed),
        };

        Ok(operations::OpCreateKey {
            key_name: proto_op.key_name,
            key_attributes: key_attributes.into(),
        })
    }
}

impl TryFrom<operations::OpCreateKey> for OpCreateKeyProto {
    type Error = ResponseStatus;

    fn try_from(op: operations::OpCreateKey) -> Result<Self, Self::Error> {
        let mut proto: OpCreateKeyProto = Default::default();
        proto.key_name = op.key_name;
        proto.key_attributes = Some(op.key_attributes.into());

        Ok(proto)
    }
}

impl TryFrom<operations::ResultCreateKey> for ResultCreateKeyProto {
    type Error = ResponseStatus;

    fn try_from(_result: operations::ResultCreateKey) -> Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<ResultCreateKeyProto> for operations::ResultCreateKey {
    type Error = ResponseStatus;

    fn try_from(_response: ResultCreateKeyProto) -> Result<Self, Self::Error> {
        Ok(operations::ResultCreateKey {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::create_key::{OpCreateKeyProto, ResultCreateKeyProto};
    use super::super::generated_ops::key_attributes::{
        self as key_attributes_proto, key_attributes_proto::AlgorithmProto, KeyAttributesProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::key_attributes::{self, KeyAttributes};
    use crate::operations::{NativeOperation, OpCreateKey, ResultCreateKey};
    use crate::requests::Opcode;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn create_key_op_from_proto() {
        let name = "test name".to_string();
        let proto = OpCreateKeyProto {
            key_name: name.clone(),
            key_attributes: Some(get_key_attrs_proto()),
        };

        let op: OpCreateKey = proto.try_into().expect("Failed conversion");
        assert_eq!(op.key_name, name);
    }

    #[test]
    fn create_key_op_to_proto() {
        let name = "test name".to_string();
        let op = OpCreateKey {
            key_name: name.clone(),
            key_attributes: get_key_attrs(),
        };

        let proto: OpCreateKeyProto = op.try_into().expect("Failed conversion");
        assert_eq!(proto.key_name, name);
    }

    #[test]
    fn create_key_res_from_proto() {
        let proto = ResultCreateKeyProto {};
        let _res: ResultCreateKey = proto.try_into().expect("Failed conversion");
    }

    #[test]
    fn create_key_res_to_proto() {
        let res = ResultCreateKey {};
        let _proto: ResultCreateKeyProto = res.try_into().expect("Failed conversion");
    }

    #[test]
    fn create_key_op_e2e() {
        let name = "test name".to_string();
        let op = OpCreateKey {
            key_name: name.clone(),
            key_attributes: get_key_attrs(),
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::CreateKey(op))
            .expect("Failed to convert to body");

        CONVERTER
            .body_to_operation(body, Opcode::CreateKey)
            .expect("Failed to convert to operation");
    }

    fn get_key_attrs() -> KeyAttributes {
        KeyAttributes {
            key_lifetime: key_attributes::KeyLifetime::Persistent,
            key_type: key_attributes::KeyType::RsaKeypair,
            ecc_curve: Some(key_attributes::EccCurve::Secp160k1),
            algorithm: key_attributes::Algorithm::sign(
                key_attributes::SignAlgorithm::RsaPkcs1v15Sign,
                Some(key_attributes::HashAlgorithm::Sha1),
            ),
            key_size: 1024,
            permit_export: true,
            permit_encrypt: true,
            permit_decrypt: true,
            permit_sign: true,
            permit_verify: true,
            permit_derive: true,
        }
    }

    fn get_key_attrs_proto() -> KeyAttributesProto {
        let algo = Some(AlgorithmProto::Sign(key_attributes_proto::Sign {
            sign_algorithm: key_attributes_proto::SignAlgorithm::RsaPkcs1v15Sign as i32,
            hash_algorithm: key_attributes_proto::HashAlgorithm::Sha1 as i32,
        }));
        KeyAttributesProto {
            key_lifetime: key_attributes_proto::KeyLifetime::Persistent as i32,
            key_type: key_attributes_proto::KeyType::RsaKeypair as i32,
            ecc_curve: key_attributes_proto::EccCurve::Secp160k1 as i32,
            algorithm_proto: algo,
            key_size: 1024,
            permit_export: true,
            permit_encrypt: true,
            permit_decrypt: true,
            permit_sign: true,
            permit_verify: true,
            permit_derive: true,
        }
    }
}
