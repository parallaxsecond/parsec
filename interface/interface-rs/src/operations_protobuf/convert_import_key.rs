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
use super::generated_ops::import_key::{OpImportKeyProto, ResultImportKeyProto};
use crate::operations;
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OpImportKeyProto> for operations::OpImportKey {
    type Error = ResponseStatus;

    fn try_from(proto_op: OpImportKeyProto) -> Result<Self, Self::Error> {
        let key_attributes = match proto_op.key_attributes {
            Some(key_attr) => key_attr,
            None => return Err(ResponseStatus::DeserializingBodyFailed),
        };

        Ok(operations::OpImportKey {
            key_name: proto_op.key_name,
            key_attributes: key_attributes.into(),
            key_data: proto_op.key_data,
        })
    }
}

impl TryFrom<operations::OpImportKey> for OpImportKeyProto {
    type Error = ResponseStatus;

    fn try_from(op: operations::OpImportKey) -> Result<Self, Self::Error> {
        Ok(OpImportKeyProto {
            key_name: op.key_name,
            key_attributes: Some(op.key_attributes.into()),
            key_data: op.key_data,
        })
    }
}

impl TryFrom<ResultImportKeyProto> for operations::ResultImportKey {
    type Error = ResponseStatus;

    fn try_from(_proto_op: ResultImportKeyProto) -> Result<Self, Self::Error> {
        Ok(operations::ResultImportKey {})
    }
}

impl TryFrom<operations::ResultImportKey> for ResultImportKeyProto {
    type Error = ResponseStatus;

    fn try_from(_op: operations::ResultImportKey) -> Result<Self, Self::Error> {
        Ok(ResultImportKeyProto {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::import_key::{OpImportKeyProto, ResultImportKeyProto};
    use super::super::generated_ops::key_attributes::{
        self as key_attributes_proto, key_attributes_proto::AlgorithmProto, KeyAttributesProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::key_attributes::{self, KeyAttributes};
    use crate::operations::{ConvertOperation, OpImportKey, ResultImportKey};
    use crate::requests::Opcode;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn import_key_op_from_proto() {
        let name = "test name".to_string();
        let key_data = vec![0x11, 0x22, 0x33];
        let proto = OpImportKeyProto {
            key_name: name.clone(),
            key_attributes: Some(get_key_attrs_proto()),
            key_data: key_data.clone(),
        };

        let op: OpImportKey = proto.try_into().expect("Failed conversion");
        assert_eq!(op.key_name, name);
        assert_eq!(op.key_data, key_data);
    }

    #[test]
    fn import_key_op_to_proto() {
        let name = "test name".to_string();
        let key_data = vec![0x11, 0x22, 0x33];
        let op = OpImportKey {
            key_name: name.clone(),
            key_attributes: get_key_attrs(),
            key_data: key_data.clone(),
        };

        let proto: OpImportKeyProto = op.try_into().expect("Failed conversion");
        assert_eq!(proto.key_name, name);
        assert_eq!(proto.key_data, key_data);
    }

    #[test]
    fn import_key_res_from_proto() {
        let proto = ResultImportKeyProto {};
        let _res: ResultImportKey = proto.try_into().expect("Failed conversion");
    }

    #[test]
    fn import_key_res_to_proto() {
        let res = ResultImportKey {};
        let _proto: ResultImportKeyProto = res.try_into().expect("Failed conversion");
    }

    #[test]
    fn import_key_op_e2e() {
        let name = "test name".to_string();
        let op = OpImportKey {
            key_name: name.clone(),
            key_attributes: get_key_attrs(),
            key_data: vec![0x11, 0x22, 0x33],
        };

        let body = CONVERTER
            .body_from_operation(ConvertOperation::ImportKey(op))
            .expect("Failed to convert to body");

        CONVERTER
            .body_to_operation(&body, Opcode::ImportKey)
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
