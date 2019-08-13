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

impl From<OpPingProto> for operations::OpPing {
    fn from(_proto_op: OpPingProto) -> operations::OpPing {
        operations::OpPing {}
    }
}

impl From<operations::OpPing> for OpPingProto {
    fn from(_proto_op: operations::OpPing) -> OpPingProto {
        Default::default()
    }
}

impl From<operations::ResultPing> for ResultPingProto {
    fn from(result: operations::ResultPing) -> ResultPingProto {
        let mut proto_response: ResultPingProto = Default::default();
        proto_response.supported_version_maj = u32::from(result.supp_version_maj);
        proto_response.supported_version_min = u32::from(result.supp_version_min);

        proto_response
    }
}

impl From<ResultPingProto> for operations::ResultPing {
    fn from(response: ResultPingProto) -> operations::ResultPing {
        operations::ResultPing {
            supp_version_maj: response.supported_version_maj as u8,
            supp_version_min: response.supported_version_min as u8,
        }
    }
}

#[cfg(test)]
mod test {
    // OpPing <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::ping::ResultPingProto;
    use crate::operations::ResultPing;

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultPingProto = Default::default();
        proto.supported_version_maj = 1;
        proto.supported_version_min = 1;
        let resp: ResultPing = proto.into();

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
}
