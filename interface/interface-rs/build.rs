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
use std::fs::{read_dir, OpenOptions};
use std::io::{Result, Write};
use std::path::Path;

const PROTO_FOLDER: &str = "../protobuf";
const PROTO_OUT_DIR: &str = "src/operations_protobuf/generated_ops";

// TODO: handle OsStrings more carefully, as .into_string() might fail

fn generate_mod_file() -> Result<()> {
    let dir_entries = read_dir(Path::new(PROTO_FOLDER))?;
    let mod_file_path = format!("{}/mod.rs", PROTO_OUT_DIR);
    let mut mod_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&mod_file_path)?;
    dir_entries.for_each(|file| {
        let filename = file.unwrap().file_name().into_string().unwrap();
        if filename.ends_with(".proto") {
            writeln!(&mut mod_file, "pub mod {};", filename.replace(".proto", "")).unwrap();
        }
    });

    mod_file.flush()?;

    Ok(())
}

fn generate_proto_sources() -> Result<()> {
    let dir_entries = read_dir(Path::new(PROTO_FOLDER))?;
    let files: Vec<String> = dir_entries
        .map(|protos_file| {
            protos_file
                .unwrap()
                .path()
                .into_os_string()
                .into_string()
                .unwrap()
        })
        .filter(|string| string.ends_with(".proto"))
        .collect();
    let files_slices: Vec<&str> = files.iter().map(|file| &file[..]).collect();
    let mut prost_config = prost_build::Config::new();
    prost_config.out_dir(Path::new("./src/operations_protobuf/generated_ops"));
    prost_config
        .compile_protos(&files_slices, &[PROTO_FOLDER])
        .expect("failed to generate protos");

    Ok(())
}

fn main() {
    generate_mod_file().expect("Failed to generate a mod file for the proto dir.");

    generate_proto_sources().expect("Failed to generate protobuf source code from proto files.");
}
