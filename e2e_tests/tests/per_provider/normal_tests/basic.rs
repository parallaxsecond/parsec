// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::RawRequestClient;
use parsec_client::core::interface::requests::request::RawHeader;
use parsec_client::core::interface::requests::{Opcode, ProviderId, ResponseStatus};

#[test]
fn invalid_provider() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = 0xff;
    req_hdr.opcode = Opcode::Ping as u32;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::ProviderDoesNotExist);
    assert_eq!(resp.header.opcode, Opcode::Ping);
}

#[cfg(not(feature = "mbed-crypto-provider"))]
#[test]
fn provider_not_registered() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::MbedCrypto as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::ProviderNotRegistered);
    assert_eq!(resp.header.opcode, Opcode::Ping);
}

#[test]
fn invalid_content_type() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;
    req_hdr.content_type = 0xff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::ContentTypeNotSupported);
    assert_eq!(resp.header.opcode, Opcode::Ping);
}

#[test]
fn invalid_accept_type() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.accept_type = 0xff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::AcceptTypeNotSupported);
    assert_eq!(resp.header.opcode, Opcode::Ping);
}

#[test]
fn invalid_body_len() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.body_len = 0xff_ff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::ConnectionError);
}

#[test]
fn invalid_auth_len() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.auth_len = 0xff_ff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::ConnectionError);
}

#[test]
fn invalid_opcode() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = 0xff_ff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::OpcodeDoesNotExist);
}

#[test]
fn invalid_authenticator() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;
    req_hdr.auth_type = 0xff;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(
        resp.header.status,
        ResponseStatus::AuthenticatorDoesNotExist
    );
}

#[test]
fn authenticator_not_registered() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;
    req_hdr.auth_type = 0x02;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(
        resp.header.status,
        ResponseStatus::AuthenticatorNotRegistered
    );
}

#[test]
fn flags_ignored() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;
    req_hdr.flags = 56;

    let _resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
}

#[test]
fn status_ignored() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.status = 0xFFFF;

    let _resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
}

#[test]
fn reserved_fields_not_zero1() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.reserved1 = 56;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::InvalidHeader);
}

#[test]
fn reserved_fields_not_zero2() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    req_hdr.provider = ProviderId::Core as u8;
    req_hdr.opcode = Opcode::Ping as u32;

    req_hdr.reserved2 = 56;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::InvalidHeader);
}
