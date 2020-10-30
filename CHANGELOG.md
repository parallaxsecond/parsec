# Changelog

## [0.6.0](https://github.com/parallaxsecond/parsec/tree/0.6.0) (2020-10-20)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.5.0...0.6.0)

**Implemented enhancements:**

- Add multitenancy testing infrastructure 👩‍🔧 [\#245](https://github.com/parallaxsecond/parsec/issues/245)
- Delete "Provider" suffix out of provider names [\#134](https://github.com/parallaxsecond/parsec/issues/134)
- Improve error message on service startup [\#260](https://github.com/parallaxsecond/parsec/pull/260) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Limit key imports in TPM provider [\#255](https://github.com/parallaxsecond/parsec/pull/255) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Add authenticator configuration [\#270](https://github.com/parallaxsecond/parsec/issues/270)
- Assemble a PR checklist for code reviewers [\#258](https://github.com/parallaxsecond/parsec/issues/258)
- Adjust README disclaimer wording [\#231](https://github.com/parallaxsecond/parsec/issues/231)

**Merged pull requests:**

- Add multitenancy tests [\#276](https://github.com/parallaxsecond/parsec/pull/276) ([hug-dev](https://github.com/hug-dev))
- Put config tests in all\_providers [\#275](https://github.com/parallaxsecond/parsec/pull/275) ([hug-dev](https://github.com/hug-dev))
- Remove warnings about parsec and parsec-clients [\#274](https://github.com/parallaxsecond/parsec/pull/274) ([hug-dev](https://github.com/hug-dev))
- Add authentication configuration [\#273](https://github.com/parallaxsecond/parsec/pull/273) ([hug-dev](https://github.com/hug-dev))
- Refactored provider names [\#263](https://github.com/parallaxsecond/parsec/pull/263) ([samwell61](https://github.com/samwell61))
- Add list keys [\#261](https://github.com/parallaxsecond/parsec/pull/261) ([joechrisellis](https://github.com/joechrisellis))

## [0.5.0](https://github.com/parallaxsecond/parsec/tree/0.5.0) (2020-10-02)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.4.0...0.5.0)

**Implemented enhancements:**

- Creating a build-time configuration file [\#256](https://github.com/parallaxsecond/parsec/issues/256)
- Merge integration tests in E2E test suite [\#228](https://github.com/parallaxsecond/parsec/issues/228)
- Support dbus-parsec with NXP secureobj library [\#223](https://github.com/parallaxsecond/parsec/issues/223)
- Verify which dependencies can/should be updated [\#158](https://github.com/parallaxsecond/parsec/issues/158)
- Add more test cases [\#151](https://github.com/parallaxsecond/parsec/issues/151)
- Test Parsec installation as a systemd daemon [\#49](https://github.com/parallaxsecond/parsec/issues/49)
- Improve E2E testing [\#253](https://github.com/parallaxsecond/parsec/pull/253) ([ionut-arm](https://github.com/ionut-arm))
- Upgrade and clean dependencies [\#246](https://github.com/parallaxsecond/parsec/pull/246) ([hug-dev](https://github.com/hug-dev))
- Import private key support for TPM provider [\#243](https://github.com/parallaxsecond/parsec/pull/243) ([joechrisellis](https://github.com/joechrisellis))
- Allow software operations in PKCS11 provider [\#241](https://github.com/parallaxsecond/parsec/pull/241) ([ionut-arm](https://github.com/ionut-arm))
- Improve key metadata handling [\#240](https://github.com/parallaxsecond/parsec/pull/240) ([ionut-arm](https://github.com/ionut-arm))
- Add support for `psa\_generate\_random` operation for MbedCrypto provider [\#208](https://github.com/parallaxsecond/parsec/pull/208) ([joechrisellis](https://github.com/joechrisellis))

**Fixed bugs:**

- Memory cleanup of sensitive data [\#122](https://github.com/parallaxsecond/parsec/issues/122)
- Fix attribute conversion in PKCS11 provider [\#254](https://github.com/parallaxsecond/parsec/pull/254) ([ionut-arm](https://github.com/ionut-arm))
- Fix sign attribute in PKCS11 [\#252](https://github.com/parallaxsecond/parsec/pull/252) ([ionut-arm](https://github.com/ionut-arm))
- Add Uuid from the interface directly [\#242](https://github.com/parallaxsecond/parsec/pull/242) ([hug-dev](https://github.com/hug-dev))
- Add `buffer\_size\_limit` config option for providers [\#233](https://github.com/parallaxsecond/parsec/pull/233) ([joechrisellis](https://github.com/joechrisellis))

**Security fixes:**

- Add memory zeroizing when needed [\#239](https://github.com/parallaxsecond/parsec/pull/239) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Implement ListAuthenticators [\#216](https://github.com/parallaxsecond/parsec/issues/216)
- Better error message when file not found [\#210](https://github.com/parallaxsecond/parsec/issues/210)
- Implement an authenticator based on the domain socket peer credential [\#200](https://github.com/parallaxsecond/parsec/issues/200)

**Merged pull requests:**

- Add Unix peer credentials authenticator [\#214](https://github.com/parallaxsecond/parsec/pull/214) ([joechrisellis](https://github.com/joechrisellis))

## [0.4.0](https://github.com/parallaxsecond/parsec/tree/0.4.0) (2020-09-01)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.3.0...0.4.0)

**Implemented enhancements:**

- Implement asymmetric encrypt/decrypt in the PKCS\#11 provider [\#224](https://github.com/parallaxsecond/parsec/issues/224)
- Implement asymmetric encrypting/decrypting for TPM provider [\#217](https://github.com/parallaxsecond/parsec/issues/217)
- Create a Parsec Command Line Interface Client [\#202](https://github.com/parallaxsecond/parsec/issues/202)
- Create a mechanism for the listener to pass system-level data to the authenticator [\#199](https://github.com/parallaxsecond/parsec/issues/199)
- Auto create `/tmp/parsec` with correct permissions on startup [\#195](https://github.com/parallaxsecond/parsec/issues/195)
- Update attribute handling in PKCS11 provider [\#227](https://github.com/parallaxsecond/parsec/pull/227) ([ionut-arm](https://github.com/ionut-arm))
- Add asymmetric encryption support to TPM provider [\#225](https://github.com/parallaxsecond/parsec/pull/225) ([ionut-arm](https://github.com/ionut-arm))
- Improve error message when config file is not found [\#211](https://github.com/parallaxsecond/parsec/pull/211) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Update Adam Parco email address in maintainers files [\#230](https://github.com/parallaxsecond/parsec/issues/230)
- Update email address [\#235](https://github.com/parallaxsecond/parsec/pull/235) ([hug-dev](https://github.com/hug-dev))
- Bugfix: fix off-by-one error \(default body length limit\) [\#234](https://github.com/parallaxsecond/parsec/pull/234) ([joechrisellis](https://github.com/joechrisellis))
- Fix clippy errors [\#206](https://github.com/parallaxsecond/parsec/pull/206) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Add an option to pass a path to a build-config file  [\#174](https://github.com/parallaxsecond/parsec/issues/174)

**Merged pull requests:**

- Add missing\_docs lint and missing docs [\#236](https://github.com/parallaxsecond/parsec/pull/236) ([hug-dev](https://github.com/hug-dev))
- Added aead encrypt decrypt, hash compute compare and raw key agreement [\#229](https://github.com/parallaxsecond/parsec/pull/229) ([sbailey-arm](https://github.com/sbailey-arm))
- Fix test and enable Travis [\#221](https://github.com/parallaxsecond/parsec/pull/221) ([ionut-arm](https://github.com/ionut-arm))
- Add implementation for ListAuthenticators operation [\#220](https://github.com/parallaxsecond/parsec/pull/220) ([joechrisellis](https://github.com/joechrisellis))
- Add check to prevent the Parsec service from running as root [\#219](https://github.com/parallaxsecond/parsec/pull/219) ([joechrisellis](https://github.com/joechrisellis))
- CoreProvider can query the other providers [\#215](https://github.com/parallaxsecond/parsec/pull/215) ([ionut-arm](https://github.com/ionut-arm))
- Rebase on new tss\_esapi [\#213](https://github.com/parallaxsecond/parsec/pull/213) ([puiterwijk](https://github.com/puiterwijk))
- Add Asymmetric Encrypt/Decrypt to mbed supported opcodes [\#212](https://github.com/parallaxsecond/parsec/pull/212) ([puiterwijk](https://github.com/puiterwijk))
- Create `Connection` abstraction for client communication [\#207](https://github.com/parallaxsecond/parsec/pull/207) ([joechrisellis](https://github.com/joechrisellis))
- Added user and group checks. Auto create socket dir. [\#205](https://github.com/parallaxsecond/parsec/pull/205) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.3.0](https://github.com/parallaxsecond/parsec/tree/0.3.0) (2020-07-16)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.2.0...0.3.0)

**Implemented enhancements:**

- Create a Mbed Crypto Secure Element driver calling Parsec Rust Client [\#128](https://github.com/parallaxsecond/parsec/issues/128)
- Threat model of Parsec [\#89](https://github.com/parallaxsecond/parsec/issues/89)
- Precise the providers' order importance [\#203](https://github.com/parallaxsecond/parsec/pull/203) ([hug-dev](https://github.com/hug-dev))
- Keep list\_providers order; add cfg tests [\#197](https://github.com/parallaxsecond/parsec/pull/197) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Added PsaExportKey [\#204](https://github.com/parallaxsecond/parsec/pull/204) ([sbailey-arm](https://github.com/sbailey-arm))
- Migrated uses of a locally declared RsaPublic key to new create picky-asn1-x509 [\#201](https://github.com/parallaxsecond/parsec/pull/201) ([sbailey-arm](https://github.com/sbailey-arm))
- Added asymmetric encrypt and decrypt to Mbed Crypto provider [\#196](https://github.com/parallaxsecond/parsec/pull/196) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.2.0](https://github.com/parallaxsecond/parsec/tree/0.2.0) (2020-07-02)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.1.2...0.2.0)

**Implemented enhancements:**

- Further simplification of the Mbed Crypto provider [\#187](https://github.com/parallaxsecond/parsec/issues/187)
- Create config "service" [\#181](https://github.com/parallaxsecond/parsec/issues/181)
- Use psa-crypto crate in the Mbed Crypto Provider [\#177](https://github.com/parallaxsecond/parsec/issues/177)
- Have a real integration test example [\#161](https://github.com/parallaxsecond/parsec/issues/161)
- Separate provider code into modules [\#133](https://github.com/parallaxsecond/parsec/issues/133)
- Update with PSA Crypto 1.0.0 interface [\#129](https://github.com/parallaxsecond/parsec/issues/129)
- Create a Parsec Rust Client [\#127](https://github.com/parallaxsecond/parsec/issues/127)
- TPM provider should establish most-secure primitives for itself [\#121](https://github.com/parallaxsecond/parsec/issues/121)
- Improvements for tests/ci.sh [\#108](https://github.com/parallaxsecond/parsec/issues/108)
- Split out ProviderConfig [\#103](https://github.com/parallaxsecond/parsec/issues/103)
- Check clippy::pedantic lints [\#100](https://github.com/parallaxsecond/parsec/issues/100)
- Modify configuration to have provider-specific table [\#70](https://github.com/parallaxsecond/parsec/issues/70)
- Create a PSA Crypto Rust wrapper crate [\#62](https://github.com/parallaxsecond/parsec/issues/62)
- Add TCTI configuration functionality [\#194](https://github.com/parallaxsecond/parsec/pull/194) ([ionut-arm](https://github.com/ionut-arm))
- Updated Parsec to use latest parsec-interface \(0.17.0\) [\#193](https://github.com/parallaxsecond/parsec/pull/193) ([sbailey-arm](https://github.com/sbailey-arm))
- Modify socket path [\#192](https://github.com/parallaxsecond/parsec/pull/192) ([hug-dev](https://github.com/hug-dev))
- Changed local\_ids for Atomic counter and removed key\_slot\_semaphore. [\#191](https://github.com/parallaxsecond/parsec/pull/191) ([sbailey-arm](https://github.com/sbailey-arm))
- Removed duplicate macros for sign output size and export pub key size. [\#190](https://github.com/parallaxsecond/parsec/pull/190) ([sbailey-arm](https://github.com/sbailey-arm))
- Move Parsec over to psa-crypto  [\#186](https://github.com/parallaxsecond/parsec/pull/186) ([sbailey-arm](https://github.com/sbailey-arm))
- Add trace logging on Provide method calls [\#185](https://github.com/parallaxsecond/parsec/pull/185) ([hug-dev](https://github.com/hug-dev))
- Update fuzz target [\#184](https://github.com/parallaxsecond/parsec/pull/184) ([ionut-arm](https://github.com/ionut-arm))
- Improve log security [\#183](https://github.com/parallaxsecond/parsec/pull/183) ([ionut-arm](https://github.com/ionut-arm))
- Add GlobalConfig [\#182](https://github.com/parallaxsecond/parsec/pull/182) ([ionut-arm](https://github.com/ionut-arm))
- Add community repo link [\#180](https://github.com/parallaxsecond/parsec/pull/180) ([hug-dev](https://github.com/hug-dev))
- Use crates.io version of the interface [\#179](https://github.com/parallaxsecond/parsec/pull/179) ([hug-dev](https://github.com/hug-dev))
- Import the newest Parsec interface [\#178](https://github.com/parallaxsecond/parsec/pull/178) ([hug-dev](https://github.com/hug-dev))
- Improve handling of list\_opcodes [\#173](https://github.com/parallaxsecond/parsec/pull/173) ([ionut-arm](https://github.com/ionut-arm))
- Add default context cipher selection for TPM provider [\#172](https://github.com/parallaxsecond/parsec/pull/172) ([ionut-arm](https://github.com/ionut-arm))
- Add ECDSA support for TPM provider [\#171](https://github.com/parallaxsecond/parsec/pull/171) ([ionut-arm](https://github.com/ionut-arm))
- Improve TPM provider [\#168](https://github.com/parallaxsecond/parsec/pull/168) ([ionut-arm](https://github.com/ionut-arm))
- Improve digest handling in PKCS11 provider [\#167](https://github.com/parallaxsecond/parsec/pull/167) ([ionut-arm](https://github.com/ionut-arm))
- Split provider code into separate modules [\#165](https://github.com/parallaxsecond/parsec/pull/165) ([ionut-arm](https://github.com/ionut-arm))
- Add integration test [\#162](https://github.com/parallaxsecond/parsec/pull/162) ([ionut-arm](https://github.com/ionut-arm))
- Move end to end tests to own crate [\#160](https://github.com/parallaxsecond/parsec/pull/160) ([ionut-arm](https://github.com/ionut-arm))
- Move test client back in the Parsec repo [\#150](https://github.com/parallaxsecond/parsec/pull/150) ([ionut-arm](https://github.com/ionut-arm))
- Remove stress test on Travis CI for PKCS 11 [\#145](https://github.com/parallaxsecond/parsec/pull/145) ([hug-dev](https://github.com/hug-dev))
- Add tests checking if key attributes are respected [\#135](https://github.com/parallaxsecond/parsec/pull/135) ([hug-dev](https://github.com/hug-dev))
- Add Contributors file [\#132](https://github.com/parallaxsecond/parsec/pull/132) ([ionut-arm](https://github.com/ionut-arm))
- Update with the latest interface [\#131](https://github.com/parallaxsecond/parsec/pull/131) ([hug-dev](https://github.com/hug-dev))
- Improvments for tests/ci.sh [\#117](https://github.com/parallaxsecond/parsec/pull/117) ([anta5010](https://github.com/anta5010))

**Fixed bugs:**

- Integration tests should be isolated in their crate [\#155](https://github.com/parallaxsecond/parsec/issues/155)
- Key should be deleted from the KIM if generation/import fails [\#139](https://github.com/parallaxsecond/parsec/issues/139)
- Fixed PKCS\#11 provieder failing failed\_created\_key\_should\_be\_removed test [\#188](https://github.com/parallaxsecond/parsec/pull/188) ([sbailey-arm](https://github.com/sbailey-arm))
- Replace calendar iframe with URL [\#166](https://github.com/parallaxsecond/parsec/pull/166) ([ionut-arm](https://github.com/ionut-arm))
- Fix clippy errors [\#157](https://github.com/parallaxsecond/parsec/pull/157) ([ionut-arm](https://github.com/ionut-arm))
- Allow PKCS11 tests to fail on Travis [\#154](https://github.com/parallaxsecond/parsec/pull/154) ([ionut-arm](https://github.com/ionut-arm))

**Security fixes:**

- Implement mitigation 4 of TM [\#189](https://github.com/parallaxsecond/parsec/pull/189) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Allow TPM owner hierarchy auth to be non-string [\#120](https://github.com/parallaxsecond/parsec/issues/120)

**Merged pull requests:**

- Update partners file with web links and logos [\#159](https://github.com/parallaxsecond/parsec/pull/159) ([paulhowardarm](https://github.com/paulhowardarm))
- Update CONTRIBUTORS.md [\#143](https://github.com/parallaxsecond/parsec/pull/143) ([Superhepper](https://github.com/Superhepper))
- A few more README updates including fixes for broken doc links [\#141](https://github.com/parallaxsecond/parsec/pull/141) ([paulhowardarm](https://github.com/paulhowardarm))
- README enhancements, PARTNERS file and new visual style for the project [\#136](https://github.com/parallaxsecond/parsec/pull/136) ([paulhowardarm](https://github.com/paulhowardarm))

## [0.1.2](https://github.com/parallaxsecond/parsec/tree/0.1.2) (2020-02-27)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.1.1...0.1.2)

**Implemented enhancements:**

- Modify configuration to have provider-specific structs [\#114](https://github.com/parallaxsecond/parsec/pull/114) ([anta5010](https://github.com/anta5010))
- Improve code documentation [\#113](https://github.com/parallaxsecond/parsec/pull/113) ([ionut-arm](https://github.com/ionut-arm))

## [0.1.1](https://github.com/parallaxsecond/parsec/tree/0.1.1) (2020-02-21)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/0.1.0...0.1.1)

**Implemented enhancements:**

- Check for more Clippy lints [\#91](https://github.com/parallaxsecond/parsec/issues/91)
- Switch to picky-asn1-der for ASN.1-DER parsing [\#84](https://github.com/parallaxsecond/parsec/issues/84)
- Have all the providers dynamically loadable [\#79](https://github.com/parallaxsecond/parsec/issues/79)
- Pass config.toml path as command-line argument [\#78](https://github.com/parallaxsecond/parsec/issues/78)
- Convert Key ID Manager String errors to ResponseStatus in the KIM itself [\#77](https://github.com/parallaxsecond/parsec/issues/77)
- Test strategy for our providers on the CI [\#69](https://github.com/parallaxsecond/parsec/issues/69)
- Add a PKCS 11 Provider [\#66](https://github.com/parallaxsecond/parsec/issues/66)
- Add a Trusted Platform Module Provider [\#65](https://github.com/parallaxsecond/parsec/issues/65)
- Assess the contents of unsafe blocks in Mbed Provider [\#63](https://github.com/parallaxsecond/parsec/issues/63)
- Drop key handles implicitly [\#57](https://github.com/parallaxsecond/parsec/issues/57)
- Add cross-compilation to Aarch64 logic and investigate CI testing [\#55](https://github.com/parallaxsecond/parsec/issues/55)
- Add fuzz tests [\#54](https://github.com/parallaxsecond/parsec/issues/54)
- Update to Mbed Crypto v2.0.0 [\#38](https://github.com/parallaxsecond/parsec/issues/38)
- Improve logging message structure [\#36](https://github.com/parallaxsecond/parsec/issues/36)
- Make PARSEC a daemon [\#35](https://github.com/parallaxsecond/parsec/issues/35)
- Improve builders for service components [\#31](https://github.com/parallaxsecond/parsec/issues/31)
- Implement a thread pool [\#29](https://github.com/parallaxsecond/parsec/issues/29)
- Use dynamically-sized buffers in Mbed provider [\#27](https://github.com/parallaxsecond/parsec/issues/27)
- Implement configuration [\#26](https://github.com/parallaxsecond/parsec/issues/26)
- Prepare for upload to crates io [\#109](https://github.com/parallaxsecond/parsec/pull/109) ([ionut-arm](https://github.com/ionut-arm))
- Add cargo clippy lints to the CI [\#99](https://github.com/parallaxsecond/parsec/pull/99) ([hug-dev](https://github.com/hug-dev))
- Implement fuzz testing [\#97](https://github.com/parallaxsecond/parsec/pull/97) ([ionut-arm](https://github.com/ionut-arm))
- Add body length limit [\#96](https://github.com/parallaxsecond/parsec/pull/96) ([ionut-arm](https://github.com/ionut-arm))
- Ensure the safety of unsafe blocks [\#93](https://github.com/parallaxsecond/parsec/pull/93) ([hug-dev](https://github.com/hug-dev))
- Replace most panicking behaviours with Result [\#92](https://github.com/parallaxsecond/parsec/pull/92) ([hug-dev](https://github.com/hug-dev))
- Modify Travis CI test script [\#90](https://github.com/parallaxsecond/parsec/pull/90) ([hug-dev](https://github.com/hug-dev))
- Deny compilation for some rustc lints [\#87](https://github.com/parallaxsecond/parsec/pull/87) ([hug-dev](https://github.com/hug-dev))
- Switch crates to use picky-asn1-der [\#85](https://github.com/parallaxsecond/parsec/pull/85) ([hug-dev](https://github.com/hug-dev))
- Modify tests directory structure [\#83](https://github.com/parallaxsecond/parsec/pull/83) ([hug-dev](https://github.com/hug-dev))
- Allow optional providers and key ID managers [\#82](https://github.com/parallaxsecond/parsec/pull/82) ([hug-dev](https://github.com/hug-dev))
- Add a command-line option to select configuration [\#81](https://github.com/parallaxsecond/parsec/pull/81) ([hug-dev](https://github.com/hug-dev))
- Add a TPM provider [\#75](https://github.com/parallaxsecond/parsec/pull/75) ([hug-dev](https://github.com/hug-dev))
- Add SIGHUP signal handling to reload configuration [\#71](https://github.com/parallaxsecond/parsec/pull/71) ([hug-dev](https://github.com/hug-dev))
- Add a PKCS 11 provider [\#68](https://github.com/parallaxsecond/parsec/pull/68) ([hug-dev](https://github.com/hug-dev))
- Simplify the README.md file [\#67](https://github.com/parallaxsecond/parsec/pull/67) ([hug-dev](https://github.com/hug-dev))
- Add cross compilation tests to the CI with cross [\#64](https://github.com/parallaxsecond/parsec/pull/64) ([hug-dev](https://github.com/hug-dev))
- Add cross-compilation logic for Mbed Crypto [\#61](https://github.com/parallaxsecond/parsec/pull/61) ([hug-dev](https://github.com/hug-dev))
- Make key slot release implicit [\#59](https://github.com/parallaxsecond/parsec/pull/59) ([ionut-arm](https://github.com/ionut-arm))
- Make buffers dynamically sized in Mbed Provider [\#58](https://github.com/parallaxsecond/parsec/pull/58) ([ionut-arm](https://github.com/ionut-arm))
- Upgrade dependency on Mbed Crypto to v2.0.0 [\#56](https://github.com/parallaxsecond/parsec/pull/56) ([ionut-arm](https://github.com/ionut-arm))
- Add provider configuration [\#51](https://github.com/parallaxsecond/parsec/pull/51) ([ionut-arm](https://github.com/ionut-arm))
- Improve handling of systemd activation [\#50](https://github.com/parallaxsecond/parsec/pull/50) ([lnicola](https://github.com/lnicola))
- Replace println calls with log crate [\#48](https://github.com/parallaxsecond/parsec/pull/48) ([hug-dev](https://github.com/hug-dev))
- Add a compile-time option for a daemon binary [\#46](https://github.com/parallaxsecond/parsec/pull/46) ([hug-dev](https://github.com/hug-dev))
- Add service builder and configuration [\#44](https://github.com/parallaxsecond/parsec/pull/44) ([ionut-arm](https://github.com/ionut-arm))
- Add stress test to the suite [\#42](https://github.com/parallaxsecond/parsec/pull/42) ([ionut-arm](https://github.com/ionut-arm))
- Add SIGTERM handler for a graceful shutdown [\#39](https://github.com/parallaxsecond/parsec/pull/39) ([hug-dev](https://github.com/hug-dev))
- Add a GitHub Actions workflow for CI [\#34](https://github.com/parallaxsecond/parsec/pull/34) ([hug-dev](https://github.com/hug-dev))
- Add and improve component builders [\#33](https://github.com/parallaxsecond/parsec/pull/33) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- TPM provider must support Owner Hierarchy authentication [\#102](https://github.com/parallaxsecond/parsec/issues/102)
- Audit our use of panicking [\#74](https://github.com/parallaxsecond/parsec/issues/74)
- Audit our use of unsafe code [\#73](https://github.com/parallaxsecond/parsec/issues/73)
- Review response codes returned by providers [\#72](https://github.com/parallaxsecond/parsec/issues/72)
- Warning during compilation about `llvm-config --prefix` [\#60](https://github.com/parallaxsecond/parsec/issues/60)
- Key handle manipulation is not thread-safe in Mbed Crypto [\#40](https://github.com/parallaxsecond/parsec/issues/40)
- Add owner hierarchy auth param [\#104](https://github.com/parallaxsecond/parsec/pull/104) ([ionut-arm](https://github.com/ionut-arm))
- Add a verify-only integration test [\#88](https://github.com/parallaxsecond/parsec/pull/88) ([hug-dev](https://github.com/hug-dev))
- Add sign to ASN.1 Integer types for RSAPublicKey [\#86](https://github.com/parallaxsecond/parsec/pull/86) ([hug-dev](https://github.com/hug-dev))
- Make sure Cargo features work [\#76](https://github.com/parallaxsecond/parsec/pull/76) ([hug-dev](https://github.com/hug-dev))
- Make UnixStreams block on read/write [\#47](https://github.com/parallaxsecond/parsec/pull/47) ([ionut-arm](https://github.com/ionut-arm))
- Keep key ID within bounds for Mbed provider [\#45](https://github.com/parallaxsecond/parsec/pull/45) ([ionut-arm](https://github.com/ionut-arm))
- Add locking around key handle operations in mbed provider [\#41](https://github.com/parallaxsecond/parsec/pull/41) ([ionut-arm](https://github.com/ionut-arm))
- Use new version of test client to fix CI [\#37](https://github.com/parallaxsecond/parsec/pull/37) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Deny compilation if there is any warning [\#80](https://github.com/parallaxsecond/parsec/issues/80)

**Merged pull requests:**

- Remove references to key lifetime [\#52](https://github.com/parallaxsecond/parsec/pull/52) ([hug-dev](https://github.com/hug-dev))
- Use thread pool instead of new thread per request [\#30](https://github.com/parallaxsecond/parsec/pull/30) ([ionut-arm](https://github.com/ionut-arm))
- Add the integration tests in the parsec repository [\#28](https://github.com/parallaxsecond/parsec/pull/28) ([hug-dev](https://github.com/hug-dev))

## [0.1.0](https://github.com/parallaxsecond/parsec/tree/0.1.0) (2019-10-09)

[Full Changelog](https://github.com/parallaxsecond/parsec/compare/047e395ee5edbad82d52738e275f756e7bd0480b...0.1.0)

**Closed issues:**

- Building/running PARSEC [\#4](https://github.com/parallaxsecond/parsec/issues/4)
- Add Jenkins, CI/CD, unit testing, and code coverage [\#3](https://github.com/parallaxsecond/parsec/issues/3)
- Implement stubbed server API for client testing [\#2](https://github.com/parallaxsecond/parsec/issues/2)
- Create PASL golang client API [\#1](https://github.com/parallaxsecond/parsec/issues/1)

**Merged pull requests:**

- Add versioning requirement on the interface [\#25](https://github.com/parallaxsecond/parsec/pull/25) ([hug-dev](https://github.com/hug-dev))
- Fixed Ionut's email address [\#24](https://github.com/parallaxsecond/parsec/pull/24) ([robdimond-arm](https://github.com/robdimond-arm))
- Remove Go client from PARSEC service [\#22](https://github.com/parallaxsecond/parsec/pull/22) ([hug-dev](https://github.com/hug-dev))
- Add documentation updates [\#21](https://github.com/parallaxsecond/parsec/pull/21) ([hug-dev](https://github.com/hug-dev))
- Docs: Update documentation to reflect the source code state [\#20](https://github.com/parallaxsecond/parsec/pull/20) ([ionut-arm](https://github.com/ionut-arm))
- Add support for ListProviders operation update [\#19](https://github.com/parallaxsecond/parsec/pull/19) ([hug-dev](https://github.com/hug-dev))
- Add a MAINTAINERS file [\#18](https://github.com/parallaxsecond/parsec/pull/18) ([hug-dev](https://github.com/hug-dev))
- Merge Integration into Master [\#17](https://github.com/parallaxsecond/parsec/pull/17) ([ionut-arm](https://github.com/ionut-arm))
- Update conn and key interfaces for initialization [\#16](https://github.com/parallaxsecond/parsec/pull/16) ([jamesonhyde-docker](https://github.com/jamesonhyde-docker))
- Update response to handle a mis-aligned header and response test [\#15](https://github.com/parallaxsecond/parsec/pull/15) ([jamesonhyde-docker](https://github.com/jamesonhyde-docker))
- Various improvements of the service internals [\#14](https://github.com/parallaxsecond/parsec/pull/14) ([hug-dev](https://github.com/hug-dev))
- Go client implementations [\#12](https://github.com/parallaxsecond/parsec/pull/12) ([jamesonhyde-docker](https://github.com/jamesonhyde-docker))
- update logo from plasma to parsec [\#11](https://github.com/parallaxsecond/parsec/pull/11) ([adamparco](https://github.com/adamparco))
- Initial go client interface for signing keys [\#10](https://github.com/parallaxsecond/parsec/pull/10) ([jamesonhyde-docker](https://github.com/jamesonhyde-docker))
- Provide minimal software solution based on Mbed Crypto [\#9](https://github.com/parallaxsecond/parsec/pull/9) ([hug-dev](https://github.com/hug-dev))
- Add API landing page [\#8](https://github.com/parallaxsecond/parsec/pull/8) ([ionut-arm](https://github.com/ionut-arm))
- Adding doc fragments. [\#7](https://github.com/parallaxsecond/parsec/pull/7) ([ionut-arm](https://github.com/ionut-arm))
- update name from PASL to PLASMA [\#6](https://github.com/parallaxsecond/parsec/pull/6) ([adamparco](https://github.com/adamparco))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
