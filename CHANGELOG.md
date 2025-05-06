# List of changes

This file briefly describes the features/changes and fixes in each release of the Security Middleware project.
The project delivers 4 components:
* SMW Library: The core library itself including the OSAL part. It exposes two public APIs: the SMW API and the PSA API.
* SMW Tests: Tests validating the core library.
* PKCS#11 Library: The pkcs#11 library interfacing with the SMW library.
* PKCS#11 Tests: Tests validating the PKCS#11 library

Each component handles its own version number specified in each component main CMakeList.txt file:
* SMW Library [CMakeLists](./core/CMakeLists.txt)
* SMW Tests [CMakeLists](./tests/CMakeLists.txt)
* PKCS#11 Library [CMakeLists](./pkcs11/CMakeLists.txt)
* PKCS#11 Tests [CMakeLists](./pkcs11/tests/CMakeLists.txt)


## List of releases

The releases are listed from the most recent to the first one.

1. [Release 5.0](#rel_5_0)
2. [Release 4.2](#rel_4_2)
3. [Release 4.1](#rel_4_1)
4. [Release 4.0](#rel_4_0)
5. [Release 3.0](#rel_3_0)
6. [Release 2.5](#rel_2_5)
7. [Release 2.4](#rel_2_4)
8. [Release 2.3](#rel_2_3)
9. [Release 2.2](#rel_2_2)
10. [Release 2.1](#rel_2_1)
11. [Release 2.0](#rel_2_0)
12. [Release 1.0](#rel_1_0)

---
### <a id ="rel_5_0"></a></br>**Release 5.0**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. PKCS#11

* As some subsystems are not handling key usage and permitted algorithm, the
  find operation is not able to find all keys whose template defines key usage
  and permitted algorithm.

#### SMW Library - _version 5.0_
##### 1. SMW APIs

* Device manager returns the correct status code if the arguments version is
  not supported.
* Fix SW implementation of the hash multipart when input is a multiple of block.
* Key manager returns the correct status code if the arguments version is
  not supported.
* The `ENABLE_TLS12` cmake option has been superseded by `ENABLE_TLS`.
  Likewise, the 'tls12' argument for the `smw_build.sh` script has been
  renamed to 'tls'.
* Add additional parameters in the algorithm definition to manage EDDSA pure
  prehashed, context key permitted algorithm.
* Add additional parameters in the algorithm definition to manage signature
  message input already hashed.
* Remove Update key operation.
* Integrate key attributes in the key descriptor. Breaking compatibility for
  the APIs:
    - smw_generate_key()
    - smw_get_key_attributes()
    - smw_derive_key()
    - smw_import_key()
* Add a new status code `SMW_STATUS_PUBLIC_EXPONENT_NOT_SUPPORTED`.
* Add support for X25519 key type (used for x25519 TLS key exchange).

##### 2. Subsystems

* ELE: Remove HKDF support. Secure Enclave doesn't support it anymore.
* ELE: Remove TLS 1.2 plain text versus key ids output buffer flag.
* ELE: Handle EDDSA additional parameters and signature message hashed flag.
* ELE: Add support for TLS1.3 KDF.
* ELE: Add any EDDSA variant for key creation permitted algorithm.
* TEE: Fix the ed25519 key security size to be 255 bits.
* TEE: Improve object storage management.
* TEE: Handle EDDSA additional parameters and signature message hashed flag.
* SECO: Fix coverity finding.
* SECO: Handle signature message hashed flag.
* ELE: Add support for signature generation using plaintext private key buffer.
* ELE: Add support for hash mac generation using plaintext private key buffer.

##### 3. ARM PSA APIs


##### 4. OSAL

* Add a dedicated configuration file for i.MX943.
* Remove HKDF key derivation in all ELE based configurations.
* Add support of the EDDSA signature for TEE subsystem in all configurations
* Add support of key permitted algo and key usage in Object database.
* Add a database version information and verification.
* Remove AEAD support for ELE subsystem in i.MX95 and i.MX943 configuration files.

#### SMW Tests - _version 5.0_

* Disable the tests that validate algorithms and key types that are currently
  unsupported on the i.MX943 platform.
* Disable TLS1.2 tests on i.MX943 platform.
* ELE tests: Disable HKDF validation.
* Fix TEE ed25519 key security size in the tests.
* Validate hash multipart when input is a multiple of block.
* Add subtests in U_API_Derive_004 to verify the management of the
  arguments version.
* ELE tests: Add tests to validate TLS1.3 operations: U_API_Derive_005,
  U_ELE_Derive_006, U_ELE_Derive_007, U_ELE_Derive_008.
* Remove "DEFAULT" algorithm and introduce "MSG_HASHED" parameter.
* Update U_API_Objects_002 to find key by permitted algo or usage.
* Add tests to validate signature generation and verification using plaintext key buffer.
* Disable ELE AEAD tests for i.MX95 and i.MX943 platforms.
* ELE tests: Add tests to validate X25519 key exchange: U_ELE_Generate_005, U_ELE_Derive_009,
  U_ELE_Derive_010, U_ELE_Derive_011.
* Add tests to validate HMAC generation and verification using plaintext key buffer.

#### PKCS#11 Library - _version 5.0_

* Add support for ed25519 key generation and signature
* Add TLS 1.3 Key exchange support
* TLS AES GCM mulpti-part operation transforms to one shot operation.

#### PKCS#11 Tests - _version 5.0_

* Add DES key generation performance test.
* Add test to validate ed25519 key generation and signature
* Do not run DES key generation performance test in debug build.
* Test TLS 1.3 Key exchange tests.
* Test TLS 1.3 AES GCM multi-part operation.
* Test TLS 1.3 Hash MAC operation.
* Fix performance test result calculation on 32bits platforms.

---
### <a id ="rel_4_2"></a></br>**Release 4.2**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported in case of reprovisioning.
* Key manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported in case of TLS1.2 KDF.

##### 3. PKCS#11

* As some subsystems are not handling key usage and permitted algorithm, the
  find operation is not able to find all keys whose template defines key usage
  and permitted algorithm.

#### SMW Library - _version 4.2_
##### 1. SMW APIs

* Save data storage ID in database to check for ELE EL2GO certificate object.
* Call `smw_delete_data()` to delete ELE EL2GO object.
* Fix coverity 2024.9.0 findings.
* Add key derivation permitted algorithm validation when key created.
* Fix MAC hash bitmap management.
* Fix library to build modularly.
* Fix a memory leak in keymgr.
* Fix key privacy update in keymgr.

##### 2. Subsystems

* ELE: Add ed25519 key management.
* ELE: Add support of ed25519 Sign and Verify operations.
* Fix coverity 2024.9.0 findings.
* ELE: Fix HKDF key permitted algorithm.
* SECO: Fix key store creation by setting strict operation flag.
* TEE: Add support for key derivation using ECDH.
* TEE: Fix key usage conversion TEE to SMW.
* TEE: TA: Fix key type conversion TEE to SMW.
* TEE: Add hardcoded permitted algorithm for keys with unique permitted algorithm.
* ELE: HKDF: Remove derived key buffer export capability.
* ELE: Update RSA permitted algorithms
* ELE: Add support for TLS1.2 KDF
* SECO: Updated support for TLS1.2 to the new API

##### 3. ARM PSA APIs

* Add support for ed25519 key management.
* Add support for Edwards-curve digital signature algorithms (PureEdDSA and ED25519PH).

##### 4. OSAL

* Add SMW_LOG_FILE and SMW_LOG_LEVEL environment variable in debug build.
At init time, log can be redirected to a file and log level could be set.
* ED25519 is supported by ELE on i.MX93 and i.MX91, add support to Key management
Sign and Verify algorithm in ELE configuration file.
* Fix coverity 2024.9.0 findings.

#### SMW Tests - _version 4.2_

* Add tests to validate ed25519 Key generation operations with ELE subsystem.
* Add tests to validate ed25519 Sign and Verify operations with ELE subsystem.
* Fix coverity 2024.9.0 findings.
* Fix object descriptor when finding data.
* Correct the test definition to run when TEE subsystem not enabled.
* Correct the certificate length in U_ELE_Attestation_001 test.
* Add U_TEE_Derive_004.
* U_ELE_Derive tests: Remove tests exporting the derived key buffer.
* Add privacy check in U_API_Object test.
* Add tests to validate TLS1.2 operations with ELE: U_ELE_Derive_005.
* Add tests to validate TLS1.2 operations with SECO: U_SECO_Derive_003.

#### PKCS#11 Library - _version 4.2_

* Add implementation for C_(Get|Set)OperationState functions
* Add support for `CKO_PROFILE` object handling.
* Add support for `CKM_ECDH1_DERIVE` mechanism.
* Fix a memory leak in object database support.
* Add support for secp224r1, secp384r1 and secp521r1 curves.
* Add support for handling only session `CKO_CERTIFICATE` objects.
  Token `CKO_CERTIFICATE` objects remain unsupported.
* Optimize code to merge common function and manipulate key and data SMW
  descriptor at one place.
* Move token key id in generic key object.
* Export token public key from SMW only on demand.
* Add `CKK_GENERIC_SECRET` key support

#### PKCS#11 Tests - _version 4.2_

* Add tests for C_(Get|Set)OperationState functions
* Fix coverity 2024.9.0 findings.
* Add tests for `CKO_PROFILE` object.
* Fix tests to run when TEE subsystem not enabled.
* Add tests for `CKM_ECDH1_DERIVE` mechanism.
* Update EC key test to validate all supported NIST curves.
* Add tests for `CKO_CERTIFICATE` object.
* Add tests finding keys generated without using PKCS11 generate operation.
* Add tests for `CKK_GENERIC_SECRET` key type.

---
### <a id ="rel_4_1"></a></br>**Release 4.1**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ELE Subsystem

* System hang may occur while generating RSA key on i.MX95.

##### 3. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported in case of reprovisioning.

#### SMW Library - _version 4.1_
##### 1. SMW APIs

* RSA public exponent set by the user is handled by TEE subsystem.
* Add SMW Object descriptor structure
* Unload the subsystem when smw_cancel_operation() is called or when a
  cryptographic multi-part operation terminates to respect the subsystem
  load/unload method `AT_CONTEXT_CREATION_DESTRUCTION`.
* Add SMW Object find API.
* Key import: redirect the EdgeLock 2GO data import to data storage module.
* Define EdgeLock 2GO Key and Data object label.
* Add support of hash multi-part with TEE and ELE subsystems.
* As CHACHA20 POLY1305 is not supported on i.MX95, remove it from
  AEAD supported algorithm in ele_imx95_config file.
* Add a new key type `SMW_KEY_TYPE_NAME_HKDF_IKM`.
* Add support of hash multi-part.
* Set default key usage flags if get key attributes operation is not supported by the subsystem.

##### 2. Subsystems

* TEE: Fix subsystem load() function to return error if TA and context failed.
* TEE: Add support of ed25519 Sign and Verify operations.
* ELE: Move selection of the EdgeLock 2GO data import selection in generic part.
* TEE: Add support for key import using HKDF IKM key.
* TEE: Remove exporting of symmetric base key in key derivation in TA.
* TEE: Update the supported base key type for HKDF key derivation. Only a
  previously imported HKDF IKM key or a plaintext buffer is supported.
* SECO: Add support of hash multi-part with SHA1, SHA224, SHA256, SHA384 and SHA512.
* SECO: Add support of hash one-shot with SHA1.

##### 3. ARM PSA APIs

##### 4. OSAL

* Create the database directory if not existing
* Add support of SQLite3 to handle database
* Add OSAL DB find API.

#### SMW Tests - _version 4.1_

* Add tests to validate ed25519 Sign and Verify operations with TEE subsystem.
* Add U_API_Object_001 and U_API_Object_002.
* Add import tests for new key type `SMW_KEY_TYPE_NAME_HKDF_IKM` for TEE.
* Update the base key type to `SMW_KEY_TYPE_NAME_HKDF_IKM` in the TEE key
  derivation tests.
* Add a new configuration API smw_config_check_derive_key() to check if the
  provided KDF name is supported by the subsystem.
* Add tests to validate hash multi-part.

#### PKCS#11 Library - _version 4.1_

* Add Linux pthread mutex callbacks if none given by the application.
* Initialize SMW's token when pkcs11 library is initialize (C_Initialize).
* Initialize the SMW library and then fill the Mechanism list when C_Initialize
is called.
* Fix data object label.
* Remove the data hardcoded label used to configure SMW library, use the
  system configuration file (smw.conf) instead.
* Find and retrieve token object from the database objects table
* Update token object in the database objects table
* Add support for Key derivation using HKDF.
* Import only the token key to subsystem.
* Retrieve public buffer of a key generated or imported using SMW API.
* Add C_GetObjectSize support
* Implement multi-part sign/verify PKCS#11 APIs.

#### PKCS#11 Tests - _version 4.1_

* Remove the C_InitToken calls every time session is opened.
* Add SMW's system configuration in the ctest test script.
* Add tests for single-part AEAD mechanisms.
* Test crypto operation using a persistent key generated with the PSA and SMW API
* Test data object retrieve using a persistent data created with the PSA API
* Test object persistency after killing the library context.
* Add tests for Key derivation using HKDF.
* Validate public buffer retrieval of a key generated or imported using the SMW API.
* Add get object size unit test.
* Validate multi-part sign/verify PKCS#11 APIs.

---
### <a id ="rel_4_0"></a></br>**Release 4.0**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported in case of reprovisioning.

##### 3. OSAL

* Cannot create the SMW datbase if the user specifies a directory that does not exist in the file system.

#### SMW Library - _version 4.0_
##### 1. SMW APIs
* Update `smw_derive_key()` API argument and add support for HKDF based key derivation.
* Key attributes, data attributes and signature algorithm are no longer encoded with TLV format. They are now encoded with a dedicated bitmap.
* Replace public string arguments with enum type in all SMW public APIs.
* Rename `smw_aead_update_add()` as `smw_aead_update_aad()`.
* Fix context operation free function.
* Generate a data ID if user calls the store data API with an ID set to 0.
* Update `smw_derive_key()` API arguments and add support for HKDF (Full/
  Extract/Expand) based key derivation.
* Selection of the subsystem during the key generate or import based on the permitted algorithm.

##### 2. Subsystems

* ELE subsystem: Fix cipher get output length feature.
* Add TEE subsystem ed25519 key management.
* Add ELE support for the CHACHA20_POLY1305 AEAD mode.
* Fix SECO MAC length to be exact length due to SECO limitation.
* Switch the SECO subsystem to the new Secure Enclave library.
* Fix SECO Data length, return data length relying on the database content.
* Add support for HKDF based key derivation in the TEE subsystem.
* Remove default value assignment for key attributes when undefined by the user across all subsystems.
  Additionally, remove default value assignment for key usage when undefined by the user for TEE subsystem.
* ELE subsystem add MD5 and SHA1 digest.
* ELE subsystem add RSA signature.
* Add TEE subsystem random IV generation.
* Add support for HKDF based key derivation in the ELE subsystem.
* TEE subsystems: Add support for importing the derived key buffer with
  user-supplied key attributes upon request.

##### 3. ARM PSA APIs

* Upgrade ARM PSA Crypto API to version 1.2.1.

##### 4. OSAL

* Add management of a linux system configuration file (/etc/opt/smw/smw.conf).
* Create common SMW library configuration definition file.
* Manage independently persistent and transient database mutex. Don't rely on
  the SQlite threadsafe protection.
* Ensure database(s) can't be changed after library initialization.

#### SMW Tests - _version 4.0_

* Fix undefined behavior with both `vprinf()` and `vfprinf()` reusing the same va_list.
* Fix trivial memory leak in util_list.c.
* Simplify the description of key attributes, data attributes and signature algorithm in test definition files.
* Add tests to validate ed25519 key management in TEE subsystem.
* Add ELE tests for CHACHA20_POLY1305 (U_ELE_Aead_001 and U_ELE_Aead_004).
* Add PSA tests for CHACHA20_POLY1305 (U_PSA_Aead_005 and U_PSA_Aead_006).
* Add tests for HKDF based key derivation.
* Add tests for HKDF Full, Extract and Expand steps.

#### PKCS#11 Library - _version 4.0_

* Update to PKCS#11 3.1 Specification.
* Implement message-based encrypt/decrypt PKCS#11 APIs.
* Change the data unique ID generation. Ask SMW to generate a data ID.
* Add support for single-part AEAD mechanisms: CKM_AES_CCM, CKM_AES_GCM, CKM_CHACHA20_POLY1305.

#### PKCS#11 Tests - _version 4.0_

* Validation of message-based encrypt/decrypt PKCS#11 APIs.
* Enable validation on Secure Enclave subsystem prior to TEE subsystem.

---
### <a id ="rel_3_0"></a></br>**Release 3.0**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported in case of reprovisioning.

#### SMW Library - _version 3.0_
##### 1. SMW APIs

* Fix the selection of the subsystem for cryptographic operations using one or more key(s).
  The selection is based on the content of the configuration file unless the cryptographic operation
  uses one or more key(s). In this case, the subsystem associated to the key(s) must be selected.
* Device manager returns the correct status code if the arguments version is not supported except in case of reprovisioning .
* Change public AEAD arguments structure members (`struct smw_aead_args`, `struct smw_aead_aad_args` and `struct smw_aead_final_args`).
* Add support of key attestation.
* Add dedicated status codes for cases where the argument string name provided by the user or the parameter set in the user configuration file is not recognized by SMW.
* Skip reading of tag `OP_TYPE_VALUES` for any key related security operation other than `DERIVE_KEY`.
* Change the `struct smw_keypair_rsa` to have first fields common to the `struct smw_keypair_gen`.
* Add support of storage re-provisioning.
* Add trace level EXTRA to lighten trace level DEBUG.
* Add prefix `[SMW]` to SMW traces.
* Add support of SHA-3 hash algorithm.
* Update the design of context management. Add a new API `smw_allocate_context()` to allocate context before initializing multi-part operation. Automatically release context resources if final multi-part operation succeeds, or upon encountering any critical error during the multi-part cryptographic operation or by calling the `smw_cancel_operation()` API.
* Update the arguments passed to `smw_cancel_operation()` and `smw_copy_context()`.
* Support storing the IV used by subsystem in the `output_iv` field for the AEAD final encryption operation, in addition to existing support for the one-shot AEAD encryption operation.
* Fix the TLV lifecycle encoding to handle boolean. Make TLV lifecycle as core global function.
* Fix SECO static link libraries.
* Add get data information API.

##### 2. Subsystems

* Add SECO subsystem storage data store and retrieve.
* Add TEE subsystem storage data store, retrieve and delete.
* Add support of CFB mode with ELE subsystem.
* Implement AEAD one-shot operation for ELE subsystem.
* Implement AEAD one-shot operation for SECO subsystem.
* Add ELE subsystem RSA key management.
* Implement storage re-provisioning for ELE subsystem.
* Add support of SHA-3 hash with TEE and ELE subsystems.
* Implement context management for TEE subsystem.
* Implement context management for ELE subsystem.
* Implement context management for HSM subsystem.
* Add ELE subsystem data delete.
* Rename HSM subsystem as SECO subsystem.
* Add ELE subsystem attestation key permitted algorithm.
* Remove SMW_STATUS_DATA_ALREADY_RETRIEVED no more used in ELE subsystem.
* Implement SM4 block cipher for TEE subsystem.
* Add SECO NVM Secure Storage start new attempt in case of failure
* Add function to check if a data is present and to get data information in ELE/TEE subsystem.

##### 3. ARM PSA APIs

* Add support of CFB mode.
* Add support of SHA-3 hash.
* Add support for single-part AEAD encryption APIs: `psa_aead_encrypt()` & `psa_aead_decrypt()`
* Change psa_its_get_info() to call the SMW get data information API.

##### 4. OSAL

* Add trace level EXTRA to lighten trace level DEBUG.
* Add prefix `[OSAL]` to OSAL traces.
* Fix the find_db_obj_free() to increment the object id until one id is free.

#### SMW Tests - _version 3.0_

* Change the TA installation default path to be `/usr/lib`.
* Update the key name and remove duplicate subtests in U_API_Aead_002.
* Remove key 1 and key_name in U_API_Aead_Multipart_005.
* Remove the subtest with incorrect tag length in U_API_Aead_Multipart_001.
* Remove aead_id and update expected result to `SMW_STATUS_INVALID_PARAM` when IV length = 6 in U_ELE_Aead_003.
* Update the expected result in test definition files for scenarios where the parameter string value is not recognized by SMW.
* Add test to validate ELE RSA key management.
* Add storage re-provisioning.
* Add skipped test management.
* Fix test engine to read data/key ID >= 0x80000000 from JSON definition.
* Add prefix `[TEST]` to test traces.
* Add SHA-3 test vectors in U_TEE_Hash_002 and U_ELE_Hash_002.
* Add SHA-3 test vectors in U_PSA_Hash_002.
* Add tests to validate revised context management.
* Review data storage test to delete data.
* Add tests for SM4 block cipher.
* Add AEAD test vectors in F_PSA_Aead_001, U_PSA_Aead_001 and U_PSA_Aead_002.
* Add tests to validate PSA single-part AEAD operations.
* Add tests to validate the SMW get data information API.
* Add data storage of a base64 value.

#### PKCS#11 Library - _version 3.0_

* Add prefix `[PKCS11]` to PKCS#11 traces.
* Update context management.
* Implement message-based sign/verify with MACs single-part PKCS#11 APIs.
* Implement SM4 block cipher support as a vendor extension.

#### PKCS#11 Tests - _version 3.0_

* Change the TA installation default path to be `/usr/lib`.
* Add prefix `[TEST]` to PKCS#11 test traces.
* Validation of message-based sign/verify with MACs single-part PKCS#11 APIs.
* Add SHA-3 test vectors in pkcs11_digest test suite.
* Add SM4 block cipher tests.

---
### <a id ="rel_2_5"></a></br>**Release 2.5**
---
#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported.

#### SMW Library - _version 2.5_
##### 1. ARM PSA APIs

* Implement PSA Internal Storage APIs.

##### 2. SMW APIs

* Fix overall code to allow disabling cmake options.
* Add commit key storage API.
* Add get/set device lifecycle API.
* Add key attributes in the `smw_delete_key()` arguments.
* Add AEAD one-shot and multi-part APIs.

##### 3. Subsystems

* Fix HSM subsystem key group update when creating TLS keys.
* Add commit key storage operation in all subsystems. In HSM and TEE subsystem
  the operation is not available so success is always returned. HSM subsystem
  key storage commit is managed with the "FLUSH_KEY" attributes of key operation.
* Fix the handling of `CURRENT` lifecycle in ELE subsystem. It is not ignored anymore.
* Add get/set device lifecycle operations in ELE subsystem.
* Fix HSM delete key operation to handle "FLUSH_KEY" attribute to commit the
  key storage rollback protection.
* Implement AEAD one-shot and multi-part operations for OPTEE subsystem.

##### 4. OSAL

* OSAL key database becomes OSAL object database that can store keys and raw data.

#### SMW Tests - _version 2.5_

* Fix test F_TEE_Keymgr_005 instability.
* Fix test F_TEE_App_002, ensure key is deleted when no more used.
* Add TEE and HSM tests to validate `smw_commit_key_storage()`. No ELE test provided
  because incrementing the rollback protection implies to reload the key storage
  saved when counter was incremented and it's not feasable in the CI test suite.
* Add tests to validate `smw_device_get_lifecycle()` and `smw_device_set_lifecycle()`.
* Add project option `TEE_TA_DESTDIR` to install TAs in a directory other than
  the system `\lib` directory.
* Add more tests to validate device UUID and Attestation APIs.
* Validation of AEAD (one-shot and multi-part) SMW's APIs.

#### PKCS#11 Library - _version 2.5_

* Fix object's mutex destroy.
* Fix TLV numeral attribute construction generating a memory overflow.

#### PKCS#11 Tests - _version 2.5_

* Add project option `TEE_TA_DESTDIR` to install TAs in a directory other than
  the system `\lib` directory.
---
### <a id ="rel_2_4"></a></br>**Release 2.4**
---
#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ELE Subsystem

* Data storage API does not handle the `CURRENT` lifecycle properly. If the application restricts the data accessibility to the `CURRENT` lifecycle and another one or more, then the `CURRENT` lifecycle is ignored.

##### 3. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported.

#### SMW Library - _version 2.4_
##### 1. ARM PSA APIs

* Fix coverity and ensure all variables are initialized.
* Add RAW data key type support.

##### 2. SMW APIs

* Fix coverity in configuration module and ensure all variables are initialized.
* Fix coverity in cryptography module and ensure all variables are initialized.
* Fix coverity in key manager module and ensure all variables are initialized.
* Fix the SMW_DBG_ASSERT() macro to exit properly in release and debug mode.
* Add device manager APIs: `smw_device_attestation()` and `smw_device_get_uuid()`.
* Add support to fetch the length of output buffer in `smw_cipher_update()` api.
* Add storage manager APIs: `smw_store_data()`, `smw_retrieve_data()`,
  `smw_delete_data()`.

##### 3. Subsystems

* The TEE TAs are compiled with TA flags TA_FLAG_SINGLE_INSTANCE and TA_FLAG_MULTI_SESSION. All TA instances can handle several sessions.
* Fix TEE TA library retrieving ECC key buffer size.
* Change ELE subsystem to align ELE Library API arguments.
* Fix coverity in HSM subsystem and ensure all variables are initialized.
* Fix coverity in ELE subsystem and ensure all variables are initialized.
* Fix coverity in TEE subsystem and ensure all variables are initialized.
* Fix coverity in TA Library of the TEE subsystem and ensure all variables are initialized.
* Add ELE subsystem storage data store and retrieve.
* Add ELE EL2GO data import.
* Fix ELE persistent/permanent key deletion strict operation.
* Fix ELE subsystem Key group management.
* Fix HSM subsystem Key group management.

##### 4. OSAL

* Fix coverity and ensure all variables are initialized.

#### SMW Tests - _version 2.4_

* Fix coverity and ensure all variables are initialized.
* Remove the subtest where the output data buffer is NULL in U_API_Cipher_Multipart_002.json.
* Add SMW API storage tests engine.

#### PKCS#11 Library - _version 2.4_

* Fix coverity and ensure all variables are initialized.
* Implement encrypt/decrypt (single-part and multi-part) PKCS#11 APIs.

#### PKCS#11 Tests - _version 2.4_

* Fix coverity and ensure all variables are initialized.
* Validation of encrypt/decrypt (single-part and multi-part) PKCS#11 APIs.

---
### <a id ="rel_2_3"></a></br>**Release 2.3**
---
#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. TEE Subsystem

* Two or more applications cannot have concurrent access to the same key storage because the TEE TAs only support one session.

##### 3. SMW APIs

* Device manager returns `SMW_STATUS_INVALID_VERSION` instead of `SMW_STATUS_VERSION_NOT_SUPPORTED` if the arguments version is not supported.

#### SMW Library - _version 2.3_
##### 1. ARM PSA APIs

* Fix memory leak caused by key generation and key import.
* Fix export of RSA, ECC and symmetric keys.
* Fix import of RSA keys and ECC keys.
* Implement Sign and Verify operations.
* Fix generation and import of DES keys and DES3 keys.
* Implement Cipher single part operation.
* Implement get key attributes.
* Key identifier can be set by caller in case of key creation.

##### 2. SMW APIs

* Implement MAC single part operation (compute and verify).
* Deprecate HMAC compute operation. Merge with MAC operation.
* Clarify the `smw_get_key_buffers_lengths()` API usage.
* Implement get key attributes API.
* Key identifier can be set by caller in case of key creation.
* Add STORAGE_ID key attributes.

##### 3. Subsystems

* Remove dependence of ELE on zLib.
* Add AES CMAC algorithm in HSM, ELE and TEE subsystems.
* Update TEE TA Library to check key usages preventing TA panic.
* Update TEE TA Library to support user key identifier as input when key is created.
* Support of the EdgeLock 2GO Key import in ELE subsystems.
* Fix TEE TA Library key identifier list management.

#### SMW Tests - _version 2.3_

* Add suspend command to switch device in sleep to memory mode (remove dedicated script to run suspend/resume test).

---
### <a id ="rel_2_2"></a></br>**Release 2.2**
---

#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ARM PSA APIs

* Key generation and key import cause memory leak.
* Export of any type of key fails.
* Import of RSA keys and ECC keys fails.
* Generation and import of DES keys and DES3 keys fail.

#### SMW Library - _version 2.2_
##### 1. Subsystem

* Add EdgeLock Enclave (ELE) subsystem.

##### 2. ARM PSA APIs

* Implement Key manager (Generate, Import, Export, Delete).

---
### <a id ="rel_2_1"></a></br>**Release 2.1**
---

#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

#### SMW Library - _version 2.1_
##### 1. ARM PSA APIs

* Upgrade ARM PSA Crypto API to version 1.1.0.
* Implement Hash one go.

##### 2. OSAL

* Change linux OSAL key database primitives to use `fcntl()` function in order to lock file access. This function guaranties file locking in case of multi-process and even with NFS file system.

##### 3. Subsystem

* Add HMAC Key generation and HMAC generation for the HSM subsystem.
* Add handling of key policy.

##### 4. SMW APIs

* Remove fields `key_attributes_list` and `key_attributes_list_length` from `struct smw_export_key_args`.

##### 5. Key manager

* Add support of key policy in key attributes list.

#### SMW Tests - _version 2.1_

* Add key policy tag in the test definition.

#### PKCS#11 Library - _version 2.1_

* Set the key policy in the key template when generating/importing keys.

---
### <a id ="rel_2_0"></a></br>**Release 2.0**
---
This version introduces the support of the ARM PSA APIs in addition to the SMW APIs. The PSA operations are routed to a dedicated subsystem, if the subsystem doesn't support the operation an error is returned.

#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

* In multi-process mode, when sharing the same key database file, file locking (against processes) is not working properly in some cases.

#### SMW Library - _version 2.0_
##### 1. Configuration file

* Remove `DEFAULT` tag, instead use file content order definition to get the subsystem/operation priority list.
* Support multiple definition sections for the same subsystem.
* Add `PSA_DEFAULT` tag, define the subsystem used to route all PSA APIs operations.
* Remove subsystem loading when library configuration is loaded.

##### 2. OSAL

* Change the library initialization to not be done at the library instantiation.
* Add `smw_osal_set_subsystem_info()` API to define the subsystems information in order to create key storage per application.
* Add `smw_osal_lib_init()` API to be called by the application when library is ready to load the configuration file.
* Implementation of a OSAL's key database to store key information and return a 32 bits key identifier (compatible with PSA APIs). The key database is handled by a binary file created/opened by the application when calling the OSAL's API `smw_osal_open_key_db()`.

##### 3. Subsystems

* Replace the OPTEE TA by a TA library reference to be used by all OPTEE TA to be loaded per application instantiating the SMW library.
* Fix TEE cipher key importation.

##### 4. SMW APIs

* Add `smw_config_subsystem_loaded()` API to get the subsystem status loaded or not.
* Change key identifier to 32 bits.

##### 5. ARM PSA APIs

* All PSA APIs not supported return an error.

#### SMW Tests - _version 2.0_

* Add subsystems information (TA UUID, key storage) in the test definition file.
* Add OPTEE TAs to be loaded per test application.
* Support of single application with multi-threads.
* Support of multiple applications with multi-threads.
* Add PSA Architecture Tests (only supported PSA APIs are tested).
* Fix operation with multiple keys (first key as id and second key as buffer).

#### PKCS#11 Library - _version 2.0_

* Add Data object to configure all subsystems.
* Call the `smw_osal_lib_init()` when token is initialized.

#### PKCS#11 Tests - _version 2.0_

* Add OPTEE TAs to be loaded per test application.
* Add TEE and HSM Data object to configure subsystems (TA UUID, Key storage).

---
### <a id ="rel_1_0"></a></br>**Release 1.0**
---
This is the first release version of the project.
#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. TEE Subsystem

* Cipher key importation is wrong in case a first key as an id and second key as a buffer.

#### SMW Library - _version 1.0_

##### 1. Configuration file

* Definition of all subsystems with supported operations.

##### 2. OSAL

* Basic Linux support.

##### 3. Subsystems

* TEE (all NXP platforms supporting OPTEE OS)
* HSM (NXP i.MX8qxpc0 running SECO firmware)

##### 4. SMW APIs:

* Key Management
* Hash
* HMAC
* Signing/Verifying message
* Random Number
* Cipher
* TLS 1.2 Key agreement

#### SMW Tests - _version 1.0_

* Validation of all SMW's APIs.
* Simple application with single thread.

#### PKCS#11 Library - _version 1.0_

* Token/Session
* Key Management
* Random Number
* Hash
* Signing/Verifying message

#### PKCS#11 Tests - _version 1.0_

* Validation of all implemented PKCS#11 APIs listed above.
