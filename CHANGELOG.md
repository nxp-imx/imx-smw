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

1. [Release 5.1.1](#rel_5_1_1)
2. [Release 5.1](#rel_5_1)
3. [Release 5.0.1](#rel_5_0)
4. [Release 4.2](#rel_4_2)
5. [Release 4.1](#rel_4_1)
6. [Release 4.0](#rel_4_0)

---
### <a id ="rel_5_1_1"></a></br>**Release 5.1.1**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ELE Subsystem

* ECC Signature verification with imported public key having x or y coordinate
  MSB=0 is not supported.

##### 3. TEE Subsystem

* ECC Signature verification with imported public key having x or y coordinate
  MSB=0 is not supported.

##### 4. PKCS#11

* As some subsystems are not handling key usage and permitted algorithm, the
  find operation is not able to find all keys whose template defines key usage
  and permitted algorithm.

#### SMW Library
##### 1. SMW APIs

##### 2. Subsystems

##### 3. ARM PSA APIs

##### 4. OSAL

#### SMW Tests

#### PKCS#11 Library

#### PKCS#11 Tests

---
### <a id ="rel_5_1"></a></br>**Release 5.1**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ELE Subsystem

* ECC Signature verification with imported public key having x or y coordinate
  MSB=0 is not supported.

##### 3. TEE Subsystem

* ECC Signature verification with imported public key having x or y coordinate
  MSB=0 is not supported.

##### 4. PKCS#11

* As some subsystems are not handling key usage and permitted algorithm, the
  find operation is not able to find all keys whose template defines key usage
  and permitted algorithm.

#### SMW Library
##### 1. SMW APIs

* Currently, we do not read the supported key types for signing and asymmetric
  encryption  security operations from the configuration file. Therefore, remove
  key type validation during key generation or import, when the key is intended
  for signing or asymmetric encryption purposes.
* Enable reading of EDDSA signature types (`PURE_EDDSA`, `EDDSA_PH` and `EDDSA_CTX`) from config file.
* Rename internal object `id` to `s_id` and `id` to `u_id` to
  clearly identify the id value meaning.
* Add support for the EL2GO OEM Secret Shared key. Key must not be in the database.
* Enhance smw_find_object_db() API to query subsystem if the object
  identifier is not present in the database.
* Add support for the SHAKE256 digest algorithm.
* Store private asymmetric key as key pair object in the database.
* Add support for the x448 key.
* In case EL2GO data, smw_key_delete() returns immediately with error SMW_STATUS_UNKNOWN_ID.
* Fix the internal key derivation conversion missing the key attributes.
* Fix the OEM Master key synchronization flag when persistent key.
* Update APIs documentation to include details about querying the required output buffer length.
* Update the smw_hash_final() API to return SMW_STATUS_OK when the output buffer is NULL and the subsystem
  returns SMW_STATUS_OUTPUT_TOO_SHORT to ensure consistent behavior across all subsystems.

##### 2. Subsystems

* TEE: Fix memory leak in case of one-short AEAD, one-shot cipher and multi-part hash operations.
* TEE: Fix the get attribute's permitted algorithm overwriting the database
  value when key is created.
* TEE: Rework TA to set the x or y MSB to 0 in case size is odd.
* TEE: Add support for the SHAKE256 digest algorithm.
* ELE: Add support for the SHAKE256 digest algorithm.
* ELE: Update TLS1.2 KDF support
* ELE: Fix endianness handling for signature and key buffers on i.MX91 and i.MX93 platforms
  to ensure consistent little-endian formatting across all platforms and key types.
* ELE: Integrate new AEAD API.
* ELE: Add support for Ed448 key management and signature operations.
* ELE: Enable i.MX95 HMAC.
* ELE: Add support for x448 key management and derivation operations.
* ELE: Edwards curve (Pre-hashed signature not supported).
* ELE: Replace SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY by SMW_STATUS_ALLOC_FAILURE
  when allocation done in the library.
* SECO: Replace SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY by SMW_STATUS_ALLOC_FAILURE
  when allocation done in the library.

##### 3. ARM PSA APIs

* Fix key generation using ELE subsystem with permitted algorithm set to an asymmetric encryption algorithm.
* Add support of the `PSA_KEY_TYPE_DG_PROVISIONING_KEY` Vendor algorithm used
  to provision the EL2GO OEM Secret Shared key (EL2GO Production flow).
* Add support of the `PSA_ALG_VENDOR_TLS13` vendor algorithm for TLS1.3 and implement
  the related PSA key derivation functions.

##### 4. OSAL

* Define the supported sign type values in the config files.
* Add a specific OSAL object structure to handle subsystem's object identifier.
* Enable TLS Key derivation on i.MX95B0 in the ele_imx95_config.txt file.
* Update the i.MX95 configuration file to enable support for AEAD one-shot operations.
* Call library destructor on SIGINT signal.

#### SMW Tests

* Enable ELE RSA tests on the i.MX95 B0 platform.
* Fix test missing the setting of the key persistency.
* Add test validating the smw_find_object_db().
* Add test validating SHAKE256 digest algorithm.
* Enable TLS key derivation tests on i.MX95.
* Add cross-subsystem signature verification tests between TEE and ELE subsystems.
* Enable ELE AEAD tests on the i.MX95 B0 platform.
* Add ELE test cases to validate AEAD operations using a plaintext key buffer.
* Add test to validate Ed448 key management.
* Add tests to verify signature generation and verification using both Ed448 key
  ID and buffers for ELE subsystem.
* Enable i.MX95 HMAC.
* Add PSA tests validating key derivation using the `PSA_ALG_VENDOR_TLS13` algorithm.
* Add tests validating x448 key.
* Add SMW tests to verify "get output buffer length" feature.
* Enable i.MX95 Edwards curve (Pre-hashed signature not supported).

#### PKCS#11 Library

* Clean up object retrieve function removing unnecessary call to the get
  key attributes.
* Add TLS 1.2 Key exchange and MAC support.
* Encode and decode data id (CKA_OBJECT_ID) in OID format.
* TLS: IV and Tag properly returned in the output buffer.
* Fix decoding data id (CKA_OBJECT_ID).
* Enable multiple cipher modes with CKA_ALLOWED_MECHANISMS attributes.

#### PKCS#11 Tests

* Test TLS 1.2 Key exchange tests.
* Test TLS 1.2 Hash MAC operation.
* Test data CKA_OBJECT_ID using OID format.
* Test encrypt/decrypt operation with an AES key supporting multiple mechanisms.

---
### <a id ="rel_5_0"></a></br>**Release 5.0.1**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. TEE Subsystem

* In case of one-shot AEAD, one-shot cipher or multi-part hash, the operation handle is not freed once the operation is finished.
If the user repeat these kinds of operations several times, the TEE subsystem will run out of memory.

##### 3. ELE Subsystem

* On i.MX91 and i.MX93 platforms, EdDSA signatures are generated in big-endian format.
* For EdDSA signature verification on i.MX91 and i.MX93 platforms, the signature and public key buffers must be
  provided in big-endian format.
* On i.MX91 and i.MX93 platforms, the exported key buffer via the key generation API (when a public key buffer is
  provided) or the key export API is encoded in big-endian format for ECC Edwards and X25519 key pairs.

##### 3. PKCS#11

* As some subsystems are not handling key usage and permitted algorithm, the
  find operation is not able to find all keys whose template defines key usage
  and permitted algorithm.

##### 3. ARM PSA APIs

* RSA key cannot be generated using ELE subsystem if permitted algorithm is an asymmetric encryption algorithm.

#### SMW Library
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
* Add asymmetric encryption and decryption APIs.
* Update public HKDF arguments structures `smw_hkdf_args` and `smw_kdf_hkdf_args`.
* Add support for EdgeLock Enclave key import.
* Add algorithm operation class key agreement.
* Add `smw_find_object_db_args` structure arguments for the object find operations
* Change the structure `smw_data_descriptor` to integrate the data's attribute
  structure instead of a pointer.
* Change the structure `smw_object_descriptor` to remove duplicated key or data
  attributes.
* Fix the EdgeLock 2GO storage identifier macros.
* Fix the data update database to not change the storage id.
* Remove the deletion of the EL2GO data from the smw_delete_key(), return
`SMW_STATUS_UNKNOWN_ID` if object identifier is not a key.
* Data operations return `SMW_STATUS_UNKNOWN_ID` if object identifier is not a
  data type.
* API get_key_attributes, add compatibility to query all subsystems when key
  not present in the database.
* Clean up internal key operations structures as key attributes are part of
the key descriptor.
* Breaking compatibility for the smw_delete_key() API by clearing version
  to 0.
* [PATCH] Fix sign/verify with pre-hashed RSA PKCS.
* [PATCH] Define a default object user_id (PKCS#11 key CKA_ID or data
  CKA_OBJECT_ID) value if not set.
* [PATCH] Free all object descriptors buffer allocated when getting database
  information.

##### 2. Subsystems

* ELE: Remove HKDF support. Secure Enclave doesn't support it anymore.
* ELE: Remove TLS 1.2 plain text versus key ids output buffer flag.
* ELE: Handle EDDSA additional parameters and signature message hashed flag.
* ELE: Add support for TLS1.3 KDF.
* ELE: Add any EDDSA variant for key creation permitted algorithm.
* ELE: Add support for signature generation using plaintext private key buffer.
* ELE: Add key import using EdgeLock Enclave blob.
* ELE: Add support for hash mac generation using plaintext private key buffer.
* ELE: Add support for key and data query.
* ELE: Key generation update key's permitted algorithm and usage independently.
* TEE: Fix the ed25519 key security size to be 255 bits.
* TEE: Improve object storage management.
* TEE: Handle EDDSA additional parameters and signature message hashed flag.
* TEE: Add support for asymmetric encryption and decryption for TEE subsystem.
* TEE: Fix random failure when converting TA UUID string to object.
* TEE: Add support for key and data query.
* TEE: Key creation update key's permitted algorithm and usage independently.
* SECO: Fix coverity finding.
* SECO: Handle signature message hashed flag.
* SECO: Add support for key and data query but as not supported returns
  `SMW_STATUS_UNKNOWN_ID`
* SECO: Key creation update key's permitted algorithm and usage independently.
  This subsystem handles neither permitted algorithm nor usage. Require SW
  implementation to support. For now, don't erase user permitted algorithm and
  set all usages to allow finding keys per usages and algorithm even if not
  accurate.
* Apply Base64 to hex conversion consistently for key buffers across all subsystems.
* SECO: [PATCH] Free all object descriptors buffer allocated when getting
  database information.

##### 3. ARM PSA APIs


##### 4. OSAL

* Add a dedicated configuration file for i.MX943.
* Remove HKDF key derivation in all ELE based configurations.
* Add support of the EDDSA signature for TEE subsystem in all configurations.
* Add support of key permitted algo and key usage in Object database.
* Add a database version information and verification.
* Remove AEAD support for ELE subsystem in i.MX95 and i.MX943 configuration files.
* Add support for asymmetric encryption and decryption for TEE subsystem in all
  configurations.
* Update database SQL search request to use bits mask for key's permitted
  algorithm and usages.

#### SMW Tests

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
* Add tests to validate asymmetric encryption and decryption APIs.
* Add key import using EdgeLock Enclave blob tests.
* Add subtests to verify cryptographic operations with Base64 encoded key buffer.
* Add PSA tests validating data deletion through key deletion and the opposite.
* Add SMW tests validating get_key_attrinbutes() query when key not present
  in database.
* [PATCH] Add tests for sign/verify with pre-hashed RSA PKCS.
* [PATCH] Free all object descriptors buffer allocated when getting database
  information.

#### PKCS#11 Library

* Add support for ed25519 key generation and signature
* Add TLS 1.3 Key exchange support
* TLS AES GCM mulpti-part operation transforms to one shot operation.
* Add CKF_LOGIN_REQUIRED flag to token flags.
* Sign/Verify: Add support of plaintext key buffer for session key objects.
* Allow using a session object in all application sessions.
* [PATCH] Fix memory leak in case of RSA private key import.
* [PATCH] Fix sign/verify with RSA PKCS mechanisms.

#### PKCS#11 Tests

* Add DES key generation performance test.
* Add test to validate ed25519 key generation and signature
* Do not run DES key generation performance test in debug build.
* Test TLS 1.3 Key exchange tests.
* Test TLS 1.3 AES GCM multi-part operation.
* Test TLS 1.3 Hash MAC operation.
* Fix performance test result calculation on 32bits platforms.
* Retry performance test case if it failed.
* Add SHA256 and SHA384 HMAC SignMessage/VerifyMessage test with a plaintext key.
* Add RSA SHA512 Sign/Verify test with a plaintext key.
* Test using a session object from another session.
* Fix hostname for i.MX943 and i.MX95.
* [PATCH] Check CKA_ID default value if none is given by the user.
* [PATCH] Free all object descriptors buffer allocated when getting database
  information.

---
### <a id ="rel_4_2"></a></br>**Release 4.2**
---
#### Known Issues
##### 1. SECO Subsystem

* When 2 or more applications load the SMW Library and configure the SECO subsystem, only one application is able to get the SECO configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the SECO subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

##### 2. ELE Subsystem

* On i.MX91 and i.MX93 platforms, EdDSA signatures are generated in big-endian format.
* For EdDSA signature verification on i.MX91 and i.MX93 platforms, the signature and public key buffers must be
  provided in big-endian format.
* On i.MX91 and i.MX93 platforms, the exported key buffer via the key generation API (when a public key buffer is
  provided) or the key export API is encoded in big-endian format for ECC Edwards key pair.

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
* Add tests finding keys generated without using PKCS#11 generate operation.
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
