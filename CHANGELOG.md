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

1. [Release 2.3](#rel_2_3)
2. [Release 2.2](#rel_2_2)
3. [Release 2.1](#rel_2_1)
4. [Release 2.0](#rel_2_0)
5. [Release 1.0](#rel_1_0)

### <a id ="rel_2_3"></a></br>**Release 2.3**
---

#### SMW Library - _version 2.3_
##### 1. ARM PSA APIs

* Fix memory leak caused by key generation and key import
* Fix export of RSA, ECC and symmetric keys.
* Fix import of RSA keys and ECC keys.
* Implement Sign and Verify operations

#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.


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

#### SMW Library - _version 2.2_
##### 1. Subsystem
* Add EdgeLock Enclave (ELE) subsystem.

##### 1. ARM PSA APIs

* Implement Key manager (Generate, Import, Export, Delete)

### <a id ="rel_2_1"></a></br>**Release 2.1**
---

#### Known Issues
##### 1. HSM Subsystem

* When 2 or more applications load the SMW Library and configure the HSM subsystem, only one application is able to get the HSM configured properly. The other applications get the `SMW_STATUS_SUBSYSTEM_LOAD_FAILURE` status error code when trying to configure/access the HSM subsystem. </br>
The failure is due to the storage manager which is already loaded and a new instance (new application) of the SMW library is trying to load it.

#### SMW Library - _version 2.1_
##### 1. ARM PSA APIs

* Upgrade ARM PSA Crypto API to version 1.1.0.
* Implement Hash one go

##### 2. OSAL

* Change linux OSAL key database primitives to use `fcntl()` function in order to lock file access. This function guaranties file locking in case of multi-process and even with NFS file system.

##### 3. Subsystem

* Add HMAC Key generation and HMAC generation for the HSM subsystem.
* Add handling of key policy

##### 4. SMW APIs

* Remove fields `key_attributes_list` and `key_attributes_list_length` from `struct smw_export_key_args`.

##### 5. Key manager

* Add support of key policy in key attributes list.

#### SMW Tests - _version 2.1_

* Add key policy tag in the test definition.

#### PKCS#11 Library - _version 2.1_

* Set the key policy in the key template when generating/importing keys.

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

* Change the library initialization to not be done at the library instanciation.
* Add `smw_osal_set_subsystem_info()` API to define the subsystems information in order to create key storage per application.
* Add `smw_osal_lib_init()` API to be called by the application when library is ready to load the configuration file.
* Implementation of a OSAL's key database to store key information and return a 32 bits key identifier (compatible with PSA APIs). The key database is handled by a binary file created/opened by the application when calling the OSAL's API `smw_osal_open_key_db()`.

##### 3. Subsystems

* Replace the OPTEE TA by a TA library reference to be used by all OPTEE TA to be loaded per application instanciating the SMW library.
* Fix TEE cipher key importation.

##### 4. SMW APIs

* Add `smw_config_subsystem_loaded()` API to get the subsystem status loaded or not.
* Change key identifier to 32 bits

##### 5. ARM PSA APIs

* All PSA APIs not supported return an error.


#### SMW Tests - _version 2.0_

* Add subsystems information (TA UUID, key storage) in the test definition file.
* Add OPTEE TAs to be loaded per test application.
* Support of single application with multi-threads.
* Support of multiple applications with multi-threads.
* Add PSA Architecture Tests (only supported PSA APIs are tested).
* Fix operation with mutliple keys (first key as id and second key as buffer)

#### PKCS#11 Library - _version 2.0_

* Add Data object to configure all subsystems.
* Call the `smw_osal_lib_init()` when token is initialized.

#### PKCS#11 Tests - _version 2.0_

* Add OPTEE TAs to be loaded per test application.
* Add TEE and HSM Data object to configure subsystems (TA UUID, Key storage)

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

* Definition of all subsystems with supported operations

##### 2. OSAL

* Basic Linux support

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
* Validation of all SMW's APIs
* Simple application with single thread

#### PKCS#11 Library - _version 1.0_
* Token/Session
* Key Management
* Random Number
* Hash
* Signing/Verifying message

#### PKCS#11 Tests - _version 1.0_
* Validation of all implemented PKCS#11 APIs listed above
