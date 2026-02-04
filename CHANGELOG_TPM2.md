# List of changes

This file briefly describes the features/changes and fixes in the development process of TPM2 module.
This project delivers 1 components:
* TPM2 Library: The core library itself. It exposes one public API: the SMW-TCTI API.


---
### </br>**xx-xx-2026**
---
#### Known Issues
##### 1. TPM2
The ELE Secure Enclave has the following limitations when used with TPM2:
 - ELE does not support key hierarchy. Therefore, TPM object qualified names
   cannot reflect parent-child relationships and are set equal to the object
   name.
 - Since the Private part of the Asymmetric key cannot be exported, even in
   encrypted format, private key blob returned by TPM2_Create contains a magic
   string followed by the SMW key identifier.

#### TPM2 Library
* Implement the following TPM2 commands:
    - TPM2_CC_GetRandom, TPM2_CC_ReadPublic
* Improvement of the following TPM2 commands:
    - TPM2_CC_GetCapability
    - TPM2_CC_Create (ECC NIST P-256 only), TPM2_CC_Load

---
### </br>**01-28-2026**
---
#### Known Issues
##### 1. TPM2
The ELE Secure Enclave has the following limitations when used with TPM2:
 - The TPM2_EvictControl allowing to convert a transient object into a
   persistent object is not supported. Hence primary key will be created as
   persistent key.
 - None of the Symmetric and Private part of the Asymmetric key can be exported,
   even in encrypted format.

The HMAC command is mocked with the use of session key for now, waiting for
object creation feature to be implemented.

#### TPM2 Library

* Implement the following TPM2 commands:
    - TPM2_CC_Startup, TPM2_CC_Shutdown, TPM2_CC_Hash
    - TPM2_CC_StartAuthSession, TPM2_CC_ContextSave
    - TPM2_CC_HMAC, TPM2_CC_FlushContext
    - TPM2_CC_CreatePrimary, TPM2_CC_GetCapability, TPM2_CC_ContextLoad

---
### </br>**01-06-2026**
---
#### Known Issues
##### 1. TPM2


#### TPM2 Library

* Implement TPM2 skeleton with basics infrastructures functions.
* The new component has been integrated into the CMake build system and the associated scripts.
* Create Shared library named libtss2-tcti-smw.so.x.y.z, bundling tpm2 code as well as tss2-mu and tss2-rc libraries

