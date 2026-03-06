# List of changes

This file briefly describes the features/changes and fixes in the development process of TPM2 module.
This project delivers 1 components:
* TPM2 Library: The core library itself. It exposes one public API: the SMW-TCTI API.


## List of releases

The releases are listed from the most recent to the first one.

1. [Release 0.1](#rel_0_1)

---
### <a id ="rel_0_1"></a></br>**Release 0.1**
---
#### Known Issues
##### 1. TPM2
The ELE Secure Enclave has the following limitations when used with TPM2:
 - The TPM2_EvictControl allowing to convert a transient object into a
   persistent object is not supported. Hence primary key will be created as
   persistent key.
 - None of the Symmetric and Private part of the Asymmetric key can be exported,
   even in encrypted format.
 - ELE does not support key hierarchy. Therefore, TPM object qualified names
   cannot reflect parent-child relationships and are set equal to the object
   name.
 - Since the Private part of the Asymmetric key cannot be exported, even in
   encrypted format, private key blob returned by TPM2_Create contains a magic
   string followed by the SMW key identifier.
 - TPMT_TK_HASHCHECK ticket is computed with HMAC using the context integrity
   hash algorithm, which is fixed to SHA256 in this implementation. This choice
   aligns with the TPM2 specification requirement that tickets use a consistent
   hash algorithm for integrity verification, and SHA256 provides adequate security.
   The HMAC computation uses hardcoded proof keys specific to each TPM hierarchy
   (Owner, Platform, and Endorsement). These proof keys serve as the HMAC secret
   for generating cryptographic tickets that validate hash operations within
   their respective hierarchy contexts.

#### TPM2 Library
* Create Shared library named libtss2-tcti-smw.so.0.1, bundling tpm2 code as well as tss2-mu and tss2-rc libraries

* Implement the following TPM2 commands:
    - TPM2_CC_Startup, TPM2_CC_Shutdown, TPM2_CC_Hash
    - TPM2_CC_StartAuthSession, TPM2_CC_ContextSave
    - TPM2_CC_HMAC, TPM2_CC_FlushContext
    - TPM2_CC_CreatePrimary, TPM2_CC_GetCapability, TPM2_CC_ContextLoad
    - TPM2_CC_GetRandom, TPM2_CC_ReadPublic
    - TPM2_CC_Create (ECC NIST P-XXX only), TPM2_CC_Load
    - TPM2_CC_Sign, TPM2_CC_VerifySignature
    - TPM2_CC_PCR_Read, TPM2_CC_PCR_Extend, TPM2_CC_PCR_Event, TPM2_CC_PCR_Reset, TPM2_CC_PCR_Allocate
* Set the signature flag indicating input message is hashed for TPM2_Sign and TPM2_VerifySignature commands.
