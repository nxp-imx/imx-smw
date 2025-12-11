# List of changes

This file briefly describes the features/changes and fixes in the development process of TPM2 module.
This project delivers 1 components:
* TPM2 Library: The core library itself. It exposes one public API: the SMW-TCTI API.

---
### </br>**01-06-2026**
---
#### Known Issues
##### 1. TPM2


#### TPM2 Library

* Implement TPM2 skeleton with basics infrastructures functions.
* The new component has been integrated into the CMake build system and the associated scripts.
* Create Shared library named libtss2-tcti-smw.so.x.y.z, bundling tpm2 code as well as tss2-mu and tss2-rc libraries

