# List of changes

This file briefly describes the features/changes and fixes in the development process of the Zephyr SMW library.

## List of releases

The releases are listed from the most recent to the first one.

1. [Release 1.0](#rel_1.0)

---
### <a id ="rel_1_0"></a></br>**Release 1.0**
---

This release is based on SMW Release 5.5

#### Known Issues

* None

#### SMW Library
##### 1. Subsystems

* Add ELE Subsystem.
* Add RNG operation support.
* Fix coverity 2026.3.0 findings.
* Add Key Management support.
* Add HMAC/CMAC support.
* Poll registers with a delay.

##### 2. OSAL

* Add Zephyr abstraction layer for SMW core library.
* Implement cache maintenance API.
* Implement file access API.
* Implement shared memory API.
* Implement get mu base address API.
* Fix coverity 2026.3.0 findings.
* Keep object id defined by user.
* Implement wait API.
