# Table of Content <!-- omit in toc -->

- [1. Introduction](#1-introduction)
- [2. Secure Subsystems versus Operations](#2-secure-subsystems-versus-operations)
- [3. Creating a simple OPTEE TA](#3-creating-a-simple-optee-ta)
- [4. Running on target](#4-running-on-target)
	- [4.1. Library configuration file](#41-library-configuration-file)
	- [4.2. Linux OS](#42-linux-os)
		- [4.2.1. Use of system configuration file](#421-use-of-system-configuration-file)
		- [4.2.2. Use of OSAL APIs and system environment](#422-use-of-osal-apis-and-system-environment)
- [5. Files Organization](#5-files-organization)


# 1. Introduction
The Security Middleware (SMW) allows any application/library to interface with any
Secure Subsystem supported by the SMW Library and available on the NXP device.
The SMW Library exports a set of APIs to application/library in order to call
Secure Subsystem corresponding operation. The Security Middleware plays the role
of "bridge" or "wrapper" between APIs and Secure Subsystem (we can see it as a
parameters/operations passthrough).
This SMW Library doesn't intent to calculate data (cryptographic operation),
the only operation it's doing is pure software data conversion like DER, PEM, ...

Security Middleware supports the following Secure Subsystem:
*	SECO subsystem (limited to device supporting the SECO, e.g. i.MX8QXP).
*	TEE subsystem (OPTEE OS running in Trustzone secure world).
* ELE subsystem (device supporting EdgeLock Enclave, e.g. i.MX8ULP, i.MX9x).

The package includes:
*	SMW Library exposing SMW's APIs and ARM PSA APIs.
*	PKCS#11 Library on top of the SMW Library.
*	Test suites: SMW test suites, PKCS#11 test suites.

This guide aims to explain how to build and integrate the Security Middleware Library.

# 2. Secure Subsystems versus Operations
Following <a href="#table-secure-subsystem-vs-operations">Secure Subsystems vs
Opertions table</a> summarizes the Operations supported per Secure Subsystem
and supported by the SMW Library.

<table>
<caption id="table-secure-subsystem-vs-operations">Secure Subsystems vs Operations</caption>
<thead>
<tr>
  <th colspan="3" rowspan="2">Operations</th>
  <th colspan="3">Subsystems</th>
</tr>
<tr>
  <th>SECO</th>
  <th>TEE</th>
  <th>ELE</th>
</tr>
</thead>
<tbody>
<tr>
  <td rowspan="13">Key Management</td>
  <td colspan="2">Generate</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td rowspan="3">Import</td>
  <td>Plain text</td>
	<td>❌</td>
	<td>✔️</td>
	<td>❌</td>
</tr>
<tr>
  <td>EdgeLock 2GO blob</td>
	<td>❌</td>
	<td>❌</td>
	<td>✔️</td>
</tr>
<tr>
  <td>EdgeLock Enclave blob</td>
	<td>❌</td>
	<td>❌</td>
	<td>❌</td>
</tr>
<tr>
  <td colspan="2">Export public key</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Update</td>
	<td>❌</td>
	<td>❌</td>
	<td>❌</td>
</tr>
<tr>
  <td colspan="2">Delete</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Key Derivation</td>
	<td>✔️<sup><a href="#t_note_1">1</a>, <a href="#t_note_2">2</a></sup></td>
	<td>✔️<sup><a href="#t_note_3">3</a></sup></td>
	<td>✔️<sup><a href="#t_note_6">6</a></sup></td>
</tr>
<tr>
  <td colspan="2">Get key attributes</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Get key buffers' length</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Get key type name</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Get key security size</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Commit key storage</td>
	<td>✔️<sup><a href="#t_note_4">4</a></td>
	<td>✔️<sup><a href="#t_note_4">4</a></td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">Hash</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">Cipher</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">HMAC</td>
	<td>❌<sup><a href="#t_note_2">2</a></sup></td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">CMAC</td>
	<td>❌</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">Asymmetric Signature</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">Authentication Encryption (AEAD)</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="3">Random Number Generation</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td rowspan="4">Device Manager</td>
	<td colspan="2">Device Attestation</td>
	<td>❌</td>
	<td>❌</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Get Device UUID</td>
	<td>❌</td>
	<td>❌</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Device Lifecycle</td>
	<td>❌</td>
	<td>❌</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Storage Reprovisioning</td>
	<td>❌</td>
	<td>❌</td>
	<td>✔️</td>
</tr>
<tr>
  <td rowspan="4">Data Storage</td>
	<td colspan="2">Get information</td>
	<td>✔️<sup><a href="#t_note_5">5</a></sup></td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Store</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Retrieve</td>
	<td>✔️</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
<tr>
  <td colspan="2">Delete</td>
	<td>❌</td>
	<td>✔️</td>
	<td>✔️</td>
</tr>
</tbody>
</table>

<p>
<a name="t_note_1"><sup>1</sup></a> Require specific SECO Firmware.<br>
<a name="t_note_2"><sup>2</sup></a> Supports TLS 1.2. Build option ENABLE_TLS12 must be set ON.<br>
<a name="t_note_3"><sup>3</sup></a> Supports HKDF.<br>
<a name="t_note_4"><sup>4</sup></a> Do nothing, returns always success.<br>
<a name="t_note_5"><sup>5</sup></a> Retrieve only information from SMW object database.<br>
<a name="t_note_6"><sup>6</sup></a> Supports HKDF (Full/Extract/Expand step).<br>
</p>

# 3. Creating a simple OPTEE TA
The Security Middleware provides <u>a reference code of a static OPTEE TA Library</u>
that could be used to build a OPTEE Trusted Application. The OPTEE TA Library is not
guaranty to be stable or bug free (this library is used in the context of the
SMW TEE subsystem validation).

To create a simple OPTEE TA using the provided static TA library, the TA project
present in the SMW test suite folder `tests/tee/ta/` can be re-used.

<pre>
<span style="color:orange">ta</span>
|-- CMakeLists.txt                  cmake project file executing the `Makefile`
|-- Makefile                        TA makefile including TA Development Kit
|-- inc
|   `-- user_ta_header_defines.h    TA definitions (TA_UUID, TA_FLAGS, TA_DATA/STACK_SIZE, ...)
|-- sub.mk                          srcs-y += ta_entry.c
`-- ta_entry.c                      TA entry points calling the static TA Library
</pre>

The `ta_entry.c` file implements only the TA mandatory functions as explain in the
[OPTEE Trusted Application](https://optee.readthedocs.io/en/latest/building/trusted_applications.html) documentation. Then those functions calls the built
`libsmw_ta.a` static library operation responding to the SMW Library requests.

The `libsmw_ta.a` is built in the library folder of the project build directory.
The library header `libsmw_ta.h` is present in the include folder of the project
build directory.

# 4. Running on target
The Security Middleware library requires some configurations defining:
  - The SMW object database storing necessary information to manage object
    (key and data) present in the different subsystem.
  - The operations per subsystems and the priority between each
    operations/subsystems definition. It's the library configuration.
  - For each subsystem available on the target and defined in the library
    configuration, the subsystem specific configuration:
      - For the TEE subsystem, the Trusted Application to used.
      - For the ELE subsystem, the ELE Non-Volatile Secure Storage identifier
        and nonce.
      - For the SECO subsystem, the SECO Non-Volatile Secure Storage identifier,
        nonce and maximum value of the replay attack counter.

## 4.1. Library configuration file
The library configuration file used to define the subsystems to enable and
their operations (with modes, keys, ...).

The supported operations by a subsystem are listed in the
<a href="#table-secure-subsystem-vs-operations">Secure Subsystems vs
Operation table</a>. More details on the subsystem (devices) capabilities are
available in the [User API documentation](../API/SecurityMiddleware_API.pdf)
in the chapter **Subsystem Capabilities**.

The writing rules and content of the library configuration are available in the
[User API documentation](../API/SecurityMiddleware_API.pdf) in the chapter
**How to write a configuration file**.

A configuration file example is available [here](../../osal/linux/config/smw_config.txt).

## 4.2. Linux OS
The Security Middleware proposes a Linux OSAL reference module allowing to
use a system configuration file (smw.conf) and exposing OSAL APIs plus
system environment to configure the database and the subsystem(s) at runtime.

> :memo: **Note:**
> The linux OSAL reference module tries to read the system configuration file
> (smw.conf) during when the function `smw_osal_lib_init(void)` is called.
> The OSAL APIs exposes for the same or system environment variable are
> overwriting the system configuration file if both options are used.

### 4.2.1. Use of system configuration file
The `smw.conf` file must be present in the system folder `/etc/opt/smw/`.
The file is divided into sections:

```
[setup]
# SMW configuration file describing the subsystem(s) operations.

[TEE]
# OPTEE TA UUID to be loaded if subsystem used.

[SECO]
# SECO subsystem NVM Secure Storage configuration if subsystem used.

[ELE]
# ELE subsystem NVM Secure Storage configuration if subsystem used.
```

The file present in the source tree [osal/linux/config/smw.conf](../../osal/linux/config/smw.conf)
gives more details information how to configure the library and the subsystem.

### 4.2.2. Use of OSAL APIs and system environment
The [User API documentation - OSAL chapter](../API/SecurityMiddleware_API.pdf)
lists the OSAL APIs exposed to configure the database and the subsystem(s) used.

The system environment variable `SMW_CONFIG_FILE` is used to load the library
configuration (operations per subsystem).
```sh
$ export SMW_CONFIG_FILE=[/path/to/configuration/file]
```

# 5. Files Organization
Below is the organization of the project sources.

<pre>
`
|-- CHANGELOG.md                    List of changes per version
|-- CMakeLists.txt                  Main CMake configuration
|-- <span style="color:orange">Documentations</span>                  Documents
|   |-- <span style="color:orange">API</span>                         User APIs documentation sources
|   |   |-- ...
|   `-- <span style="color:orange">user_guide</span>                  User guide and build instructions
|       `-- ...
|-- LICENSE                         License/Copyright file
|-- README.md
|-- SW-Content-Register.txt
|-- <span style="color:orange">cmake</span>                           Additional CMake building scripts
|-- <span style="color:orange">core</span>                            Core library
|   |-- CMakeLists.txt              Core library CMake configuration
|   |-- <span style="color:orange">config</span>                      Configuration Module - parser
|   |   |-- ...
|   |-- <span style="color:orange">crypto</span>                      Cryptography Module - SMW APIs
|   |   |-- ...
|   |-- <span style="color:orange">devmgr</span>                      Device Management Module - SMW APIs
|   |   |-- ...
|   |-- <span style="color:orange">inc</span>                         Core local includes
|   |   |-- ...
|   |-- <span style="color:orange">init</span>                        Core library initialization - SMW APIs
|   |   |-- ...
|   |-- <span style="color:orange">keymgr</span>                      Key Manager Module - SMW APIs
|   |   |-- ...
|   |-- <span style="color:orange">psa</span>                         ARM PSA APIs wrapper
|   |   |-- ...
|   |-- <span style="color:orange">subsystems</span>                  Secure Subsystems Layers
|   |   |-- <span style="color:orange">ele</span>                     ELE Subsystem
|   |   |   |-- ...
|   |   |-- <span style="color:orange">seco</span>                    SECO Subsystem
|   |   |   |-- ...
|   |   `-- <span style="color:orange">tee</span>                     TEE Subsystem
|   |       |-- ...
|   |       |-- <span style="color:orange">common</span>              Common files Normal World/Secure World (TA)
|   |       |   `-- ...
|   |       `-- <span style="color:orange">lib_ta</span>              Example of static TA Library (use for test)
|   |           |-- ...
|   |           `-- <span style="color:orange">include</span>         Static TA interface header
|   `-- <span style="color:orange">utils</span>                       Core utilities
|       `-- ...
|-- <span style="color:orange">inc</span>                             Overall project global includes
|   `-- ...
|-- <span style="color:orange">osal</span>                            OS'es Abstraction Layers
|   |-- CMakeLists.txt              OSAL global CMake configuration
|   `-- <span style="color:orange">linux</span>                       Linux OS Abstraction Layer
|       `-- ...
|-- <span style="color:orange">pkcs11</span>                          PKCS#11 library
|   |-- CMakeLists.txt              PKCS#11 library CMake configuration
|   |-- <span style="color:orange">import</span>                      OASIS PKCS#11 standard headers
|   |   `-- ...
|   |-- <span style="color:orange">src</span>                         PKCS#11 library sources - APIs
|   |   |-- <span style="color:orange">ifsmw</span>                   SMW's Library interface
|   |   |   `-- ...
|   |   |-- <span style="color:orange">include</span>                 PKCS#11 Common include files
|   |   |   `-- ...
|   |   |-- <span style="color:orange">objects</span>                 PKCS#11 Objects management sources
|   |   |   `-- ...
|   |   |-- <span style="color:orange">utils</span>                   PKCS#11 Utilities
|   |   |   `-- ...
|   |   `-- ...
|   `-- <span style="color:orange">tests</span>                       PKCS#11 Test suite
|-- <span style="color:orange">public</span>                          SMW's interface headers (refer to APIs documentation)
|   |-- <span style="color:orange">psa</span>                         ARM PSA APIs interface headers (refer to APIs documentation)
|   |   |-- crypto.h
|   |   |-- crypto_sizes.h
|   |   |-- crypto_struct.h
|   |   |-- crypto_types.h
|   |   |-- crypto_values.h
|   |   |-- error.h
|   |   |-- initial_attestation.h
|   |   |-- internal_trusted_storage.h
|   |   |-- protected_storage.h
|   |   `-- storage_common.h
|   |-- <span style="color:orange">smw</span>
|   |   |-- attr.h
|   |   |-- names.h
|   |   `-- <span style="color:orange">crypto</span>                 SMW's cryptographic interface headers (refer to APIs documentation)
|   |       `-- aead.h
|   |-- smw_config.h
|   |-- smw_crypto.h
|   |-- smw_device.h
|   |-- smw_info.h
|   |-- smw_keymgr.h
|   |-- smw_osal.h
|   |-- smw_status.h
|   `-- smw_storage.h
|-- <span style="color:orange">scripts</span>                         Project building/environment scripts
`-- <span style="color:orange">tests</span>                           SMW's Test suite
</pre>
