# Table of Content <!-- omit in toc -->

- [1. Introduction](#1-introduction)
- [2. Toolchains](#2-toolchains)
  - [2.1. Install in a default path](#21-install-in-a-default-path)
  - [2.2. Install in other path](#22-install-in-other-path)
  - [2.3. Additional toolchain options](#23-additional-toolchain-options)
- [3. External Dependencies](#3-external-dependencies)
    - [3.1. SECO subsystem](#31-seco-subsystem)
      - [3.1.1. SECO Libraries](#311-seco-libraries)
      - [3.1.2. NVM Daemon](#312-nvm-daemon)
    - [3.2. TEE subsystem](#32-tee-subsystem)
      - [3.2.1. OPTEE Client Library](#321-optee-client-library)
      - [3.2.2. OPTEE TA Development Kit](#322-optee-ta-development-kit)
    - [3.3. ELE subsystem](#33-ele-subsystem)
      - [3.3.1. ELE Library](#331-ele-library)
      - [3.3.2. NVM Daemon](#332-nvm-daemon)
    - [3.4. JSON-C Library](#34-json-c-library)
    - [3.5 ARM PSA Test Suite](#35-arm-psa-test-suite)
- [4. Project configuration and compilation](#4-project-configuration-and-compilation)
  - [4.1. Build environment options](#41-build-environment-options)
  - [4.2. Enabling Secure Subsystems](#42-enabling-secure-subsystems)
  - [4.3. Libraries options](#43-libraries-options)
    - [4.3.1. SMW Library options](#431-smw-library-options)
    - [4.3.2. PKCS#11 Library options](#432-pkcs11-library-options)
  - [4.4. Enabling test suites](#44-enabling-test-suites)
- [5. SMW/PKCS#11 Libraries installation](#5-smwpkcs11-libraries-installation)
  - [5.1. Install command](#51-install-command)
  - [5.2. Install result](#52-install-result)
- [6. Tests](#6-tests)
  - [6.1. Compilation](#61-compilation)
  - [6.2. Installation](#62-installation)
    - [6.2.1. Install command](#621-install-command)
    - [6.2.2. Install result](#622-install-result)
  - [6.3. Execution](#63-execution)
- [7. Tips](#7-tips)
  - [7.1. Reference platforms configuration script](#71-reference-platforms-configuration-script)
  - [7.2. Multi-function build script](#72-multi-function-build-script)
  - [7.3. Including SMW in other cmake project](#73-including-smw-in-other-cmake-project)


# 1. Introduction
This guide aims to explain how to build and integrate the Security Middleware Library.

The Security Middleware project is using CMake and make tools to compile. A GNU
ARM Toolchain 32 or 64 bits function of the targeted device is also required to compile.
This section is describing how to prepare the project's dependencies like,
toolchains, libraries, headers, ...

# 2. Toolchains

Security Middleware is meant to run on ARM architecture processors that own
subsystems hardware. Consequently the right toolchain must be used to cross-compile
this project.

Project provide script to download and install cross-compiler GNU ARM 32 or 64
bits toolchain aarch\[*XX*\]-none-linux-gnu 10.3-2021.07 (\[*XX*\] can be 32 or
64 according to the target platform (32 or 64 bits)).
The command must be executed from sources installation folder.

## 2.1. Install in a default path
To install the toolchain in the source `./toolchains` directory, execute the
following cmake script command:

```sh
$ cmake -DFORCE_TOOLCHAIN_INSTALL=True -P ./scripts/aarch[XX]_toolchain.cmake
```

This configuration will download the toolchain from the developer arm website
into the root source `./toolchains` folder. The toolchain will be uploaded and
extracted (this will take several minutes).

## 2.2. Install in other path
To install the toolchain in the a specific directory, execute the following
cmake script command:

```sh
$ cmake -DFORCE_TOOLCHAIN_INSTALL=True -DTOOLCHAIN_PATH=[install path] -P ./scripts/aarch[XX]_toolchain.cmake
```

This configuration will download the toolchain from the developer arm website
into the given path specified with the TOOLCHAIN_PATH option. The toolchain
will be uploaded and extracted (this will take several minutes).

## 2.3. Additional toolchain options
The following <a href="#table-additional-toolchain-options">Additional toolchain
options table</a> define other options that can be used when executing one of the
cmake script or command described in this documentation.

<table>
<caption id="table-additional-toolchain-options">Additional toolchain options</caption>
<thead>
<tr>
  <th>Option</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>TOOLCHAIN_NAME</td>
	<td>Specified a GNU ARM toolchain name (e.g. aarch64-linux-gnu)</td>
</tr>
<tr>
  <td>TOOLCHAIN_VERSION</td>
	<td>Specified a specific GNU ARM toolchain version (other than "10.3-2021.07").
	This option combined with the TOOLCHAIN_NAME is used to defined the toolchain
	complete name `gcc-arm-[TOOLCHAIN_VERSION]-x86_64-[TOOLCHAIN_NAME]`</td>
</tr>
</tbody>
</table>

# 3. External Dependencies
To enable SMW supported subsystem or module (like tests) additional libraries
and their header files are required. The following <a href="#table-external-dependencies-build-options">
External Dependencies build options table</a>
lists the requirements for each subsystem and the build option(s) to configure
in order to enable the subsystem in SMW Library.

Depending of the Secure Subsystems or module to support, the external dependencies
listed be built before configuring the SMW Library. Instructions are provided in
this section to build external dependencies using provided cmake scripts.

<table>
<caption id="table-external-dependencies-build-options">External Dependencies build options</caption>
<thead>
<tr>
  <th>Module</th>
  <th>External library/header</th>
	<th>Comments</th>
</tr>
</thead>
<tbody>
<tr>
  <td rowspan="2">SECO subsystem</td>
  <td>SECO Library</td>
	<td>Shared library lib_hsm.so and hsm_api.h header</td>
</tr>
<tr>
 	<td>SECO NVM Manager</td>
	<td>Daemon service to be started before using SMW Library</td>
</tr>
<tr>
  <td rowspan="2">TEE subsystem</td>
	<td>OPTEE Client Library</td>
	<td>Shared library libteec.so and tee_client_api.h header</td>
</tr>
<tr>
  <td>OPTEE OS TA Development kit</td>
	<td>Makefile module ta_dev_kit.mk and tee_internal_api.h, tee_api_defines.h headers</td>
</tr>
<tr>
  <td rowspan="2">ELE subsystem</td>
	<td>ELE Library</td>
	<td>Shared library libele_hsm.so and hsm_api.h header</td>
</tr>
<tr>
  <td>ELE NVM Manager</td>
	<td>Daemon service to be started before using SMW Library</td>
</tr>
<tr>
  <td>SMW test suite</td>
	<td>JSON-C Library</td>
	<td>Shared library libjson-c.so and json.h/json_config.h header</td>
</tr>
</tbody>
</table>

### 3.1. SECO subsystem

#### 3.1.1. SECO Libraries
The SECO Library interfaces the SMW's subsystem SECO with the kernel SECO
Message Unit driver.

The following cmake script builds the SECO pointed by the `SECO_SRC_PATH` using
the default compiler. Installation of the ARM 32 or 64 bits cross-compiler is described in [Toolchains](#2-toolchains).

The built libraries and corresponding interface headers are installed in the `SECO_ROOT`
directory.

```sh
$ cmake -DCMAKE_TOOLCHAIN_FILE=./scripts/aarch[XX]_toolchain.cmake -DSECO_ROOT=[export path] -DSECO_SRC_PATH=[source path] -P ./scripts/build_seco.cmake
```

#### 3.1.2. NVM Daemon
The SECO Non-Volatile Memory (NVM) daemon used to store all persistent objects is
built with the same command as the [SECO Library](#311-seco-library).
The NVM Daemon is a linux service that must be started before loading the SMW Library.

The NVM Daemon service package is available in the `SECO_ROOT` directory.

To start the NVM Daemon service if not yet active, the following command can be
used on the host platform.

```sh
systemctl start nvm_daemon
```

### 3.2. TEE subsystem
The core library includes a static OPTEE Trusted Application library
(code is available under `core/subsystems/tee/lib_ta/` folder). This library is
built if the OPTEE Client and TA Development Kit options are set as defined
in this section. This static library binary is present in the library folder of
the project build directory.

<u>This library is an example and is used by the test suite package</u>. To ensure TEE
key storage protection against non-secure client application, an application
must load a unique TA, else if applications load/share the same TA, the key
storage is also shared. The section [Creating a simple OPTEE TA](#3223-creating-a-simple-optee-ta) hereafter gives an example to create a simple TA using the TA Library provided.

#### 3.2.1. OPTEE Client Library
The OPTEE Client library interfaces the SMW Library with the OPTEE Trusted
Application (TA) running in Trustzone secure world.

The following cmake script builds the OPTEE Client sources pointed by the
`TEEC_SRC_PATH` using the default compiler. Installation of the ARM 32 or 64 bits cross-compiler is described in [Toolchains](#2-toolchains).

The built library and corresponding interface headers are installed in the `TEEC_ROOT`
directory.

```sh
$ cmake -DCMAKE_TOOLCHAIN_FILE=./scripts/aarch[XX]_toolchain.cmake -DTEEC_ROOT=[export path] -DTEEC_SRC_PATH=[source path] -P ./scripts/build_teec.cmake
```

> :memo: **Note:**
> The option `BUILD_DIR` can be setup to define the OPTEE Client build directory
prefix. The default `BUILD_DIR` value is `./ext_build`. The intermediate objects
are built in the `[BUILD_DIR]/optee_client` (by default `./ext_build/optee_client`).

#### 3.2.2. OPTEE TA Development Kit
The OPTEE TA Development Kit is a OPTEE Trusted Application build kit.

The following cmake script builds the OPTEE TA Development Kit sources pointed by the
`OPTEE_OS_SRC_PATH` using the default compiler. Installation of the ARM 32 or 64 bits cross-compiler is described in [Toolchains](#2-toolchains).

The OPTEE OS sources built are the NXP sources integrating the NXP platform and
available in github (https://github.com/nxp-imx/imx-optee-os).

The development kit and corresponding interface headers are installed in the `TA_DEV_KIT_ROOT`
directory.

```sh
$ cmake -DCMAKE_TOOLCHAIN_FILE=./scripts/aarch[XX]_toolchain.cmake -DTA_dEV_KIT_ROOT=[export path] -DOPTEE_OS_SRC_PATH=[source path] -DPLATFORM=[platform] -P ./scripts/build_tadevkit.cmake
```

> :memo: **Notes:**
> - The option `PLATFORM` must be one of the NXP OPTEE OS supported platforms
(refer to the script `scripts/nxp_build.sh` present in NXP OPTEE OS sources). The
`PLATFORM` name is used to create the OPTEE OS build directory `build.[PLATFORM]`.
The toolchain used is function of the platform.
> - The option `BUILD_DIR` can be setup to define the OPTEE OS build directory
prefix. The OPTEE OS objects are built in the `./[BUILD_DIR]/build.[PLATFORM]`
(by default `./build.[PLATFORM]`).

### 3.3. ELE subsystem
#### 3.3.1. ELE Library
The ELE Library interfaces the SMW's subsystem ELE with the kernel ELE
Message Unit driver.

The following cmake script builds the ELE pointed by the `ELE_SRC_PATH` using
the default compiler. Installation of the ARM 32 or 64 bits cross-compiler is described in [Toolchains](#2-toolchains).

The built libraries and corresponding interface headers are installed in the `ELE_ROOT`
directory.

```sh
$ cmake -DCMAKE_TOOLCHAIN_FILE=./scripts/aarch[XX]_toolchain.cmake -DELE_ROOT=[export path] -DELE_SRC_PATH=[source path] -P ./scripts/build_ele.cmake
```

#### 3.3.2. NVM Daemon
The ELE Non-Volatile Memory (NVM) daemon used to store all persistent objects is
built with the same command as the [ELE Library](#331-ele-library).
The NVM Daemon is a linux service that must be started before loading the SMW Library.

The NVM Daemon service package is available in the `ELE_ROOT` directory.

To start the NVM Daemon service if not yet active, the following command can be
used on the host platform.

```sh
systemctl start nvm_daemon
```

### 3.4. JSON-C Library
The JSON-C Library is required only if the SMW test suite is wanted.

The following cmake script uploads into the `JSONC_SRC_PATH` if not already present
and builds the JSON-C sources present by the `JSONC_SRC_PATH` using the
default compiler, then the library and interface headers are copied in the path
specified by `JSONC_ROOT`. Installation of the ARM 32 or 64 bits cross-compiler is
described in [Toolchains](#2-toolchains).

```sh
$ cmake -DCMAKE_TOOLCHAIN_FILE=./scripts/aarch[XX]_toolchain.cmake -DJSONC_ROOT=[export path] -DJSONC_SRC_PATH=[source path] -P ./scripts/build_jsonc.cmake
```

> :memo: **Note:**
> The option `JSONC_VERSION` can be defined to build a specific JSON-C library.
If not define, the version 0.15 is built.

### 3.5 ARM PSA Test Suite
The SMW Library refers to the ARM PSA Test Suite to validate the implementation
of the ARM PSA API standard compliancy. If the SMW Tests are enabled and the
ARM PSA tests must be executed, the cmake project option `PSA_ARCH_TESTS_SRC_PATH`
must be defined with the path where are cloned the ARM PSA Test Suite sources.
See the [Enabling Test Suites](#44-enabling-test-suites) chapter.

The sources are available on GitHub <a href="https://github.com/ARM-software/psa-arch-tests.git">
	ARM PSA test suite</a>.

A SMW cmake script is available to clone the version used as reference.

```sh
$ cmake -DPSA_ARCH_TESTS_SRC_PATH=[source path] -P ./scripts/fetch_psaarchtests.cmake
```

# 4. Project configuration and compilation
This chapter explains how to configure and compile the Secure Middleware project:
- SMW shared library and test suites (SMW and PSA standard test suite)
- PKCS#11 shared library and test suite

The project requires the cmake minimal version 3.13.

Before building the project, it must be configured to select at least the
cross-compiler toolchain and the subsystem(s) to support in the SMW Library.
If no subsystem is configured, the project will not build.

> :bulb: **Tip:**
> The configuration of the project can be done interactively with the GUI ccmake
tool (refer to <a href=https://cmake.org/cmake/help/latest/manual/ccmake.1.html>ccmake help</a>)

## 4.1. Build environment options
The <a href="#table-build-environment-options">build environment options</a>
setup the overall project by defining the compiler, the debug level and the API
documentation generation.

<table>
<caption id="table-build-environment-options">Build environment options</caption>
<thead>
<tr>
  <th>Project cmake variable</th>
  <th>CMake option</th>
	<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
	<td>CMAKE_TOOLCHAIN_FILE</td>
	<td>-DCMAKE_TOOLCHAIN_FILE=[/path/to/script]</td>
	<td>Path to the script configuring the cross-compiler toolchain.<br>
	Project script could be used, e.g:
	<ul>
	  <li><em>./scripts/aarch64_toolchain.cmake</em> for the 64 bits GNU ARM toolchain.</li>
	  <li><em>./scripts/aarch32_toolchain.cmake</em> for the 32 bits GNU AMR toolchain.</li>
	</ul></td>
</tr>
<tr>
  <td>TOOLCHAIN_NAME</td>
  <td>-DTOOLCHAIN_NAME=[toolchain name]</td>
  <td>Configure the toolchain name, default are:
	<ul>
	  <li><em>aarch64-none-linux-gnu for the 64 bits GNU ARM toolchain.</em></li>
		<li><em>arm-none-linux-gnueabih for the 32 bits GNU ARM toolchain.</em></li>
	</ul>
	</td>
</tr>
<tr>
  <td>TOOLCHAIN_PATH</td>
  <td>-DTOOLCHAIN_PATH=[/path/to/toolchain]</td>
  <td>Configure the toolchain path if it's not the default one.
	Must be the path to the folder containing the toolchain folder.</td>
</tr>
<tr>
  <td>CMAKE_BUILD_TYPE</td>
  <td>-DCMAKE_BUILD_TYPE=[Debug/<b>Release</b>]</td>
  <td>Build type of the project. Release is the default option.
	Debug allows to access to more debug levels define by the <i>VERBOSE</i>
	option.</td>
</tr>
<tr>
  <td>VERBOSE</td>
  <td>-DVERBOSE=n</td>
  <td>Configure the debug trace level:
	<ul>
	<li><b>0</b> &rarr; No trace</li>
	<li>1 &rarr; ERROR, error traces only</li>
	<li>2 &rarr; INFO, error and information traces</li>
	<li>3 &rarr; DEBUG, all above + debug traces</li>
	<li>4 &rarr; VERBOSE, all above + verbose traces</li>
	<li>5 &rarr; EXTRA, all traces</li>
	</ul>
	If CMAKE_BUILD_TYPE is set to "Debug", max trace level supported is 5, otherwise is 2.
	Any value greater than the max trace level is interpreted as the max trace level.<br>
	By default setting is no trace.
	</td>
</tr>
<tr>
  <td>FORMAT</td>
  <td>-DFORMAT=[all|html|pdf]</td>
  <td>Configure the APIs documentation format to generate:
	<ul>
	<li>all  &rarr; Build PDF and HTML</li>
	<li>html &rarr; Build only HTML</li>
	<li>pdf  &rarr; Build only PDF</li>
	</ul>
	By default, documentation is not generated.</td>
</tr>
<tr>
  <td>CMAKE_INSTALL_PREFIX</td>
  <td>-DCMAKE_INSTALL_PREFIX=[/path/to/install]</td>
  <td>Define the cmake project install prefix directory when executing make install
	- refer to <a href=https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html#variable:CMAKE_INSTALL_PREFIX">CMAKE_INSTALL_PREFIX</a> definition.<br>
  Default value is /usr/local</td>
</tr>
<tr>
  <td>DISABLE_CMAKE_CONFIG</td>
	<td>-DDISABLE_CMAKE_CONFIG=[ON|<b>OFF</b>]</td>
	<td>If equal ON, disable the project cmake package config files see
	<a href="https://cmake.org/cmake/help/latest/manual/cmake-packages.7.html">cmake package</a><br>
	By default, the DISABLE_CMAKE_CONFIG=OFF.</td>
</tr>
<tr>
  <td>TEE_TA_DESTDIR</td>
  <td>-DTEE_TA_DESTDIR=[/path/to/install/ta/]</td>
  <td>Define the path where TEE TAs are installed. The path is prefixed by the <i><code>[DESTDIR]</code></i> environment variable.<br>
  By default, the TAs are installed in the <code>/usr/lib/optee_armtz</code> directory.<br>
  Installing TAs in the non-default directory may require specific TEE build
  configuration not configurable by SMW project.</td>
</tr>
</tbody>
</table>

## 4.2. Enabling Secure Subsystems
The Secure Subsystem(s) supported by the SMW library are depending of the cmake
project option configuration as details in the <a href="#table-enabling-secure-subsystem-options">
Enabling Secure Subsystems options table</a> below.

Before enabling a subsystem, the subsystem dependencies must be built as described in [External Dependencies](#32-external-dependencies) section if necessary.

<table>
<caption id="table-enabling-secure-subsystem-options">Enabling Secure Subsystem options</caption>
<thead>
<tr>
  <th>Secure Subsystem</th>
  <th>CMake option</th>
	<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>SECO</td>
  <td>-DSECO_ROOT=[/path/to/export]</td>
  <td>Path to the SECO library and headers interface</td>
</tr>
<tr>
  <td rowspan="2">TEE</td>
  <td>-DTEEC_ROOT=[/path/to/export]</td>
  <td>Path to the OPTEE Client library and headers interface</td>
</tr>
<tr>
  <td>-DTA_DEV_KIT_ROOT=[/path/to/export]</td>
	<td>Path to the OPTEE OS TA Development Kit</td>
</tr>
<tr>
  <td>ELE</td>
  <td>-DELE_ROOT=[/path/to/export]</td>
  <td>Path to the ELE library and headers interface</td>
</tr>
</tbody>
</table>

## 4.3. Libraries options

### 4.3.1. SMW Library options
The following <a href="#table-smw-library-options">SMW Library options table</a>
lists the SMW build options selectable to customize the operation supported by
the library.

The default option value is in **bold**.

<table>
<caption id="table-smw-library-options">SMW Library options</caption>
<thead>
<tr>
  <th>CMake option</th>
	<th>Description</th>
	<th>Dependent on</th>
</tr>
</thead>
<tbody>
<tr>
  <td>-DENABLE_KEYMGR_MODULE=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Key Manager operations. Default is ON (enable).</td>
	<td></td>
</tr>
<tr>
  <td>-DENABLE_HASH=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Hash operations. Default is ON (enable).</td>
	<td></td>
</tr>
<tr>
  <td>-DENABLE_SIGN_VERIFY=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of asymmetric signature and verification
	operations. Default is ON (enable).</td>
	<td>ENABLE_KEYMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_MAC=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of MAC (HMAC/CMAC) operations.
	Default is ON (enable).</td>
	<td>ENABLE_KEYMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_CIPHER=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Cipher encryption/decryption operations.
	Default is ON (enable).</td>
	<td>ENABLE_KEYMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_AEAD=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of authentication encryption and decryption
	(AEAD) operations. Default is ON (enable).</td>
	<td>ENABLE_KEYMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_STORAGE_MODULE=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of data storage operations.
	Default is ON (enable).</td>
	<td>ENABLE_KEYMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_DEVMGR_MODULE=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Device Manager operations.
	Default is ON (enable).</td>
	<td></td>
</tr>
<tr>
  <td>-DENABLE_DEVICE_ATTESTATION=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Device Attestation operations.
	Default is ON (enable).</td>
	<td>ENABLE_DEVMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_DEVICE_LIFECYCLE=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Device Lifecycle operations.
	Default is ON (enable).</td>
	<td>ENABLE_DEVMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_DEVICE_REPROVISION=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Device Storage reprovisioning operations.
	Default is ON (enable).</td>
	<td>ENABLE_DEVMGR_MODULE</td>
</tr>
<tr>
  <td>-DENABLE_RNG=[<b>ON</b>|OFF]</td>
  <td>Enable/disable the support of Random Number Generation operations.
	Default is ON (enable).</td>
	<td></td>
<tr>
  <td>-DENABLE_TLS12=[ON|<b>OFF</b>]</td>
  <td>Enable/disable the support of TLS 1.2 key derivation features.
	Default is OFF (disable).</td>
	<td></td>
</tr>
<tr>
  <td>-DENABLE_PSA_DEFAULT_ALT=[ON|<b>OFF</b>]</td>
  <td>Enable/disable the support of an alternative subsystem for the PSA
	interface operations. Default is OFF (disable).</td>
	<td></td>
</tr>
</tbody>
</table>

### 4.3.2. PKCS#11 Library options
The following <a href="#table-pkcs11-library-options">PKCS#11 Library options
table</a> lists the PKCS#11 build options selectable to customize the operation
supported by the library.

The default option value is in **bold**.

<table>
<caption id="table-pkcs11-library-options">PKCS#11 Library options</caption>
<thead>
<tr>
  <th>CMake option</th>
	<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>-DPKCS11_MULTI_TRHEAD=[ON|<b>OFF</b>]</td>
  <td>Library multi-threading is supported. Default is OFF (disable).</td>
</tr>
<tr>
  <td>-DPKCS11_OS_MUTEX_SUPPORT=[ON|<b>OFF</b>]</td>
  <td>Library use OS Thread primitives. Default is OFF (disable).</td>
</tr>
<tr>
  <td>-DPKCS11_OS_TRHEAD_SUPPORT=[ON|<b>OFF</b>]</td>
  <td>Library use OS Mutex primitives. Default is OFF (disable).</td>
</tr>
<tr>
  <td>-DSMW_DEVICE_ONLY=[<b>ON</b>|OFF]</td>
  <td>Abstract all SMW's Secure Subsystems to be seen as a unique SMW subsystem.
	Default is ON (enable).</td>
</tr>
</tbody>
</table>

## 4.4. Enabling test suites
The SMW and PKCS#11 libraries are validated using in-house test suites or
reference test suite.

The SMW APIs are tested with a test suite specifically implemented for that and
using JSON-C test file description, hence to enable the SMW test suite, the
JSON-C Library must be built and defined in the project option.

The ARM PSA APIs are tested using the same test suite used for the SMW API tests
or with the ARM PSA test suite.

The PKCS#11 library is tested using a test suite specifically implemented for that.
This test suite doesn't require specific options to be enabled.

The following <a href="#table-test-suites-options">Enabling test
suites options table</a> lists the option to enable the test suites.

The default option value is in **bold**.

<table>
<caption id="table-test-suites-options">Enabling test suites options</caption>
<thead>
<tr>
  <th>CMake option</th>
	<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>-DJSONC_ROOT=[/path/to/export]</td>
  <td>Path to JSONC library and header files. Set this option enable the
	build of SMW test suites.</td>
</tr>
<tr>
  <td>-DPSA_ARCH_TESTS_SRC_PATH=[/path/to/src]</td>
  <td>Path to <a href="https://github.com/ARM-software/psa-arch-tests.git">
	ARM PSA test suite</a>.<br>
	<b>Note</b>: the -DJSONC_ROOT must also be defined.</td>
</tr>

</tbody>
</table>


# 5. SMW/PKCS#11 Libraries installation
As mentioned in the [Project configuration and compilation](#4-project-configuration-and-compilation),
the output library is located in the sub-directory _`lib`_ of the project build
folder (e.g _`./build/lib`_) and the exported header files in the top folder
_`./public`_ folder.

It's possible to install these files using the `make install` command that, by default, installs files in system folder _`/usr`_ as defined by the
<a href=https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html>CMAKE_INSTALL_PREFIX</a>.
As this project could be cross-compiled, destination directory could be changed

## 5.1. Install command
The following command shows how to install this project in a specific destination:

1. Place into the project build folder
2. Run this command:
	```sh
	[build]$ make DESTDIR=[path/to/install] install
	```

> :memo: **Note**:
> _DESTDIR_ is the path to the installation directory in which _`usr`_ folder
is created or already present. Hence, project library `libsmw.so` is installed
in _`[DESTDIR]/[CMAKE_INSTALL_PREFIX]/lib`_ (i.e. _`[DESTDIR]/usr/lib`_ by
default).

If errors like "file INSTALL cannot copy file" or "file failed to open for
writing (Permission denied)" occurred, execute the previous make command with
super-user privilege.

```sh
[build]$ sudo make DESTDIR=[path/to/install] install
```

## 5.2. Install result

> :memo: **Note 1**: The <i>y</i> is for the project minor version.

> :memo: **Note 2**: The `usr/lib/cmake` folder is not present if the project
option `DISABLE_CMAKE_CONFIG=ON` (see [Build environment options](#41-build-environment-options)).

<pre>
`-- <span style="color:orange">usr</span>
    |-- <span style="color:orange">include</span>
    |   |-- <span style="color:orange">smw</span>
    |   |   |-- <span style="color:orange">psa</span>
    |   |   |   |-- crypto.h
    |   |   |   |-- crypto_sizes.h
    |   |   |   |-- crypto_struct.h
    |   |   |   |-- crypto_types.h
    |   |   |   |-- crypto_values.h
    |   |   |   |-- error.h
    |   |   |   |-- initial_attestation.h
    |   |   |   |-- internal_trusted_storage.h
    |   |   |   |-- protected_storage.h
    |   |   |   `-- storage_common.h
    |   |   |-- <span style="color:orange">smw</span>
    |   |   |   |-- attr.h
    |   |   |   |-- names.h
    |   |   |   `-- <span style="color:orange">crypto</span>
    |   |   |       |-- aead.h
    |   |   |       `-- op_context.h
    |   |   |-- smw_config.h
    |   |   |-- smw_crypto.h
    |   |   |-- smw_device.h
    |   |   |-- smw_info.h
    |   |   |-- smw_keymgr.h
    |   |   |-- smw_osal.h
    |   |   |-- smw_status.h
    |   |   `-- smw_storage.h
    |   `-- <span style="color:orange">smw_pkcs11</span>
    |       |-- pkcs11.h
    |       |-- pkcs11f.h
    |       `-- pkcs11t.h
    `-- <span style="color:orange">lib</span>
        |-- <span style="color:orange">cmake</span>
        |   |-- NXP_SMWConfig.cmake
        |   |-- NXP_SMWConfigVersion.cmake
        |   |-- NXP_SMWTargets-debug.cmake
        |   `-- NXP_SMWTargets.cmake
        |-- libsmw.so -> libsmw.so.2
        |-- libsmw.so.2 -> libsmw.so.2.<i>y</i>
        |-- libsmw.so.2.<i>y</i>
        |-- libsmw_pkcs11.so -> libsmw_pkcs11.so.2
        |-- libsmw_pkcs11.so.2 -> libsmw_pkcs11.so.2.<i>y</i>
        `-- libsmw_pkcs11.so.2.<i>y</i>
</pre>

# 6. Tests
SMW library provides a test suite for SMW and PKCS#11 APIs.

## 6.1. Compilation
To enable the SMW API test suites, `JSONC_ROOT` project option must be set
(see [Enabling test suites](#44-enabling-test-suites)).

1. Place into build folder.
2. Command to build SMW/PSA API tests:
	```sh
	[build]$ make smwtest
	```

3. Command to build PKCS#11 API tests:
	```sh
	[build]$ make testsmw_pkcs11
	```

4. Command to build all tests available:
	```sh
	[build]$ make build_tests
	```

## 6.2. Installation
### 6.2.1. Install command
Test engines and tests files (configuration, test definition, script, ctest
testfile) could be installed using the _make install_tests_ command.

The following command shows how to install all tests (SMW and PKCS#11) in a specific destination:

1. Place into the project build folder
2. Run this command:
```sh
[build]$ make DESTDIR=[path/to/install] install_tests
```

If errors like "file INSTALL cannot copy file" or "file failed to open for
writing (Permission denied)" occurred, execute the previous make command with
super-user privilege.

```sh
[build]$ sudo make DESTDIR=[path/to/install] install_tests
```

> :memo: **Note**:
> Like the [SMW/PKCS#11 Libraries installation](#5-smwpkcs11-libraries-installation),
> files are installed in _`[DESTDIR]/[CMAKE_INSTALL_PREFIX]`_ destination folder
> (i.e. _`[DESTDIR]/usr`_ by default).
> - Engines are installed in _`[DESTDIR]/[CMAKE_INSTALL_PREFIX]/bin`_
> - SMW Library test files are installed in _`[DESTDIR]/[CMAKE_INSTALL_PREFIX]/share/smw/tests`_
> - PKCS#11 Library test files are installed in _`[DESTDIR]/[CMAKE_INSTALL_PREFIX]/share/smw/pkcs11/tests`_
> - TEE TAs are installed in _`[DESTDIR]/[TEE_TA_DESTDIR]/optee_armtz`_


### 6.2.2. Install result

> :memo: **Note 1**: The <i>y</i> is for the project minor version.

> :memo: **Note 2**: The `usr/lib/cmake` folder is not present if the project
option `DISABLE_CMAKE_CONFIG=ON` (see [Build environment options](#41-build-environment-options)).

> :memo: **Note 3**: In this installation, the _`[TEE_TA_DESTDIR]`_ is
set with the default value `/usr/lib/optee_armtz`

<pre>
`-- <span style="color:orange">usr</span>
    |-- <span style="color:orange">lib</span>
    |   `-- <span style="color:orange">optee_armtz</span>
    |   |-- 11b5c4aa-6d20-11ea-bc55-0242ac130003.ta
    |   `-- 218c6053-294e-4e96-830c-e6eba4aa4345.ta
    |-- <span style="color:orange">bin</span>
    |   |-- smwtest
    |   `-- testsmw_pkcs11
    `-- <span style="color:orange">share</span>
        `-- <span style="color:orange">smw</span>
            |-- <span style="color:orange">pkcs11</span>
            |   |-- <span style="color:orange">config</span>
            |   |   |-- default_config.txt
            |   |   |-- ele_only_config.txt
            |   |   |-- seco_only_config.txt
            |   |   `-- tee_only_config.txt
            |   |-- <span style="color:orange">scripts</span>
            |   |   `-- run_psa_test.sh
            |   |   `-- run_simple_test.sh
            |   `-- <span style="color:orange">tests</span>
            |       `-- CTestTestfile.cmake
            `-- <span style="color:orange">tests</span>
                |-- CTestTestfile.cmake
                |-- <span style="color:orange">config</span>
                |   |-- api_config.txt
                |   `-- ...
                |-- <span style="color:orange">scripts</span>
                |   `-- run_simple_test.sh
                `-- <span style="color:orange">test_definition</span>
                    |-- F_TEE_App_001.json
										`-- ...
</pre>

## 6.3. Execution
To be able to execute SMW test suite, CTest tool must be installed on the target.

The following commands show how to execute SMW and PKCS#11 tests:

1. Place into test folder:
	- For SMW API tests:
		```sh
		$ cd [DESTDIR]/[CMAKE_INSTALL_PREFIX]/share/smw/tests
		```

	- For PKCS#11 API tests:
		```sh
		$ cd [DESTDIR]/[CMAKE_INSTALL_PREFIX]/share/smw/pkcs11/tests
		```

2. Run the CTest command:
	```sh
	[DESTDIR]/[CMAKE_INSTALL_PREFIX]/share/smw/.../tests $ ctest
	```

Here's a list of useful CTest options:
- -R \<test name\> to run a specific test
- -L \<label name\> to run all the tests of a certain label
- -LE \<label name\> to run all tests except those from a certain label
- --verbose to print some debug traces

For each test a status file is generated in the folder where CTest command in
run. It describes subtest status (PASSED or FAILED) and failure status.

# 7. Tips

Configuring and building the project can be simplified by using provided
scripts.

## 7.1. Reference platforms configuration script
The `./scripts/smw_configure.sh` shell script can be used to prepare and configure
the project for reference platforms as details below assuming that external
dependencies sources are installed in predefined path.

For all platforms, TEE subsystem is enabled all tests are enabled.

The script is invoked with 3 mandatory parameters and accept 1 optional parameter
setting the path where the toolchain is installed (see [Toolchains](#2-toolchains)).
If optional `toolpath=` parameter is not set, the toolchain is expected to be
installed in `/toolchains` system path.

```sh
$ ./scripts/smw_configure.sh [build directory] [architecture] [platform] toolpath=[path/to/toolchain]
```

<table>
<caption id="platforms_smw_configure">Supported Platforms</caption>
<thead>
<tr>
  <td>Platforms</td>
	<td>Architecture</td>
</tr>
</thead>
<tbody>
<tr>
  <td>imx7dsabresd</td>
  <td>aarch32</td>
</tr>
<tr>
  <td>imx8mmevk</td>
  <td>aarch64</td>
</tr>
<tr>
  <td>imx8qxpc0mek</td>
  <td>aarch64</td>
</tr>
<tr>
  <td>imx8ulpevk</td>
  <td>aarch64</td>
</tr>
<tr>
  <td>imx93evk</td>
  <td>aarch64</td>
</tr>
<tr>
  <td>imx95evk</td>
  <td>aarch64</td>
</tr>
</tbody>
</table>

<table>
<caption id="prerequisite_smw_configure">Prerequisites</caption>
<thead>
<tr>
  <th>Platforms</th>
  <th>Sources</th>
  <th>Path<br>(relative to smw sources path)</th>
	<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>All</td>
  <td>https://github.com/nxp-imx/imx-optee-client</td>
  <td>../optee-client</td>
  <td>NXP i.MX OPTEE OS Client library sources</td>
</tr>
<tr>
  <td>All</td>
  <td>https://github.com/nxp-imx/imx-optee-os</td>
  <td>../optee-os</td>
  <td>NXP i.MX OPTEE OS sources</td>
</tr>
<tr>
  <td rowspan="2">All</td>
  <td>https://github.com/json-c/json-c</td>
	<td rowspan="2">../jsonc</td>
  <td rowspan="2">JSON-C library sources</td>
</tr>
<tr>
	<td>https://s3.amazonaws.com/json-c_releases/releases/json-c-0.15.tar.gz</td>
	<td></td>
</tr>
<tr>
  <td>All</td>
  <td>https://github.com/ARM-software/psa-arch-tests.git</td>
	<td>master</td>
	<td>../psa-arch-tests</td>
  <td>JSON-C library sources</td>
</tr>
<tr>
  <td><ul>
	<li>imx95evk</li>
	<li>imx93evk</li>
	<li>imx8ulpevk</li>
	</ul></td>
  <td>https://github.com/nxp-imx/imx-secure-enclave.git</td>
	<td>../secure_enclave</td>
  <td>ELE library sources</td>
</tr>
<tr>
  <td>imx8qxpc0mek</td>
  <td>https://github.com/NXP/imx-seco-libs.git</td>
	<td>../seco_libs</td>
  <td>SECO library sources</td>
</tr>
</tbody>
</table>

## 7.2. Multi-function build script
The `./scripts/smw_build.sh` is a multi-function script that can be used to:

- Install the toolchains (see [Toolchains](#2-toolchains))
- Build and install SMW's external dependencies (see [External Dependencies](#3-external-dependencies))
- Configure and build the SMW project (see [Project configuration and compilation](#4-project-configuration-and-compilation))
- Install the SMW objects (see [SMW/PKCS#11 Libraries installation](#5-smwpkcs11-libraries-installation))
- Package the SMW objects and required external dependencies into a tarball.

More help is available by executing:

```sh
$ ./scripts/smw_build.sh -h
```

## 7.3. Including SMW in other cmake project
The Security Middleware project can be included in other cmake project using
the cmake <a href="https://cmake.org/cmake/help/latest/command/find_package.html#command:find_package">find_package()</a>.
The cmake `-DNXP_SMW_DIR` variable must be set to the path where is present the
`NXP_SMWConfig.cmake` file. Usually, it's in the SMW installation path `/usr/lib/cmake/`.

> :memo: **Note:** The `DISABLE_CMAKE_CONFIG` must not be set to `ON` in order to
> generate the cmake package files (see [Build environment options](#41-build-environment-options)).
