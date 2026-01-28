# TPM2-Tool User Guide <!-- omit in toc -->

# Table of Content <!-- omit in toc -->

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Limitations](#limitations)
- [Commands and Examples](#commands-and-examples)
  - [Initialize TPM2](#initialize-tpm2)
  - [Shutdown TPM2](#shutdown-tpm2)
  - [Hash Data](#hash-data)
- [TPM2 Commands Supported](#tpm2-commands-supported)

# Introduction

<a href="https://tpm2-tools.readthedocs.io/en/latest/">tpm2-tool</a> is a
command-line utility used to interact with the TPM2 (Trusted Platform Module 2.0)
through the SMW's TSS2 TCTI library.

This guide provides practical examples of how to use `tpm2-tool` with NXP
platforms to perform cryptographic operations, manage TPM resources.


# Prerequisites

Before using `tpm2-tool`, ensure the following:

- You have installed the `tpm2-tool` utility
  (<a href="https://tpm2-tools.readthedocs.io/en/latest/INSTALL/">`tpm2-tool` installation guide</a>).
- Ensure that SMW's TSS2 TCTI library is installed on your system. The shared
  library file `libtss2-tcti-smw.so.n.m` (where `n.m` is the library major.minor
  version)  must be present in the system folder usually `/usr/lib/`.
  On linux based system, the symbol file `libtss2-tcti-smw.so.n` is also present.

  More information are available in [build instruction](../build_instructions.md),
  chapter `Install command`.
- You are running on a NXP platform with a EdgeLock Secure Enclave (ELE)
  enabled (configured) in the SMW library and make sure that the
  NVM Secure Storage kernel service is up and running using the command:

  ```sh
  systemctl start nvm_daemon
  ```

> 📝 **Note 1:**
> SMW TPM2 is only working on NXP platform with an ELE Secure Enclave
> (i.MX9x devices).

The SMW's TSS2 TCTI library can be referenced using the environment variable
`TPM2TOOLS_TCTI` or command line option `--tcti` (or `-T`.)

The SMW's TSS2 TCTI library is named `libtss2-tcti-smw.so.n`, where `n` is the
library major version, (e.g., `libtss2-tcti-smw.so.1`). To use this TCTI
libary with `tpm2-tool`:

  - Either set the environment variable `TPM2TOOLS_TCTI`:
    ```sh
    export TPM2TOOLS_TCTI=libtss2-tcti-smw.so.n
    ```
  - or use the command line option `--tcti` (or `-T`):
    ```sh
    tpm2 [command] --tcti=libtss2-tcti-smw.so.n [options]
    ```
    or
    ```sh
    tpm2 [command] -T libtss2-tcti-smw.so.n [options]
    ```

More information on how to set the TCTI library are available in the
<a href="https://tpm2-tools.readthedocs.io/en/latest/man/common/tcti/">tpm2-tool TCTI Configuration</a>.

# Limitations

The ELE Secure Enclave has the following limitations when used with TPM2:
 - The TPM2_EvictControl allowing to convert a transient object into a
   persistent object is not supported. Hence primary key will be created as
   persistent key.
 - None of the Symmetric and Private part of the Asymmetric key can be exported,
   even in encrypted format.


# Commands and Examples

In the following examples, the environment variable `TPM2TOOLS_TCTI` is set.

## Initialize TPM2
Initialize the TPM2 device, use the startup command:
```sh
tpm2_startup -c
```

## Shutdown TPM2
Shutdown the TPM2 device, use the shutdown command:
```sh
tpm2_shutdown -c
```

## Hash Data
Hash data using TPM2:
```sh
tpm2_hash -g sha256 -o hash.out data.txt
```

## Start Authorization Session
Start a TPM2 authorization session (TPM2_SE_HMAC type) and save its context
in a file, use the startauthsession command:
```sh
tpm2_startauthsession --hmac-session -S session.ctx
```

## Create Primary object
Creates an ECC primary key (P-256) under the Owner hierarchy with SHA-256 as
the name hash, using restricted fixed attributes, and saves the resulting key
context to primary_ecdsa.ctx
```sh
tpm2_createprimary -C o -g sha256 -G ecc256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted" \
  -c primary_ecdsa.ctx \
```

## Get Capability
Lists all currently loaded transient object handles in the TPM,
showing which temporary keys or objects are active in memory, use the
getcap command:
```sh
tpm2_getcap handles-transient
```

# TPM2 Commands Supported

Following table lists TPM2 Commands implemented in the SMW's TSS2 TCTI library.

| TPM2 Commands           |
| :---------------------- |
| `TPM2_Startup`          |
| `TPM2_Shutdown`         |
| `TPM2_Hash`             |
| `TPM2_StartAuthSession` |
| `TPM2_CreatePrimary`    |
| `TPM2_GetCapability`    |
| `TPM2_ContextLoad`      |
| `TPM2_ContextSave`      |
| `TPM2_FlushContext`     |
