# TPM2-Tool User Guide <!-- omit in toc -->

# Table of Content <!-- omit in toc -->

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Limitations](#limitations)
- [Commands and Examples](#commands-and-examples)
  - [Initialize TPM2](#initialize-tpm2)
  - [Shutdown TPM2](#shutdown-tpm2)
  - [Hash Data](#hash-data)
  - [Get Random](#get-random)
  - [Read Public](#read-public)
  - [Create Key object](#create-key-object)
  - [Load Key object](#load-key-object)
  - [Sign Data](#sign-data)
  - [Verify Signature](#verify-signature)
- [TPM2 Commands Supported](#tpm2-commands-supported)

# Introduction

<a href="https://tpm2-tools.readthedocs.io/en/latest/">tpm2-tool</a> is a
command-line utility used to interact with the TPM2 (Trusted Platform Module 2.0)
through the SMW's TSS2 TCTI library.

This guide provides practical examples of how to use `tpm2-tool` with NXP
platforms to perform cryptographic operations, manage TPM resources.

> **WARNING:**
> The TPM2 TCTI support is currently in early development stage with limited
> command coverage. This implementation is provided as a proof of concept for
> evaluation purposes and may not handle all TPM2 operations correctly. It is
> not recommended for production use at this time.


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

The current implementation targets the TPM 2.0 Automotive Thin Profile
as defined in the TCG specification.

The ELE Secure Enclave has the following limitations when used with TPM2:
 - The TPM2_EvictControl allowing to convert a transient object into a
   persistent object is not supported. Hence primary key will be created as
   persistent key.
 - None of the Symmetric and Private part of the Asymmetric key can be exported,
   even in encrypted format.
 - For ECDSA algorithms, the algorithm digest size (in bits) must be equal to
   the asymmetric keypair security size (in bits). Exception for SHA512:
   keypair security size must be 521.
 - For TPMT_TK_HASHCHECK ticket, the HMAC computation uses hardcoded proof keys
   specific to each TPM hierarchy (Owner, Platform, and Endorsement). These
   proof keys serve as the HMAC secret for generating cryptographic tickets
   that validate hash operations within their respective hierarchy contexts.

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
context to primary_ecdsa.ctx. Use the createprimary command:
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

## Get Random
Generates 32 bytes of cryptographically secure random data from the TPM's
random number generator and displays the output in hexadecimal format.
Use the getrandom command:
```sh
tpm2_getrandom 32 --hex
```

## Read Public
Retrieves and displays the public area of a loaded TPM object from the
specified context file, showing the object's algorithm, attributes, and
public key parameters.
Use readpublic command:
```sh
tpm2_readpublic -c primary_ecdh.ctx
```

## Create Key object

### Create ECC Key object
Creates an ECC (NIST P-256) key object. Use the create command:
```sh
tpm2_create -C primary_ecdsa.ctx -G ecc256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -u signing_key.pub -r signing_key.priv \
```

**Parameters**:
- `-C primary_ecdsa.ctx`: Parent key context
- `-G ecc256`: Key type: ECC NIST P-256
- `-a`: Key attributes (sign, fixed TPM, fixed parent, sensitive data origin)
- `-u signing_key.pub`: Output file for the public key
- `-r signing_key.priv`: Output file for the private key blob

### Create HMAC Key object
Creates a SHA384 HMAC key object. Use the create command:
```sh
tpm2_create -C primary_ecdsa.ctx -G hmac:sha384 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -u signing_key.pub -r signing_key.priv \
```

**Parameters**:
- `-C primary_ecdsa.ctx`: Parent key context
- `-G hmac:sha384`: Key type: HMAC, sha384, using only hmac will use default hash alg (sha256)
- `-a`: Key attributes (sign, fixed TPM, fixed parent, sensitive data origin)
- `-u signing_key.pub`: Output file for the public key
- `-r signing_key.priv`: Output file for the private key blob

## Load Key object
Loads a previously created key object into TPM memory, making it available for
cryptographic operations. Use the load command:
```sh
tpm2_load -C primary_ecdsa.ctx \
  -u signing_key.pub \
  -r signing_key.priv \
  -c signing_key.ctx \
```

**Parameters**:
- `-C primary_ecdsa.ctx`: Parent key context
- `-u signing_key.pub`: Input file containing the public key
- `-r signing_key.priv`: Input file containing the private key blob
- `-c signing_key.ctx`: Output file for the loaded key context

## Sign Data
Signs a message or pre-computed digest using a loaded TPM signing key with ECDSA
signature scheme.

### Sign raw message
The TPM computes the digest internally before signing. Use the sign command:
```sh
tpm2_sign -c signing_key.ctx -g sha256 -f tss -o signature.tss message.txt
```

**Parameters**:
- `-c signing_key.ctx`: Context of the loaded signing key
- `-g sha256`: Hash algorithm to use for computing the digest (SHA-256)
- `-f tss`: Signature format (TSS format includes signature scheme information)
- `-o signature.tss`: Output file for the signature in TSS format
- `message.txt`: Input file containing the raw message to sign

### Sign pre-computed digest
Sign a digest that was computed externally or using `tpm2_hash`.

**Step 1 - Compute the digest using tpm2_hash**:
```sh
tpm2_hash -g sha256 -o message.hash message.txt
```

**Step 2 - Sign the digest**:
```sh
tpm2_sign -c signing_key.ctx -g sha256 -f tss -d -o signature.tss message.hash
```

**Parameters**:
- `-c signing_key.ctx`: Context of the loaded signing key
- `-g sha256`: Hash algorithm used to compute the digest (SHA-256)
- `-f tss`: Signature format (TSS format includes signature scheme information)
- `-d`: Indicates that the input is a pre-computed digest (not a raw message)
- `-o signature.tss`: Output file for the signature in TSS format
- `message.hash`: Input file containing the pre-computed digest to sign

## Verify Signature
Verifies a signature against a message or pre-computed digest using the public key
from a loaded TPM key object.

### Verify signature with raw message
The TPM computes the digest internally before verification. Use the verify signature
command:
```sh
tpm2_verifysignature -c signing_key.ctx -g sha256 -s signature.tss -m message.txt
```

**Parameters**:
- `-c signing_key.ctx`: Context of the loaded signing key
- `-g sha256`: Hash algorithm to use for computing the digest (SHA-256)
- `-s signature.tss`: Input file containing the signature to verify (in TSS format)
- `-m message.txt`: Input file containing the raw message

### Verify signature with pre-computed digest
Verify a signature against a digest that was computed externally or using `tpm2_hash`:
```sh
tpm2_verifysignature -c signing_key.ctx -s signature.tss -d message.hash
```

**Parameters**:
- `-c signing_key.ctx`: Context of the loaded signing key
- `-s signature.tss`: Input file containing the signature to verify (in TSS format)
- `-d message.hash`: Input file containing the pre-computed digest (message hash)

## HMAC
Computes an HMAC over an input message using a previously created and loaded KeyedHash
object configured for signing operations. The resulting HMAC digest is written to an
output file. Use the hmac command:
```sh
tpm2_hmac -c hmac.ctx -g sha256 -o message.hmac message.txt
```

**Parameters**:
- `-c hmac.ctx`: Context of the loaded KeyedHash object
- `-g sha256`: Hash algorithm to use for computing the HMAC
- `-o message.hmac`: Output file in which the resulting HMAC digest is written (in binary format)
- `message.txt`: Input file over which the HMAC is computed

## PCR Read
Reads the current values of Platform Configuration Registers (PCRs) for specified hash algorithms
and PCR indices. The command displays the PCR values and can optionally save them
to an output file. Use the pcrread command:
```sh
tpm2_pcrread sha256:0 -o pcrs.bin
```

**Parameters**:
- `sha256:0`: Specify hash algorithm and PCR indices to read (e.g., SHA-256 PCR 0)
- `-o pcrs.bin`: Output file in which the resulting PCR values are written (in binary format)

## PCR Reset
Resets a Platform Configuration Register to its initial zero-filled state.
Only PCRs 16-23 can be reset at runtime; attempting to reset other PCRs will fail
with a locality error. Use the pcrreset command:
```sh
tpm2_pcrreset 16
```

**Parameters**:
- `16`: PCR index to reset

## PCR Extend
Extends a Platform Configuration Register with a provided digest value.
The PCR is updated using the formula: PCR_new = Hash(PCR_old || digest).
This operation is fundamental for building chains of trust in measured boot
scenarios. Use the pcrextend command:
```sh
tpm2_pcrextend 0:sha256=<digest_value>
```

**Parameters**:
- `0`: PCR index to extend
- `sha256`: Hash algorithm to use for the extension operation
- `digest_value`: Digest value to extend into the PCR (hexadecimal format) with
the correct size regarding hash algorithm used

## PCR Allocate
Configures the allocation of PCR banks by specifying which hash algorithms should be active.
This command requires platform authorization and typically causes a TPM reset.
Use the pcrallocate command:
```sh
tpm2_pcrallocate sha256:0
```

**Parameters**:
- `sha256`: Hash algorithm to enable for PCR banks
- `0`: PCR indices to include (:0 means PCR 0, can specify multiple like :0,1,2 or :all)

> 📝 **Note:**
> In the current SMW TCTI implementation, this command is processed as a mock
> operation. The requested allocation is acknowledged but not applied, and the
> response reports the current allocation state unchanged. This allows compatibility
> with TPM tools while maintaining the existing PCR bank configuration.

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
| `TPM2_GetRandom`        |
| `TPM2_ReadPublic`       |
| `TPM2_Create`           |
| `TPM2_Load`             |
| `TPM2_Sign`             |
| `TPM2_VerifySignature`  |
| `TPM2_HMAC`             |
| `TPM2_PCR_Read`         |
| `TPM2_PCR_Reset`        |
| `TPM2_PCR_Extend`       |
| `TPM2_PCR_Allocate`     |
