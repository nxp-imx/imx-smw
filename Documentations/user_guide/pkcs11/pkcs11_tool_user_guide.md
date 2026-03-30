# PKCS11-Tool User Guide <!-- omit in toc -->

# Table of Content <!-- omit in toc -->

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Limitations](#limitations)
- [Commands and Examples](#commands-and-examples)
  - [📋 Listing Tokens](#-listing-tokens)
    - [Example on i.MX93 platform](#example-on-imx93-platform)
  - [📋 Listing Objects](#-listing-objects)
    - [Listing all](#listing-all)
      - [Example on i.MX93 platform](#example-on-imx93-platform-1)
    - [Listing per label](#listing-per-label)
      - [Example on i.MX93 platform](#example-on-imx93-platform-2)
  - [📋 Listing Mechanisms](#-listing-mechanisms)
  - [🔑 Key Generation](#-key-generation)
    - [Basic syntax](#basic-syntax)
    - [Generate an RSA key pair:](#generate-an-rsa-key-pair)
      - [Example on i.MX93 platform](#example-on-imx93-platform-3)
    - [Generate an ECC key pair:](#generate-an-ecc-key-pair)
      - [Example on i.MX93 platform](#example-on-imx93-platform-4)
    - [Generate an AES secret key:](#generate-an-aes-secret-key)
      - [Example on i.MX93 platform](#example-on-imx93-platform-5)
  - [🔑 Key Deletion](#-key-deletion)
    - [Basic syntax](#basic-syntax-1)
    - [Delete an ECC key pair:](#delete-an-ecc-key-pair)
      - [Example on i.MX93 platform](#example-on-imx93-platform-6)
    - [Delete an AES secret key:](#delete-an-aes-secret-key)
      - [Example on i.MX93 platform](#example-on-imx93-platform-7)
  - [🔐 Encryption](#-encryption)
  - [🔓 Decryption](#-decryption)
  - [✍️ Signing](#️-signing)
  - [✅ Verification](#-verification)
  - [🛡️ Authenticated Encryption (AEAD)](#️-authenticated-encryption-aead)
  - [🎲 Random Number Generation](#-random-number-generation)
  - [📥 Reading, Writing and Deleting Data](#-reading-writing-and-deleting-data)
    - [Write data](#write-data)
    - [Read data](#read-data)
    - [Delete data](#delete-data)
- [Cryptography Mechanisms Supported](#cryptography-mechanisms-supported)
  - [Key Generation](#key-generation)
  - [Key Derivation](#key-derivation)
  - [Digest](#digest)
  - [MAC Signature](#mac-signature)
  - [Asymmetric Signature](#asymmetric-signature)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Authentication Encryption](#authentication-encryption)
- [PKCS11 APIs Supported](#pkcs11-apis-supported)
- [Best Practices for Using pkcs11-tool](#best-practices-for-using-pkcs11-tool)
  - [🔐 Use the Correct PKCS#11 Module](#-use-the-correct-pkcs11-module)
  - [📋 List and Understand Capabilities](#-list-and-understand-capabilities)
  - [🏷️ Use Consistent Labels and IDs](#️-use-consistent-labels-and-ids)
  - [🧭 Use Verbose and Debug Options](#-use-verbose-and-debug-options)


# Introduction

`pkcs11-tool` is a command-line utility used to interact with PKCS#11
cryptographic tokens such as smart cards and Hardware Security Modules (HSMs).
It allows users to perform operations like listing objects,
generating key pairs, signing data, and more.

This guide explains some typical command lines example that could be executed
on NXP platforms.


# Prerequisites

Before using `pkcs11-tool`, ensure the following:

- You have installed the `pkcs11-tool` utility (usually part of the
  [OpenSC](https://github.com/OpenSC/OpenSC/wiki) package).
- Ensure that SMW's PKCS11 library is installed on your system. The shared
  library file `libsmw_pkcs11.so.x.y` (where `x.y` is the library major.minor
  version)  must be present in the system folder usually `\usr\lib\`.
  On linux based system, the symbol file `libsmw_pkcs11.so.x` is also present and
  should be used as pkcs11-tool module parameter (*--module*).

  More information are available in [build instruction](../build_instructions.md),
  chapter `Install command`.
- If running on a NXP platform with a Secure Enclave (e.g. SECO or ELE Secure
  Enclave) enabled (configured) in the SMW library, make sure that the
  NVM Secure Storage kernel service is up and running using the command:

  ```sh
  systemctl start nvm_daemon
  ```

To simplify the command line, the following environment variable can be defined
to refer on the SMW's PKCS11 library. In this documentation, we assume that the
library is present in the system folder `\usr\lib\`.

```sh
export MODULE_PKCS11=/usr/lib/libsmw_pkcs11.so.5
```

> 📝 **Note 1:**
> For the following command example, the SMW's PKCS11 library
  major version 5 is used. If another version is used, replace the shared
  library major version with the correct value.

> 📝 **Note 2:**
> For a concrete use case, the following examples are
  executed on NXP platform with an ELE Secure Enclave that is i.MX9x devices.

> 📝 **Note 3:**
> SMW's PKCS11 doesn't require PIN code, hence no need to
  specify the `--pin` parameter, even if set it will be ignored.


# Limitations

This user guide doesn't provide all possible `pkcs11-tool` command lines and
doesn't guaranty that all possible options of the listed operations are
functional with the SMW's PKCS11 library where targeted Secure Subsystem are
TEE, ELE or SECO.

Indeed, PKCS11 library doesn't support all PKCS11 interfaces
[PKCS11 API](#pkcs11-apis-supported) and Secure Subsystem targeted for the
PKCS11 operation can have particular behaviours not managed by the tool
implementation.

Support of the token certificate is not yet available. Only PKCS11 session
certificate are handled.

Known issue: `pkcs11-tool` uri encoding fail to encode id bigger than `0xff`
As specified in [PKCS#11 URI Scheme](https://datatracker.ietf.org/doc/html/rfc7512)
The value of the attribute "id" MUST be compared using the simple
string comparison after **all bytes** are percent-encoded using
uppercase letters for digits A-F (i.e. `0x102` is encoded as `%01%02`).

# Commands and Examples

## 📋 Listing Tokens

To list all available tokens:

```sh
pkcs11-tool --module $MODULE_PKCS11 -L
```

### Example on i.MX93 platform

```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 -L

Available slots:
Slot 0 (0x0): Security Middleware Abstraction
  token label        : smw
  token manufacturer : NXP Semiconductor
  token model        :
  token flags        : login required, PIN pad present, token initialized
  hardware version   : 0.0
  firmware version   : 0.0
  serial num         :
  pin min/max        : 0/0
  uri                : pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw
```

## 📋 Listing Objects

### Listing all

**Definition**: List all objects (keys, certificates, etc.) on a token:

```sh
pkcs11-tool --module $MODULE_PKCS11 --login -O
```

This command lists all objects stored on the token.

#### Example on i.MX93 platform

In this example, 2 persistent keys (one AES symmetric and one ECDSA
asymmetric) and 1 persistent data have been previously created using SMW's APIs.

```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login -O

Using slot 0 with a present token (0x0)
Profile object 3842126176
  profile_id:          CKP_BASELINE_PROVIDER (1)
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   0441040adad46d500a5d6f43aeea20998a1d27e19b307ac73fd5994f842159a93e15c7eb8a333b117bdfe63ca85566d395a862844f4c7971681776cfdcd50473b60de7
  EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
  label:      Key
  ID:         01e240
  Usage:      verify
  Access:     none
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01e240;object=Key;type=public
Private Key Object; EC
  label:      Key
  ID:         01e240
  Usage:      sign
  Access:     none
  Allowed mechanisms: ECDSA-SHA256
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01e240;object=Key;type=private
Secret Key Object; AES length 16
  label:      Key
  ID:         020012
  Usage:      encrypt, decrypt
  Access:     none
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%020012;object=Key;type=secret-key
Data object 3842370016
  label:          'Data'
  application:    ''
  app_id:         1.2.21
  flags:          modifiable
  uri:            pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;object=Data;type=data
```

### Listing per label

**Definition**: List objects (keys, certificates, etc.) on a token based on
  a label value:

```sh
pkcs11-tool --module $MODULE_PKCS11 --login -O --label "MyLabel"
```

This command lists all objects stored on the token where label is "*MyLabel*".

> 📝 **Note:**
> SMW library pre-defined default label for objects not
> created by PKCS11 (e.g. using ARM PSA, SMW APIs, EdgeLock 2GO provisioning):
>
>  - "Key": Default key label
>  - "Key-EdgeLock2GO": Default EdgeLock 2GO key label
>  - "Data": Default data label
>  - "Data-EdgeLock2GO": Default EdgeLock 2GO data label

#### Example on i.MX93 platform

In this example, 2 persistent keys (one AES symmetric key and one ECDSA
asymmetric) and 1 persistent data have been previously created using SMW's APIs.

Keys are labelled "Key" and Data is labelled "Data".

```sh
pkcs11-tool --module $MODULE_PKCS11 --login -O --label "Key"
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login -O --label "Key"
Using slot 0 with a present token (0x0)
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   0441041ccfa619f995a7468b2b283d2c558095b234f057cdc2c73f327aa8ae96ab993825594400d7e79dfc18e5016c62c4df9d259c5b4aab5fc14e196f1ec37e2b07f5
  EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
  label:      Key
  ID:         01e240
  Usage:      verify
  Access:     none
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01e240;object=Key;type=public
Private Key Object; EC
  label:      Key
  ID:         01e240
  Usage:      sign
  Access:     none
  Allowed mechanisms: ECDSA-SHA256
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01e240;object=Key;type=private
Secret Key Object; AES length 16
warning: PKCS11 function C_GetAttributeValue(VALUE) failed: rv = CKR_ATTRIBUTE_SENSITIVE (0x11)

  label:      Key
  ID:         020012
warning: PKCS11 function C_GetAttributeValue(VERIFY_RECOVER) failed: rv = CKR_ATTRIBUTE_TYPE_INVALID (0x12)

  Usage:      encrypt, decrypt
  Access:     none
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%020012;object=Key;type=secret-key
```

## 📋 Listing Mechanisms

**Definition**: List Mechanisms supported on a token:

```sh
pkcs11-tool --module $MODULE_PKCS11 -M
```

This command will list all mechanisms supported on the token.
The output mechanisms will be like:

  - RSA-PKCS
  - SHA256-RSA-PKCS
  - ECDSA
  - AES-CBC
  - CKM_SHA256_HMAC

Each mechanism corresponds to a cryptographic operation the token can perform.

Understanding Mechanism Capabilities, each mechanism may support:

  - Key generation
  - Encryption/Decryption
  - Signing/Verifying
  - Digesting (hashing)

The mechanisms supported depend on the token and the subsystem(s) configured.
Refer to [Cryptography Mechanisms Supported](#cryptography-mechanisms-supported).

## 🔑 Key Generation

**Definition**: Creating cryptographic keys directly on the token.

**Use Cases**:
- Secure key provisioning
- On-device key management

### Basic syntax

- To generate an asymmetric key

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type <type> \
            --id <hex_id> \
            --label "<label>" \
            --usage-sign --usage-decrypt <other usages> \
            --allowed-mechanisms "<mechanism1>"
```

- To generate a symmetric key

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keygen \
            --key-type <type> \
            --id <hex_id> \
            --label "<label>" \
            --allowed-mechanisms "<mechanism1>"
```

> 📝 **Note 1:**
> The key usage must be specified when generating a key and must be
> defined from the following list:
>
>  - --usage-sign:    Specify 'sign' usage for the private key and 'verify'
>                     usage for the public key.
>  - --usage-decrypt: Specify 'decrypt' usage flag.
>                     For RSA keys, sets 'decrypt' usage flag for the
                      private key and 'encrypt' usage flag for the public key.
                      For secret keys, sets both 'encrypt' and 'decrypt' flags.
>  - --usage-derive:  Specify 'derive' usage flag (EC key only).

> 📝 **Note 2:**
> The mechanism name to set with the option
  `--allowed-mechanism` must be one of the mechanisms resulting of the
  [Listing Mechanisms](#-listing-mechanisms).


### Generate an RSA key pair:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type rsa:2048 \
            --id 01 \
            --label "MyRSAKey" \
            --usage-sign \
            --allowed-mechanisms "RSA-PKCS"
```

#### Example on i.MX93 platform

```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login --keypairgen --key-type rsa:2048 --id 01 --label "MyRSAKey" --usage-sign --allowed-mechanisms "RSA-PKCS"
Using slot 0 with a present token (0x0)
Key pair generated:
Private Key Object; RSA
  label:      MyRSAKey
  ID:         01
  Usage:      sign
  Access:     sensitive, local
  Allowed mechanisms: RSA-PKCS
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01;object=MyRSAKey;type=private
Public Key Object; RSA 2048 bits
  label:      MyRSAKey
  ID:         01
  Usage:      verify
  Access:     local
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%01;object=MyRSAKey;type=public
```

### Generate an ECC key pair:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type EC:prime256v1 \
            --id 02 \
            --label "MyECCKey" \
            --usage-sign \
            --allowed-mechanisms "ECDSA-SHA256"
```

#### Example on i.MX93 platform

```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login --keypairgen --key-type EC:prime256v1 --id 02 --label "MyECCKey" --usage-sign --allowed-mechanisms "ECDSA-SHA256"
Using slot 0 with a present token (0x0)
Key pair generated:
Private Key Object; EC
  label:      MyECCKey
  ID:         02
  Usage:      sign
  Access:     sensitive, local
  Allowed mechanisms: ECDSA-SHA256
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%02;object=MyECCKey;type=private
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   044104d5c696d6cdee950fea5d9951cd684d5e9f7ead55da5ffb13b50b6e343cd59eabca2edb5b0f29ac3c4b5ff4d9ff7c7ada65f8e4080a36341e653422daef819b20
  EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
  label:      MyECCKey
  ID:         02
  Usage:      verify
  Access:     local
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%02;object=MyECCKey;type=public
```

### Generate an AES secret key:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keygen \
            --key-type AES:32 \
            --id 03 \
            --label "MyAESKey" \
            --usage-decrypt \
            --allowed-mechanisms "AES-ECB"
```

#### Example on i.MX93 platform


```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login --keygen --key-type AES:32 --id 03 --label "MyAESKey" --allowed-mechanisms "AES-ECB"
Using slot 0 with a present token (0x0)
Key generated:
Secret Key Object; AES length 32
warning: PKCS11 function C_GetAttributeValue(VALUE) failed: rv = CKR_ATTRIBUTE_SENSITIVE (0x11)

  label:      MyAESKey
  ID:         03
warning: PKCS11 function C_GetAttributeValue(VERIFY_RECOVER) failed: rv = CKR_ATTRIBUTE_TYPE_INVALID (0x12)

  Usage:      encrypt, decrypt
  Access:     local
  Unique ID:
  uri:        pkcs11:model=;manufacturer=NXP%20Semiconductor;serial=;token=smw;id=%03;object=MyAESKey;type=secret-key
```

## 🔑 Key Deletion

**Definition**: Destroying cryptographic keys directly on the token.

### Basic syntax

- To delete an asymmetric key

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --delete \
            --type privkey \
            --id <hex_id> \
            --label "<label>"
```

- To delete a symmetric key

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --delete \
            --type secrkey \
            --id <hex_id> \
            --label "<label>"
```

> 📝 **Note 1:**
> For asymmetric key, deleting the public key is not going to delete the token key pair 
> and public key will be regenerated from the private key.
> To delete the key pair, delete the private key object.
> This will automatically delete the associated public key as well.

### Delete an ECC key pair:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --delete \
            --type privkey \
            --id 02 \
            --label "MyECCKey"
```

#### Example on i.MX93 platform

```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login --delete --type privkey --id 02 --label "MyECCKey"
Using slot 0 with a present token (0x0)
```

### Delete an AES secret key:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --delete \
            --type secrkey \
            --id 03 \
            --label "MyAESKey"
```

#### Example on i.MX93 platform


```sh
root@imx93evk:~# pkcs11-tool --module $MODULE_PKCS11 --login --delete --type secrkey --id 03 --label "MyAESKey"
Using slot 0 with a present token (0x0)
```

## 🔐 Encryption

**Definition**: The process of converting plaintext into ciphertext using a
  cryptographic algorithm and key.

**Use Cases**:
- Secure communication
- Data protection at rest


Encrypt data using a public key stored on the token:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --encrypt \
            --id 03 \
            --mechanism AES-ECB \
            --input-file plaintext.txt \
            --output-file ciphertext.bin
```

> 📝 **Note:**
> Command may return an error if the plaintext to encrypt
  is not a multiple cipher block as C_EncryptUpdate might not supported by
  the subsystem targeted.

## 🔓 Decryption

**Definition**: The process of converting ciphertext back into plaintext
  using the appropriate decryption key.

**Use Cases**:
- Reading encrypted messages
- Secure file access


Decrypt data using a private key stored on the token:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --decrypt \
            --id 03 \
            --mechanism AES-ECB \
            --input-file ciphertext.bin \
            --output-file plaintext.txt
```

> 📝 **Note:**
> Command may return an error if the cipher to decrypt
  is not a multiple cipher block as C_DecryptUpdate might not supported by
  the subsystem targeted.

## ✍️ Signing

**Definition**: Creating a digital signature using a private key to ensure
  data integrity and authenticity.

**Use Cases**:
- Document signing
- Software authenticity

Sign data using a private key:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --sign \
            --id 02 \
            --mechanism ECDSA-SHA256 \
            --input-file message.txt \
            --output-file signature.bin
```

## ✅ Verification

**Definition**: Validating a digital signature using the corresponding public key.

**Use Cases**:
- Verifying signed documents
- Authenticating software

Verify a signature using a public key:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --verify \
            --id 02 \
            --mechanism ECDSA-SHA256 \
            --input-file message.txt \
            --signature-file signature.bin
```

## 🛡️ Authenticated Encryption (AEAD)

**Definition**: Encrypting data while simultaneously ensuring its integrity
  and authenticity.

**Use Cases**:
- Secure messaging
- TLS and VPN encryption

Authenticated encryption with AES-GCM (if supported):

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --encrypt \
            --id 04 \
            --mechanism AES-GCM \
            --input-file plaintext.txt \
            --output-file ciphertext.bin
```

**Note:** AEAD support depends on the token and may require additional parameters.


## 🎲 Random Number Generation

**Definition**: Generating cryptographically secure random numbers.

**Use Cases**:
- Key generation
- Nonce and IV creation

Generate random bytes:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --generate-random 32 \
            --output-file random.bin
```


## 📥 Reading, Writing and Deleting Data

`pkcs11-tool` provides some object command that could be used to
manage the data object type.

The data identifier is handles with the `--application-id` tool
parameter using OID format.
For the data identifier, the OID must be `1.2.<id>` where `<id>`
is the data identifier in the secure subsystem.

### Write data

**Definition**: Write a data with the content of the input file.

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --write-object <file> \
            --type data \
            --label <label> \
            --application-id 1.2.<id>
```

### Read data

**Definition**: Read a data and display it on the console or
store it in a file if the `--output-file <file>` is specified.

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --read-object \
            --output-file <file> \
            --type data \
            --label <label> \
            --application-id 1.2.<id>
```

### Delete data

**Definition**: Delete a data.

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --delete-object \
            --type data \
            --label <label> \
            --application-id 1.2.<id>
```


# Cryptography Mechanisms Supported

SMW's PKCS11 secure subsystem token target fully depends on the library
subsystem versus operation configuration and the subsystem capabilities.

Please refer to the [User Guide](../user_guide.md) and
the [User API documentation](../../API/SecurityMiddleware_API.pdf), chapters
`Subsystems Capabilities` and `How to write a configuration file`

## Key Generation

| Mechanism Name                | Description                         |
| :---------------------------- | :---------------------------------- |
| `CKM_EC_KEY_PAIR_GEN`         | Elliptic Curve key pair generation. |
| `CKM_RSA_PKCS_KEY_PAIR_GEN`   | RSA key pair generation.            |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Edwards Curve key pair generation.  |
| `CKM_AES_KEY_GEN`             | AES key generation.                 |
| `CKM_DES_KEY_GEN`             | DES key generation.                 |
| `CKM_DES3_KEY_GEN`            | Triple-DES key generation.          |
| `CKM_GENERIC_SECRET_KEY_GEN`  | Generic secret key generation.      |

**Additional NXP Vendor mechanisms**

| Mechanism Name    | Description         | Value      |
| :---------------- | :------------------ | :--------- |
| `CKM_SM4_KEY_GEN` | SM4 key generation. | 0x80534D58 |


## Key Derivation

| Mechanism Name     | Description                                   |
| :----------------- | :-------------------------------------------- |
| `CKM_HKDF_DERIVE`  | HMAC-base key derivation.                     |
| `CKM_ECDH1_DERIVE` | Elliptic Curve Diffie-Hellman key derivation. |


## Digest

| Mechanism Name | Description                 |
| :------------- | :-------------------------- |
| `CKM_MD5`      | MD5 hashing algorithm.      |
| `CKM_SHA_1`    | SHA-1 hashing algorithm.    |
| `CKM_SHA224`   | SHA-224 hashing algorithm.  |
| `CKM_SHA256`   | SHA-256 hashing algorithm.  |
| `CKM_SHA384`   | SHA-384 hashing algorithm.  |
| `CKM_SHA512`   | SHA-512 hashing algorithm.  |
| `CKM_SHA3_224` | SHA3-224 hashing algorithm. |
| `CKM_SHA3_256` | SHA3-256 hashing algorithm. |
| `CKM_SHA3_384` | SHA3-384 hashing algorithm. |
| `CKM_SHA3_512` | SHA3-512 hashing algorithm. |

## MAC Signature

| Mechanism Name              | Description                                                           |
| :-------------------------- | :-------------------------------------------------------------------- |
| `CKM_MD5_HMAC_GENERAL`      | General length MD5 HMAC signature generation and verification.        |
| `CKM_SHA_1_HMAC_GENERAL`    | General length SHA-1 HMAC signature generation and verification.      |
| `CKM_SHA224_HMAC_GENERAL`   | General length SHA224 HMAC signature generation and verification.     |
| `CKM_SHA256_HMAC_GENERAL`   | General length SHA256 HMAC signature generation and verification.     |
| `CKM_SHA384_HMAC_GENERAL`   | General length SHA384 HMAC signature generation and verification.     |
| `CKM_SHA512_HMAC_GENERAL`   | General length SHA512 HMAC signature generation and verification.     |
| `CKM_SHA3_224_HMAC_GENERAL` | General length SHA3-224 HMAC signature generation and verification.   |
| `CKM_SHA3_256_HMAC_GENERAL` | General length SHA3-256 HMAC signature generation and verification.   |
| `CKM_SHA3_384_HMAC_GENERAL` | General length SHA3-384 HMAC signature generation and verification.   |
| `CKM_SHA3_512_HMAC_GENERAL` | General length SH3-512 HMAC signature generation and verification.    |
| `CKM_MD5_HMAC`              | MD5 HMAC signature generation and verification.                       |
| `CKM_SHA_1_HMAC`            | SHA-1 HMAC signature generation and verification.                     |
| `CKM_SHA224_HMAC`           | SHA224 HMAC signature generation and verification.                    |
| `CKM_SHA256_HMAC`           | SHA256 HMAC signature generation and verification.                    |
| `CKM_SHA384_HMAC`           | SHA384 HMAC signature generation and verification.                    |
| `CKM_SHA512_HMAC`           | SHA512 HMAC signature generation and verification.                    |
| `CKM_SHA3_224_HMAC`         | SHA3-224 HMAC signature generation and verification.                  |
| `CKM_SHA3_256_HMAC`         | SHA3-256 HMAC signature generation and verification.                  |
| `CKM_SHA3_384_HMAC`         | SHA3-384 HMAC signature generation and verification.                  |
| `CKM_SHA3_512_HMAC`         | SH3-512 HMAC signature generation and verification.                   |
| `CKM_AES_CMAC_GENERAL`      | General length AES CMAC signature generation and verification.        |
| `CKM_AES_CMAC`              | Full block AES CMAC signature generation and verification.            |
| `CKM_DES3_CMAC_GENERAL`     | General length Triple-DES CMAC signature generation and verification. |
| `CKM_DES3_CMAC`             | Full block Triple-DES CMAC signature generation and verification.     |


## Asymmetric Signature

| Mechanism Name        | Description                                                         |
| :-------------------- | :------------------------------------------------------------------ |
| `CKM_RSA_PKCS`        | PKCS#1 v1.5 RSA signature generation and verification.              |
| `CKM_SHA1_RSA_PKCS`   | SHA-1 with RSA PKCS#1 v1.5 signature generation and verification.   |
| `CKM_SHA224_RSA_PKCS` | SHA-224 with RSA PKCS#1 v1.5 signature generation and verification. |
| `CKM_SHA256_RSA_PKCS` | SHA-256 with RSA PKCS#1 v1.5 signature generation and verification. |
| `CKM_SHA384_RSA_PKCS` | SHA-384 with RSA PKCS#1 v1.5 signature generation and verification. |
| `CKM_SHA512_RSA_PKCS` | SHA-512 with RSA PKCS#1 v1.5 signature generation and verification. |
| `CKM_RSA_PSS`         | PKCS #1 RSA PSS signature generation and verification.              |
| `CKM_SHA1_RSA_PSS`    | SHA-1 with RSA PSS signature generation and verification.           |
| `CKM_SHA224_RSA_PSS`  | SHA-224 with RSA PSS signature generation and verification.         |
| `CKM_SHA256_RSA_PSS`  | SHA-256 with RSA PSS signature generation and verification.         |
| `CKM_SHA384_RSA_PSS`  | SHA-384 with RSA PSS signature generation and verification.         |
| `CKM_SHA512_RSA_PSS`  | SHA-512 with RSA PSS signature generation and verification.         |
| `CKM_ECDSA`           | Elliptic Curve Digital Signature Algorithm any hashing.             |
| `CKM_ECDSA_SHA1`      | ECDSA with SHA-1 hashing.                                           |
| `CKM_ECDSA_SHA224`    | ECDSA with SHA-224 hashing.                                         |
| `CKM_ECDSA_SHA256`    | ECDSA with SHA-256 hashing.                                         |
| `CKM_ECDSA_SHA384`    | ECDSA with SHA-384 hashing.                                         |
| `CKM_ECDSA_SHA512`    | ECDSA with SHA-512 hashing.                                         |
| `CKM_EDDSA`           | Edwards Curve Digital Signature Algorithm any hashing.              |


## Symmetric Encryption

| Mechanism Name | Description                                                                                        |
| :------------- | :------------------------------------------------------------------------------------------------- |
| `CKM_AES_ECB`  | AES encryption/decryption in Electronic CodeBook (ECB) mode.                                       |
| `CKM_AES_CBC`  | AES encryption/decryption in Cipher Block Chaining (CBC) mode.                                     |
| `CKM_AES_CTR`  | AES encryption/decryption in Counter (CTR) mode.                                                   |
| `CKM_AES_CTS`  | AES encryption/decryption in Cipher Text Stealing (CTS) mode.                                      |
| `CKM_AES_XTS`  | AES encryption/decryption in XEX-based Tweaked CodeBook mode with Cipher Text Stealing (XTS) mode. |
| `CKM_DES_ECB`  | DES encryption/decryption in Electronic CodeBook (ECB) mode.                                       |
| `CKM_DES_CBC`  | DES encryption/decryption in Cipher Block Chaining (CBC) mode.                                     |
| `CKM_DES3_ECB` | Triple-DES encryption/decryption in Electronic CodeBook (ECB) mode.                                |
| `CKM_DES3_CBC` | Triple-DES encryption/decryption in Cipher Block Chaining (CBC) mode.                              |


**Additional NXP Vendor mechanisms**

| Mechanism Name | Description                                                    | Value      |
| :------------- | :------------------------------------------------------------- | :--------- |
| `CKM_SM4_ECB`  | SM4 encryption/decryption in Electronic CodeBook (ECB) mode.   | 0x80534D5B |
| `CKM_SM4_CBC`  | SM4 encryption/decryption in Cipher Block Chaining (CBC) mode. | 0x80534D59 |
| `CKM_SM4_CTR`  | SM4 encryption/decryption in Counter (CTR) mode.               | 0x80534D5A |


## Authentication Encryption

| Mechanism Name          | Description                                                                                        |
| :---------------------- | :------------------------------------------------------------------------------------------------- |
| `CKM_AES_CCM`           | AES encryption/decryption in Counter with cipher block chaining message authentication code (CCM). |
| `CKM_AES_GCM`           | AES encryption/decryption in Galois/Counter Mode (GCM).                                            |
| `CKM_CHACHA20_POLY1305` | ChaCha20 stream cipher with the Poly1305 message authentication code.                              |

# PKCS11 APIs Supported

Following table lists all PKCS11 APIs implemented in the SMW's PKCS11 library.

| PKCS11 API            | Supported |
| :-------------------- | :-------: |
| C_Initialize          |    Yes    |
| C_Finalize            |    Yes    |
| C_GetInfo             |    Yes    |
| C_GetFunctionList     |    Yes    |
| C_GetSlotList         |    Yes    |
| C_GetSlotInfo         |    Yes    |
| C_GetTokenInfo        |    Yes    |
| C_GetMechanismList    |    Yes    |
| C_GetMechanismInfo    |    Yes    |
| C_InitToken           |    Yes    |
| C_InitPIN             |  **No**   |
| C_SetPIN              |  **No**   |
| C_OpenSession         |    Yes    |
| C_CloseSession        |    Yes    |
| C_CloseAllSessions    |    Yes    |
| C_GetSessionInfo      |    Yes    |
| C_GetOperationState   |    Yes    |
| C_SetOperationState   |    Yes    |
| C_Login               |    Yes    |
| C_Logout              |    Yes    |
| C_CreateObject        |    Yes    |
| C_CopyObject          |  **No**   |
| C_DestroyObject       |    Yes    |
| C_GetObjectSize       |    Yes    |
| C_GetAttributeValue   |    Yes    |
| C_SetAttributeValue   |    Yes    |
| C_FindObjectsInit     |    Yes    |
| C_FindObjects         |    Yes    |
| C_FindObjectsFinal    |    Yes    |
| C_EncryptInit         |    Yes    |
| C_Encrypt             |    Yes    |
| C_EncryptUpdate       |    Yes    |
| C_EncryptFinal        |    Yes    |
| C_DecryptInit         |    Yes    |
| C_Decrypt             |    Yes    |
| C_DecryptUpdate       |    Yes    |
| C_DecryptFinal        |    Yes    |
| C_DigestInit          |    Yes    |
| C_Digest              |    Yes    |
| C_DigestUpdate        |    Yes    |
| C_DigestKey           |    Yes    |
| C_DigestFinal         |    Yes    |
| C_SignInit            |    Yes    |
| C_Sign                |    Yes    |
| C_SignUpdate          |    Yes    |
| C_SignFinal           |    Yes    |
| C_SignRecoverInit     |  **No**   |
| C_SignRecover         |  **No**   |
| C_VerifyInit          |    Yes    |
| C_Verify              |    Yes    |
| C_VerifyUpdate        |    Yes    |
| C_VerifyFinal         |    Yes    |
| C_VerifyRecoverInit   |  **No**   |
| C_VerifyRecover       |  **No**   |
| C_DigestEncryptUpdate |  **No**   |
| C_DecryptDigestUpdate |  **No**   |
| C_SignEncryptUpdate   |  **No**   |
| C_DecryptVerifyUpdate |  **No**   |
| C_GenerateKey         |    Yes    |
| C_GenerateKeyPair     |    Yes    |
| C_WrapKey             |  **No**   |
| C_UnwrapKey           |  **No**   |
| C_DeriveKey           |    Yes    |
| C_SeedRandom          |  **No**   |
| C_GenerateRandom      |    Yes    |
| C_GetFunctionStatus   |    Yes    |
| C_CancelFunction      |    Yes    |
| C_WaitForSlotEvent    |  **No**   |
| C_GetInterfaceList    |    Yes    |
| C_GetInterface        |    Yes    |
| C_LoginUser           |    Yes    |
| C_SessionCancel       |  **No**   |
| C_MessageEncryptInit  |    Yes    |
| C_EncryptMessage      |    Yes    |
| C_EncryptMessageBegin |    Yes    |
| C_EncryptMessageNext  |    Yes    |
| C_MessageEncryptFinal |    Yes    |
| C_MessageDecryptInit  |    Yes    |
| C_DecryptMessage      |    Yes    |
| C_DecryptMessageBegin |    Yes    |
| C_DecryptMessageNext  |    Yes    |
| C_MessageDecryptFinal |    Yes    |
| C_MessageSignInit     |    Yes    |
| C_SignMessage         |    Yes    |
| C_SignMessageBegin    |    Yes    |
| C_SignMessageNext     |    Yes    |
| C_MessageSignFinal    |    Yes    |
| C_MessageVerifyInit   |    Yes    |
| C_VerifyMessage       |    Yes    |
| C_VerifyMessageBegin  |    Yes    |
| C_VerifyMessageNext   |    Yes    |
| C_MessageVerifyFinal  |    Yes    |


# Best Practices for Using pkcs11-tool

## 🔐 Use the Correct PKCS#11 Module
- Always specify the correct path to your PKCS#11 library using
  `--module /path/to/pkcs11.so`.
- The library name is `libsmw_pkcs11.so.x` (where `x` is the library
  major version) must be present in the system folder `\usr\lib\`.
  For example the SMW library version 5.0 or later version 5.1, 5.2, ..., 5.x
  will have the file (symbol link) `\usr\lib\libsmw_pkcs11.so.5`

## 📋 List and Understand Capabilities
- Use `-L` to list tokens:
  ```sh
  pkcs11-tool --module /path/to/pkcs11.so -L
  ```

  This shows:

  - Label: Human-readable name
  - Manufacturer ID
  - Model
  - Serial number
  - Flags: e.g., login required, token initialized, write protected

- Use '-M' to list supported mechanims:
  ```sh
  pkcs11-tool --module /path/to/pkcs11.so -M
  ```

- Object Capabilities

  Objects (keys, certs) on the token have attributes like:

  - CKA_SIGN: Can be used for signing
  - CKA_ENCRYPT: Can be used for encryption
  - CKA_EXTRACTABLE: Whether the key can be exported (usually false for private keys)
  - CKA_SENSITIVE: Indicates if the key is sensitive

  You can list objects and inspect their attributes with:

  ```sh
  pkcs11-tool --module /path/to/pkcs11.so --login -O
  ```


## 🏷️ Use Consistent Labels and IDs
Assign meaningful --label and --id values when generating keys.
Helps with managing and referencing keys later.


## 🧭 Use Verbose and Debug Options
Add -v or --verbose to get more detailed output when troubleshooting.
