# TLS Connection Setup with OpenSSL and PKCS#11 Provider <!-- omit in toc -->

# Table of Content <!-- omit in toc -->

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Limitations](#limitations)
  - [Supported TLS private EC key curves](#supported-tls-private-ec-key-curves)
    - [Elliptic curves](#elliptic-curves)
    - [Edwards curves](#edwards-curves)
    - [Montgomery curves](#montgomery-curves)
  - [Supported algorithms](#supported-algorithms)
    - [TLS 1.2 supported cipher suites](#tls-12-supported-cipher-suites)
    - [TLS 1.3 supported cipher suites](#tls-13-supported-cipher-suites)
  - [Known issues](#known-issues)
    - [pkcs11-tool URI encoding limitation](#pkcs11-tool-uri-encoding-limitation)
    - [TLS groups for key exchange](#tls-groups-for-key-exchange)
- [TLS using ECDSA Key](#tls-using-ecdsa-key)
  - [Create the ECDSA Certificate and Key](#create-the-ecdsa-certificate-and-key)
- [TLS using EdDSA Key](#tls-using-eddsa-key)
  - [Create the EdDSA Certificate and Key](#create-the-eddsa-certificate-and-key)
- [Create a TLS Server CSR](#create-a-tls-server-csr)
- [TLS Server Certificate Signing](#tls-server-certificate-signing)
  - [Step 1: Create a Private CA Certificate](#step-1-create-a-private-ca-certificate)
  - [Step 2: Self-Sign the CA Certificate](#step-2-self-sign-the-ca-certificate)
  - [Step 3: Sign the Server Certificate with the Private CA](#step-3-sign-the-server-certificate-with-the-private-ca)
- [Start TLS Server](#start-tls-server)
  - [Without verifying client certificates](#without-verifying-client-certificates)
  - [Request a client certificates chain](#request-a-client-certificates-chain)
- [TLS client key and certificate creation option](#tls-client-key-and-certificate-creation-option)
  - [Step 1: Generate client private key](#step-1-generate-client-private-key)
  - [Step 2: Create client CSR for TLS authentication](#step-2-create-client-csr-for-tls-authentication)
  - [Step 3: Self Sign the client certificate with the private CA](#step-3-self-sign-the-client-certificate-with-the-private-ca)
- [Test TLS 1.2 Connection](#test-tls-12-connection)
- [Test TLS 1.3 Connection](#test-tls-13-connection)
- [Examples](#examples)
  - [Offloading server to i.MX Secure Enclave (mutual authentication)](#offloading-server-to-imx-secure-enclave-mutual-authentication)
  - [Offloading client to i.MX Secure Enclave (mutual authentication)](#offloading-client-to-imx-secure-enclave-mutual-authentication)
  - [Client Self-signed certificate i.MX Secure Enclave](#client-self-signed-certificate-imx-secure-enclave)
    - [Step 1: Generate CA private key in i.MX Secure Enclave](#step-1-generate-ca-private-key-in-imx-secure-enclave)
    - [Step 2: Self-Sign the CA Certificate](#step-2-self-sign-the-ca-certificate-1)
    - [Step 3: Self Sign the client certificate with the private CA](#step-3-self-sign-the-client-certificate-with-the-private-ca-1)
- [References](#references)

# Overview
This document outlines the steps to establish TLS 1.2 and TLS 1.3 connections using OpenSSL with the PKCS#11 provider, leveraging ECDSA and EdDSA keys.

# Prerequisites

Before using `openssl`, ensure the following:

- OpenSSL 3.4.2 is installed 
- You have installed the `pkcs11-tool` utility (usually part of the
  [OpenSC](https://github.com/OpenSC/OpenSC/wiki) package).
- You have installed the **NXP** PKCS#11 provider 1.0 module from
  [pkcs11-provider](https://github.com/nxp-imx/pkcs11-provider)
- Ensure that SMW's PKCS11 library is installed on your system. The shared
  library file `libsmw_pkcs11.so.x.y` (where `x.y` is the library major.minor
  version)  must be present in the system folder usually `/usr/lib/`.
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

# Environment Setup

To simplify the command line, the following environment variable can be defined
to refer on the SMW's PKCS11 library. In this documentation, we assume that the
library is present in the system folder `/usr/lib/`.

```sh
export MODULE_PKCS11=/usr/lib/libsmw_pkcs11.so.5
```

Same for the PKCS11 module environment variables, we can define a variable to simplify
the OpenSSL configuration file:

```sh
export PKCS11_PROVIDER=/usr/lib/ossl-modules/pkcs11.so
export PKCS11_MODULE_PATH=/usr/lib/libsmw_pkcs11.so.5
```

Finally, configure the OpenSSL environment to recognize the PKCS11 provider:
To do so, copy `/etc/ssl/openssl.cnf` to `/etc/ssl/openssl-pkcs11.cnf` and
add the following sections to the `openssl-pkcs11.cnf` file:

```ini
[openssl_init]
ssl_conf = ssl_module
providers = provider_sect
alg_section = algorithm_sect

[ssl_module]
system_default = tls_system_default

[tls_system_default]
Groups = secp521r1:secp384r1:prime256v1

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = ${PKCS11_PROVIDER}
pkcs11-module-path = ${PKCS11_MODULE_PATH}
pkcs11-module-cache-keys = false
pkcs11-module-quirks = no-operation-state
pkcs11-module-login-behavior = always
pkcs11-module-block-operations = digest
activate = 1

[algorithm_sect]
default_properties = ?provider=pkcs11
```

It is recommended to create a specific OpenSSL configuration file to enable the PKCS11 provider.
You will have to set the `OPENSSL_CONF` environment variable to point to this configuration file.

```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl req -new \
            -sha256 \
            -key "pkcs11:token=smw;id=%01;object=server-key;type=private" \
            -out server-cert.csr \
            -subj "/O=NXP-server-cert/CN=NXP-CN_server-cert/emailAddress=nxp-server-cert@nxp-test.com"
```

# Limitations
Only following EC keys are supported for certificate generation and TLS connections.
## Supported TLS private EC key curves
### Elliptic curves
- prime256v1
- secp384r1
### Edwards curves
- edwards25519
- edwards448
### Montgomery curves
- x25519
- x448

⚠️ These are supported only with TLS 1.3.

pkcs11-provider added support for these curves in the [1.2 release](https://github.com/latchset/pkcs11-provider/milestone/2).

## Supported algorithms
### TLS 1.2 supported cipher suites
- ECDHE-ECDSA-AES128-SHA256
- ECDHE-ECDSA-AES256-SHA384
- ECDHE-ECDSA-AES128-GCM-SHA256
- ECDHE-ECDSA-AES256-GCM-SHA384
- ECDHE-ECDSA-CHACHA20-POLY1305

### TLS 1.3 supported cipher suites
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

## Known issues

### pkcs11-tool URI encoding limitation

`pkcs11-tool` uri encoding fail to encode id bigger than `0xff`
As specified in [PKCS#11 URI Scheme](https://datatracker.ietf.org/doc/html/rfc7512)
The value of the attribute "id" MUST be compared using the simple
string comparison after **all bytes** are percent-encoded using
uppercase letters for digits A-F (i.e. `0x102` is encoded as `%01%02`).

### TLS groups for key exchange

Typically, both the `pkcs11` and the `default` providers are loaded, as is the example
configuration file in [Environment Setup](#environment-setup). OpenSSL gathers all the
supported algorithms from both providers, and may negociate an algorithm that is only
supported by the `default` provider, leading to failures because the result of the key
exchange cannot be used by the `pkcs11` provider. To avoid this, make sure the list of
TLS groups only includes the supported algorithms.

The example configuration file includes all the supported groups with both TLS 1.2 and
TLS 1.3.

# TLS using ECDSA Key
## Create the ECDSA Certificate and Key

Generate a private key on your server system,
Please refer to the [pkcs11-tool documentation](../pkcs11/pkcs11_tool_user_guide.md) for detailed key generation options.
For example:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type EC:prime256v1 \
            --id 01 \
            --label "server-key" \
            --usage-sign \
            --allowed-mechanisms "ECDSA-SHA256"
```

# TLS using EdDSA Key
⚠️ EdDSA is not supported in TLS 1.2. Use TLS 1.3 instead.

## Create the EdDSA Certificate and Key

Generate a private key on your server system,
Please refer to the [pkcs11-tool documentation](../pkcs11/pkcs11_tool_user_guide.md) for detailed key generation options.
For example:

```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type EC:edwards25519 \
            --id 01 \
            --label "server-key" \
            --usage-sign \
            --allowed-mechanisms "EDDSA"
```
# Create a TLS Server CSR

You can use a text editor to prepare a configuration file that simplifies creating your CSR, for example:

```sh
$ vim <example_server.cnf>
[server-cert]
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_name

[req]
distinguished_name = dn
prompt = no

[dn]
C = <US>
O = <Example Organization>
CN = <server.example.com>
```

Create a CSR using the private key you created previously:

```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl req -new \
            -sha256 \
            -key "pkcs11:token=smw;id=%01;object=server-key;type=private" \
            -out server-cert.csr \
            -config <example_server.cnf>
```

# TLS Server Certificate Signing

Submit the CSR to a CA of your choice for signing.
Alternatively, for an internal use within a trusted network, use your private CA for signing.

## Step 1: Create a Private CA Certificate

For example, using an ECDSA with prime256v1 curve for the CA certificate.

```sh
openssl ecparam -name prime256v1 \
                -genkey \
                -noout \
                -out ca.key
```

## Step 2: Self-Sign the CA Certificate

The generated ca.crt file is a self-signed CA certificate that you can use to sign other certificates for ten years. In the case of a private CA, you can replace <Example_CA> with any string as the common name (CN).

```sh
openssl req -new \
            -x509 \
            -key ca.key \
            -days 365 \
            -subj "/CN=<Example_CA>" \
            -out ca.crt
```

To use a self-signed CA certificate as a trust anchor on client systems, copy the CA certificate to the client and add it to the client's system-wide truststore as `root`.

## Step 3: Sign the Server Certificate with the Private CA

```sh
openssl x509 -req \
             -in server-cert.csr \
             -CA ca.crt \
             -CAkey ca.key \
             -CAcreateserial \
             -out server-cert.crt \
             -days 1000
```

# Start TLS Server

## Without verifying client certificates
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_server \
  -accept 443 \
  -cert server-cert.crt \
  -key "pkcs11:token=smw;id=%01;object=server-key;type=private"
```

## Request a client certificates chain
For example with the -Verify 3 option below, the client must supply a certificate chain that is verified until depth 3 is reached.

```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_server \
  -accept 443 \
  -Verify 3 \
  -cert server-cert.crt \
  -key "pkcs11:token=smw;id=%01;object=server-key;type=private"
```

# TLS client key and certificate creation option

Create a client certificate and key using ECDSA or EdDSA for TLS authentication as done for server certificate and key.

For example, using ECDSA with prime256v1 curve:

## Step 1: Generate client private key
```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type EC:prime256v1 \
            --id 01 \
            --label "client-key" \
            --usage-sign \
            --allowed-mechanisms "ECDSA-SHA256"
```

## Step 2: Create client CSR for TLS authentication
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl req -new \
            -sha256 \
            -key "pkcs11:token=smw;id=%01;object=client-key;type=private" \
            -out client-cert.csr \
            -config <example_server.cnf>
```

## Step 3: Self Sign the client certificate with the private CA
```sh
openssl x509 -req \
             -in client-cert.csr \
             -CA ca.crt \
             -CAkey ca.key \
             -CAcreateserial \
             -out client-cert.crt \
             -days 1000
```     

# Test TLS 1.2 Connection

```sh
# Test TLS 1.2 Connection with client authentication and specific cipher suites
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_2 \
  -cipher "ECDHE-ECDSA-AES128-GCM-SHA256" \
  -key "pkcs11:token=smw;id=%01;object=client-key;type=private" \
  -cert client-cert.crt \
  -CAfile ca.crt
```

```sh
# Test TLS 1.2 Connection with specific cipher suites
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_2 \
  -cipher "ECDHE-ECDSA-AES128-GCM-SHA256" \
  -CAfile ca.crt
```

# Test TLS 1.3 Connection

```sh
# Test TLS 1.3 Connection with client authentication and specific cipher suites
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_3 \
  -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" \
  -key "pkcs11:token=smw;id=%01;object=client-key;type=private" \
  -cert client-cert.crt \
  -CAfile ca.crt
```

```sh
# Test TLS 1.3 Connection with specific cipher suites
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_3 \
  -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" \
  -CAfile ca.crt
```

# Examples

## Offloading server to i.MX Secure Enclave (mutual authentication)
Server TLS handshake and message exchange keys are offloaded in the i.MX Secure Enclave by interfacing OpenSSL to SMW's PKCS11 library. TLS encryption and signature are done by i.MX Secure Enclave.

On the i.MX, after doing the [TLS Server Certificate Signing](#tls-server-certificate-signing) steps, start the TLS server with the private key stored in the i.MX Secure Enclave:
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_server \
  -accept 443 \
  -Verify 3 \
  -cert server-cert.crt \
  -key "pkcs11:token=smw;id=%01;object=server-key;type=private"
```

## Offloading client to i.MX Secure Enclave (mutual authentication)
Client TLS handshake and message exchange keys are offloaded in the i.MX Secure Enclave by interfacing OpenSSL to SMW's PKCS11 library. TLS encryption and signature are done by i.MX Secure Enclave.

On the i.MX, after doing the [TLS Client Certificate Signing](#tls-client-key-and-certificate-creation-option) steps, start the TLS client with this private key with the following command:
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_3 \
  -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" \
  -key "pkcs11:token=smw;id=%01;object=client-key;type=private" \
  -cert client-cert.crt \
  -CAfile ca.crt
```

## Client Self-signed certificate i.MX Secure Enclave
In this case, the client self-signed certificate is signed with a i.MX Secure Enclave key to authenticate the client. OpenSSL is managing/handling all other TLS connection keys required for the handshake and client/server exchange.

###  Step 1: Generate CA private key in i.MX Secure Enclave
```sh
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type EC:prime256v1 \
            --label "ca-key" \
            --id 02 \
            --usage-sign \
            --allowed-mechanisms "ECDSA-SHA256"
```

### Step 2: Self-Sign the CA Certificate
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl req -new \
            -x509 \
            -key "pkcs11:token=smw;id=%02;object=ca-key;type=private" \
            -days 365 \
            -subj "/CN=<Example_CA>" \
            -out ca.crt
```

### Step 3: Self Sign the client certificate with the private CA
Use the client CSR created in [Step 2: Create client CSR for TLS authentication](#step-2-create-client-csr-for-tls-authentication):

```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl x509 -req \
             -in client-cert.csr \
             -CA ca.crt \
             -CAkey "pkcs11:token=smw;id=%02;object=ca-key;type=private" \
             -CAcreateserial \
             -out client-cert-self-signed.crt \
             -days 1000
```

Then start the TLS client with this private key and self signed certificate with the following command:
```sh
OPENSSL_CONF=/etc/ssl/openssl-pkcs11.cnf openssl s_client \
  -connect example.com:443 \
  -tls1_3 \
  -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" \
  -key "pkcs11:token=smw;id=%01;object=client-key;type=private" \
  -cert client-cert-self-signed.crt \
  -CAfile ca.crt
```


# References
- [OpenSSL Documentation](https://docs.openssl.org/3.0/man1/)
- [PKCS#11 URI Scheme](https://datatracker.ietf.org/doc/html/rfc7512)
- [pkcs11-tool documentation](../pkcs11/pkcs11_tool_user_guide.md)
