/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __SMW_STRINGS_H__
#define __SMW_STRINGS_H__

typedef const char *smw_string_t;

/**
 * typedef smw_subsystem_t - Subsystem name
 * Values:
 *	- TEE
 *	- HSM
 */
typedef smw_string_t smw_subsystem_t;

/**
 * typedef smw_key_type_t - Key type name
 * Values:
 *	- NIST
 *	- BRAINPOOL_R1
 *	- BRAINPOOL_T1
 *	- AES
 *	- DES
 *	- DES3
 *	- DSA_SM2_FP
 *	- SM4
 *	- HMAC_MD5
 *	- HMAC_SHA1
 *	- HMAC_SHA224
 *	- HMAC_SHA256
 *	- HMAC_SHA384
 *	- HMAC_SHA512
 *	- HMAC_SM3
 *	- RSA
 */
typedef smw_string_t smw_key_type_t;

/**
 * typedef smw_hash_algo_t - Hash algorithm name
 * Values:
 *	- MD5
 *	- SHA1
 *	- SHA224
 *	- SHA256
 *	- SHA384
 *	- SHA512
 *	- SM3
 */
typedef smw_string_t smw_hash_algo_t;

/**
 * typedef smw_cipher_mode_t - Cipher mode name
 * Values:
 *	- CBC
 *	- CCM
 *	- CTR
 *	- CTS
 *	- ECB
 *	- GCM
 *	- XTS
 */
typedef smw_string_t smw_cipher_mode_t;

/**
 * typedef smw_cipher_operation_t - Cipher operation name
 * Values:
 *	- ENCRYPT
 *	- DECRYPT
 */
typedef smw_string_t smw_cipher_operation_t;

/**
 * typedef smw_key_format_t - Key format name
 * Values:
 *	- HEX: hexadecimal value (no encoding)
 *	- BASE64: base 64 encoding value
 */
typedef smw_string_t smw_key_format_t;

/**
 * typedef smw_attribute_type_t - Attribute type name
 *
 * An attribute is encoded with a Type-Length-Value (TLV) format.
 * Function of the attribute type, the TLV scheme varies.
 * Refer to :doc:`/tlv/tlv`
 *
 * Key Manager attributes:
 *
 * The following :numref:`key_manager_attributes` lists all TLV attributes
 * supported by key manager operations like generate, import, derive, delete.
 *
 * .. table:: Key manager attributes
 *    :name: key_manager_attributes
 *    :align: center
 *    :widths: 25 14 62
 *    :width: 100%
 *    :class: wrap-table
 *
 *    +-----------------+--------------+---------------------------------------+
 *    | **Type Value**  | **Encoding** | **Description**                       |
 *    +=================+==============+=======================================+
 *    | PERSISTENT      | boolean      | If present key is persistent.         |
 *    +-----------------+--------------+---------------------------------------+
 *    | RSA_PUB_EXP     | numeral      | Setup the RSA Public exponent value.  |
 *    |                 |              | The default value is 65537 if this    |
 *    |                 |              | attribute is not defined.             |
 *    +-----------------+--------------+---------------------------------------+
 *    | FLUSH_KEY       | boolean      | If present, ensure that the key       |
 *    |                 |              | storage is up to date.                |
 *    +-----------------+--------------+---------------------------------------+
 *
 * Signature attributes:
 *
 * The following :numref:`signature_attributes` lists all TLV attributes
 * supported by sign and verify operations.
 *
 * .. table:: Signature attributes
 *    :name: signature_attributes
 *    :align: center
 *    :widths: 25 14 62
 *    :width: 100%
 *    :class: wrap-table
 *
 *    +-----------------+--------------+---------------------------------------+
 *    | **Type Value**  | **Encoding** | **Description**                       |
 *    +=================+==============+=======================================+
 *    | SIGNATURE_TYPE  | string       | Define the type of signature in case  |
 *    |                 |              | multiple options are possible.        |
 *    |                 |              | Otherwise the signature type is       |
 *    |                 |              | function of the key type.             |
 *    |                 |              | Refer to `smw_signature_type_t`_      |
 *    |                 |              | to get the possible attribute value.  |
 *    +-----------------+--------------+---------------------------------------+
 *    | SALT_LENGTH     | string       | If signature is RSASSA-PSS, set the   |
 *    |                 |              | salt length of the signature.         |
 *    +-----------------+--------------+---------------------------------------+
 *    | TLS_MAC_FINISH  | string       | Define the TLS finish message         |
 *    |                 |              | signature type to generate. Value is  |
 *    |                 |              | either "CLIENT" or "SERVER"           |
 *    |                 |              | corresponding to client or server     |
 *    |                 |              | finish signature.                     |
 *    +-----------------+--------------+---------------------------------------+
 *
 */
typedef smw_string_t smw_attribute_type_t;

/**
 * typedef smw_signature_type_t - Signature type name
 * Values:
 *	- DEFAULT
 *	- RSASSA-PKCS1-V1_5
 *	- RSASSA-PSS
 */
typedef smw_string_t smw_signature_type_t;

/**
 * typedef smw_kdf_t - Key derivation function name
 * Values:
 *	- TLS12_KEY_EXCHANGE
 */
typedef smw_string_t smw_kdf_t;

/**
 * typedef smw_tls12_kea_t - TLS 1.2 Key exchange algorithm name
 * Values:
 *	- DH_DSS
 *	- DH_RSA
 *	- DHE_DSS
 *	- DHE_RSA
 *	- ECDH_ECDSA
 *	- ECDH_RSA
 *	- ECDHE_ECDSA
 *	- ECDHE_RSA
 *	- RSA
 */
typedef smw_string_t smw_tls12_kea_t;

/**
 * typedef smw_tls12_enc_t - TLS 1.2 encryption algorithm name
 * Values:
 *	- 3DES_EDE_CBC
 *	- AES_128_CBC
 *	- AES_128_GCM
 *	- AES_256_CBC
 *	- AES_256_GCM
 *	- RC4_128
 */
typedef smw_string_t smw_tls12_enc_t;

#endif /* __SMW_STRINGS_H__ */
