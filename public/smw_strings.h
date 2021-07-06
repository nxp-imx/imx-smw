/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
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
 * Values:
 *	- PERSISTENT
 *	- SIGNATURE_TYPE
 *	- RSA_PUB_EXP
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
 * typedef smw_kdf_name_t - Key derivation function name
 * Values:
 *	- TLS12_KEY_EXCHANGE
 */
typedef smw_string_t smw_kdf_t;

/**
 * typedef smw_tls12_kea_name_t - TLS 1.2 Key exchange algorithm name
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
 * typedef smw_tls12_enc_name_t - TLS 1.2 encryption algorithm name
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
