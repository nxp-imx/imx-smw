/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#ifndef __SMW_STRINGS_H__
#define __SMW_STRINGS_H__

typedef const char *smw_string_t;

/**
 * typedef smw_key_type_t - Key type name
 * Values:
 *	- NIST
 *	- BRAINPOOL_R1
 *	- BRAINPOOL_T1
 *	- ED25519
 *	- AES
 *	- DES
 *	- DES3
 *	- DH
 *	- DSA_SM2_FP
 *	- SM4
 *	- HMAC
 *	- HMAC_MD5
 *	- HMAC_SHA1
 *	- HMAC_SHA224
 *	- HMAC_SHA256
 *	- HMAC_SHA384
 *	- HMAC_SHA512
 *	- HMAC_SM3
 *	- RAW
 *	- RSA
 *	- TLS_MASTER_KEY
 */
typedef smw_string_t smw_key_type_t;

/**
 * typedef smw_key_privacy_t - Key privacy name
 * Values:
 *	- PUBLIC
 *	- PRIVATE
 *	- KEYPAIR
 */
typedef smw_string_t smw_key_privacy_t;

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
 * typedef smw_mac_algo_t - MAC algorithm name
 * Values:
 *	- CMAC
 *	- CMAC_TRUNCATED
 *	- HMAC
 *	- HMAC_TRUNCATED
 */
typedef smw_string_t smw_mac_algo_t;

/**
 * typedef smw_cipher_mode_t - Cipher mode name
 * Values:
 *	- CBC
 *	- CFB
 *	- CTR
 *	- CTS
 *	- ECB
 *	- XTS
 */
typedef smw_string_t smw_cipher_mode_t;
/**
 * typedef smw_aead_mode_t - AEAD mode name
 * Values:
 *	- CCM
 *	- CHACHA20_POLY1305
 *	- GCM
 */
typedef smw_string_t smw_aead_mode_t;

/**
 * typedef smw_cipher_operation_t - Cipher operation name
 * Values:
 *	- ENCRYPT
 *	- DECRYPT
 */
typedef smw_string_t smw_cipher_operation_t;

/**
 * typedef smw_aead_operation_t - AEAD operation name
 * Values:
 *	- ENCRYPT
 *	- DECRYPT
 */
typedef smw_string_t smw_aead_operation_t;

/**
 * typedef smw_key_format_t - Key format name
 * Values:
 *	- HEX: hexadecimal value (no encoding)
 *	- BASE64: base 64 encoding value
 */
typedef smw_string_t smw_key_format_t;

/**
 * typedef smw_signature_algo_t - Signature main algo name
 * Values:
 *	- DEFAULT
 *	- ECDSA
 *	- EDDSA
 *	- DSA
 *	- RSA
 *	- TLS_1_2
 */
typedef smw_string_t smw_signature_algo_t;

/**
 * typedef smw_signature_type_t - Signature type name
 * Values:
 *	- DEFAULT
 *	- PKCS1_1_5
 *	- PSS
 *	- CLIENT
 *	- SERVER
 *	- CMAC
 */
typedef smw_string_t smw_signature_type_t;

/**
 * typedef smw_kdf_t - Key derivation function name
 * Values:
 *	- TLS12_KEY_EXCHANGE
 *	- HKDF
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

/**
 * typedef smw_lifecycle_t - Device lifecycle name
 * Values:
 *	- OPEN
 *	- CLOSED
 *	- CLOSED_LOCKED
 *	- OEM_RETURN
 *	- NXP_RETURN
 */
typedef smw_string_t smw_lifecycle_t;

#endif /* __SMW_STRINGS_H__ */
