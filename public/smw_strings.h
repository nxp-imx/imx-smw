/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#ifndef __SMW_STRINGS_H__
#define __SMW_STRINGS_H__

typedef const char *smw_string_t;

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
