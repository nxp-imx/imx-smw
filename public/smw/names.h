/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __SMW_NAMES_H__
#define __SMW_NAMES_H__

/**
 * typedef smw_subsystem_t - Secure Subsystem name
 *
 * Values:
 * * SMW_SUBSYSTEM_NAME_NONE: No Secure Subsystem specified
 * * SMW_SUBSYSTEM_NAME_TEE: Trusted Execution Envrionment
 * * SMW_SUBSYSTEM_NAME_SECO: SECO
 * * SMW_SUBSYSTEM_NAME_ELE: Edge Lock Enclave
 * * SMW_SUBSYSTEM_NAME_NB: Number of Secure Subsystems
 */
typedef enum {
	SMW_SUBSYSTEM_NAME_NONE,
	SMW_SUBSYSTEM_NAME_TEE,
	SMW_SUBSYSTEM_NAME_SECO,
	SMW_SUBSYSTEM_NAME_ELE,
	SMW_SUBSYSTEM_NAME_NB
} smw_subsystem_t;

/**
 * typedef smw_operation_t - Security Operation name
 *
 * Values:
 * * SMW_OPERATION_NAME_NONE: No operation specified
 * * SMW_OPERATION_NAME_HASH: Hash a message
 * * SMW_OPERATION_NAME_SIGN: Sign a message
 * * SMW_OPERATION_NAME_VERIFY: Verify the signature of a message
 * * SMW_OPERATION_NAME_RNG: Generate a Random Number
 * * SMW_OPERATION_NAME_CIPHER: Cipher encryption or decryption
 * * SMW_OPERATION_NAME_CIPHER_MULTI_PART: Cipher multi-part encryption or decryption
 * * SMW_OPERATION_NAME_MAC: Generate a Message Authentication Code
 * * SMW_OPERATION_NAME_AEAD: Authenticated Encryption with Associated Data
 * * SMW_OPERATION_NAME_AEAD_MULTI_PART: AEAD multi-part
 * * SMW_OPERATION_NAME_AEAD_UPDATE_AAD: Update AEAD Additional Authenticated Data
 * * SMW_OPERATION_NAME_DEVICE_GET_UUID: Get device UUID
 * * SMW_OPERATION_NAME_DEVICE_ATTESTATION: Attest device
 * * SMW_OPERATION_NAME_DEVICE_LIFECYCLE: Get or set Device lifecycle
 * * SMW_OPERATION_NAME_DEVICE_REPROVISION: Prepare or send a device reprovisioning message
 * * SMW_OPERATION_NAME_GENERATE_KEY: Generate a key
 * * SMW_OPERATION_NAME_DERIVE_KEY: Derive a key
 * * SMW_OPERATION_NAME_UPDATE_KEY: Update a key
 * * SMW_OPERATION_NAME_IMPORT_KEY: Import a key
 * * SMW_OPERATION_NAME_EXPORT_KEY: Export a key
 * * SMW_OPERATION_NAME_DELETE_KEY: Delete a key
 * * SMW_OPERATION_NAME_GET_KEY_LENGTHS: Get key length
 * * SMW_OPERATION_NAME_GET_KEY_ATTRIBUTES: Get key atributes
 * * SMW_OPERATION_NAME_COMMIT_KEY_STORAGE: Commit key storage
 * * SMW_OPERATION_NAME_KEY_ATTESTATION: Attest key
 * * SMW_OPERATION_NAME_STORAGE_STORE: Store data
 * * SMW_OPERATION_NAME_STORAGE_RETRIEVE: Retrieve data
 * * SMW_OPERATION_NAME_STORAGE_DELETE: Delete data
 * * SMW_OPERATION_NAME_STORAGE_IS_DATA_PRESENT: Check if data is present in storage
 * * SMW_OPERATION_NAME_STORAGE_GET_DATA_INFO: Get data info
 * * SMW_OPERATION_NAME_NB: Number of operations
 */
typedef enum {
	SMW_OPERATION_NAME_NONE,
	SMW_OPERATION_NAME_HASH,
	SMW_OPERATION_NAME_SIGN,
	SMW_OPERATION_NAME_VERIFY,
	SMW_OPERATION_NAME_RNG,
	SMW_OPERATION_NAME_CIPHER,
	SMW_OPERATION_NAME_CIPHER_MULTI_PART,
	SMW_OPERATION_NAME_MAC,
	SMW_OPERATION_NAME_AEAD,
	SMW_OPERATION_NAME_AEAD_MULTI_PART,
	SMW_OPERATION_NAME_AEAD_UPDATE_AAD,
	SMW_OPERATION_NAME_DEVICE_GET_UUID,
	SMW_OPERATION_NAME_DEVICE_ATTESTATION,
	SMW_OPERATION_NAME_DEVICE_LIFECYCLE,
	SMW_OPERATION_NAME_DEVICE_REPROVISION,
	SMW_OPERATION_NAME_GENERATE_KEY,
	SMW_OPERATION_NAME_DERIVE_KEY,
	SMW_OPERATION_NAME_UPDATE_KEY,
	SMW_OPERATION_NAME_IMPORT_KEY,
	SMW_OPERATION_NAME_EXPORT_KEY,
	SMW_OPERATION_NAME_DELETE_KEY,
	SMW_OPERATION_NAME_GET_KEY_LENGTHS,
	SMW_OPERATION_NAME_GET_KEY_ATTRIBUTES,
	SMW_OPERATION_NAME_COMMIT_KEY_STORAGE,
	SMW_OPERATION_NAME_KEY_ATTESTATION,
	SMW_OPERATION_NAME_STORAGE_STORE,
	SMW_OPERATION_NAME_STORAGE_RETRIEVE,
	SMW_OPERATION_NAME_STORAGE_DELETE,
	SMW_OPERATION_NAME_STORAGE_IS_DATA_PRESENT,
	SMW_OPERATION_NAME_STORAGE_GET_DATA_INFO,
	SMW_OPERATION_NAME_NB
} smw_operation_t;

/**
 * typedef smw_key_type_t - Key type name
 *
 * Values:
 * * SMW_KEY_TYPE_NAME_NONE: No key type specified
 * * SMW_KEY_TYPE_NAME_SECP_R1: ECC Secp R1 key
 * * SMW_KEY_TYPE_NAME_BRAINPOOL_R1: ECC Brainpool R1 key
 * * SMW_KEY_TYPE_NAME_BRAINPOOL_T1: ECC Brainpool T1 key
 * * SMW_KEY_TYPE_NAME_ED25519: Twisted Edwards 25519 key
 * * SMW_KEY_TYPE_NAME_AES: AES key
 * * SMW_KEY_TYPE_NAME_DES: DES key
 * * SMW_KEY_TYPE_NAME_DES3: Triple DES key
 * * SMW_KEY_TYPE_NAME_DSA_SM2_FP: DSA SM2 key
 * * SMW_KEY_TYPE_NAME_SM4:  SM4 key
 * * SMW_KEY_TYPE_NAME_HMAC: HMAC key
 * * SMW_KEY_TYPE_NAME_RSA: RSA key
 * * SMW_KEY_TYPE_NAME_DH: DH key
 * * SMW_KEY_TYPE_NAME_TLS_MASTER: TLS master key
 * * SMW_KEY_TYPE_NAME_RAW: Raw key
 * * SMW_KEY_TYPE_NAME_NB: Number of key types
 */
typedef enum {
	SMW_KEY_TYPE_NAME_NONE,
	SMW_KEY_TYPE_NAME_SECP_R1,
	SMW_KEY_TYPE_NAME_BRAINPOOL_R1,
	SMW_KEY_TYPE_NAME_BRAINPOOL_T1,
	SMW_KEY_TYPE_NAME_ED25519,
	SMW_KEY_TYPE_NAME_AES,
	SMW_KEY_TYPE_NAME_DES,
	SMW_KEY_TYPE_NAME_DES3,
	SMW_KEY_TYPE_NAME_DSA_SM2_FP,
	SMW_KEY_TYPE_NAME_SM4,
	SMW_KEY_TYPE_NAME_HMAC,
	SMW_KEY_TYPE_NAME_RSA,
	SMW_KEY_TYPE_NAME_DH,
	SMW_KEY_TYPE_NAME_TLS_MASTER,
	SMW_KEY_TYPE_NAME_RAW,
	SMW_KEY_TYPE_NAME_GENERIC_SECRET,
	SMW_KEY_TYPE_NAME_NB
} smw_key_type_t;

/**
 * typedef smw_key_privacy_t - Key privacy name
 *
 * Values:
 * * SMW_KEY_PRIVACY_NAME_NONE: No key privacy specified
 * * SMW_KEY_PRIVACY_NAME_PUBLIC: Public key
 * * SMW_KEY_PRIVACY_NAME_PRIVATE: Private key
 * * SMW_KEY_PRIVACY_NAME_PAIR: Key pair
 * * SMW_KEY_PRIVACY_NAME_SHARED_SECRET: Shared secret
 * * SMW_KEY_PRIVACY_NAME_NB: Number of key privacies
 */
typedef enum {
	SMW_KEY_PRIVACY_NAME_NONE,
	SMW_KEY_PRIVACY_NAME_PUBLIC,
	SMW_KEY_PRIVACY_NAME_PRIVATE,
	SMW_KEY_PRIVACY_NAME_PAIR,
	SMW_KEY_PRIVACY_NAME_SHARED_SECRET,
	SMW_KEY_PRIVACY_NAME_NB
} smw_key_privacy_t;

/**
 * typedef smw_hash_algo_t - Hash algorithm name
 *
 * Values:
 * * SMW_HASH_ALGO_NAME_NONE: No hash algorithm specified
 * * SMW_HASH_ALGO_NAME_MD5: Message Digest 5
 * * SMW_HASH_ALGO_NAME_SHA1: Secure Hash Algorithm 1
 * * SMW_HASH_ALGO_NAME_SHA224: Secure Hash Algorithm 2, 224 bits
 * * SMW_HASH_ALGO_NAME_SHA256: Secure Hash Algorithm 2, 256 bits
 * * SMW_HASH_ALGO_NAME_SHA384: Secure Hash Algorithm 2, 384 bits
 * * SMW_HASH_ALGO_NAME_SHA512: Secure Hash Algorithm 2, 512 bits
 * * SMW_HASH_ALGO_NAME_SHA3_224: Secure Hash Algorithm 3, 224 bits
 * * SMW_HASH_ALGO_NAME_SHA3_256: Secure Hash Algorithm 3, 256 bits
 * * SMW_HASH_ALGO_NAME_SHA3_384: Secure Hash Algorithm 3, 384 bits
 * * SMW_HASH_ALGO_NAME_SHA3_512: Secure Hash Algorithm 3, 512 bits
 * * SMW_HASH_ALGO_NAME_SM3: ShangMi 3
 * * SMW_HASH_ALGO_NAME_NB: Number of Hash algorithms
 */
typedef enum {
	SMW_HASH_ALGO_NAME_NONE,
	SMW_HASH_ALGO_NAME_MD5,
	SMW_HASH_ALGO_NAME_SHA1,
	SMW_HASH_ALGO_NAME_SHA224,
	SMW_HASH_ALGO_NAME_SHA256,
	SMW_HASH_ALGO_NAME_SHA384,
	SMW_HASH_ALGO_NAME_SHA512,
	SMW_HASH_ALGO_NAME_SHA3_224,
	SMW_HASH_ALGO_NAME_SHA3_256,
	SMW_HASH_ALGO_NAME_SHA3_384,
	SMW_HASH_ALGO_NAME_SHA3_512,
	SMW_HASH_ALGO_NAME_SM3,
	SMW_HASH_ALGO_NAME_NB
} smw_hash_algo_t;

/**
 * typedef smw_mac_algo_t - MAC algorithm name
 *
 * Values:
 * * SMW_MAC_ALGO_NAME_NONE: No Message Authentication Code algorithm specified
 * * SMW_MAC_ALGO_NAME_CMAC: Cipher-based Message Authentication Code algorithm
 * * SMW_MAC_ALGO_NAME_CMAC_TRUNCATED: Cipher-based Message Authentication Code truncated algorithm
 * * SMW_MAC_ALGO_NAME_HMAC: Hash-Based Message Authentication Code algorithm
 * * SMW_MAC_ALGO_NAME_HMAC_TRUNCATED: Hash-Based Message Authentication Code truncated algorithm
 * * SMW_MAC_ALGO_NAME_NB: Number of Message Authentication Code algorithms
 */
typedef enum {
	SMW_MAC_ALGO_NAME_NONE,
	SMW_MAC_ALGO_NAME_CMAC,
	SMW_MAC_ALGO_NAME_CMAC_TRUNCATED,
	SMW_MAC_ALGO_NAME_HMAC,
	SMW_MAC_ALGO_NAME_HMAC_TRUNCATED,
	SMW_MAC_ALGO_NAME_NB
} smw_mac_algo_t;

/**
 * typedef smw_cipher_mode_t - Cipher mode name
 *
 * Values:
 * * SMW_CIPHER_MODE_NAME_NONE: No cipher mode specified
 * * SMW_CIPHER_MODE_NAME_CBC: Cipher Block Chaining mode
 * * SMW_CIPHER_MODE_NAME_CFB: Cipher Feedback Block mode
 * * SMW_CIPHER_MODE_NAME_CTR: Counter mode
 * * SMW_CIPHER_MODE_NAME_CTS: Ciphertext Stealing mode
 * * SMW_CIPHER_MODE_NAME_ECB: Electronic Codebook Block mode
 * * SMW_CIPHER_MODE_NAME_XTS: XEX Tweakable Block Cipher with Ciphertext Stealing mode
 * * SMW_CIPHER_MODE_NAME_NB: Number of cipher modes
 */
typedef enum {
	SMW_CIPHER_MODE_NAME_NONE,
	SMW_CIPHER_MODE_NAME_CBC,
	SMW_CIPHER_MODE_NAME_CFB,
	SMW_CIPHER_MODE_NAME_CTR,
	SMW_CIPHER_MODE_NAME_CTS,
	SMW_CIPHER_MODE_NAME_ECB,
	SMW_CIPHER_MODE_NAME_XTS,
	SMW_CIPHER_MODE_NAME_NB
} smw_cipher_mode_t;

/**
 * typedef smw_aead_mode_t - AEAD mode name
 *
 * Values:
 * * SMW_AEAD_MODE_NAME_NONE: No AEAD mode specficied
 * * SMW_AEAD_MODE_NAME_CCM: Counter with CBC-MAC mode
 * * SMW_AEAD_MODE_NAME_GCM: Galois Counter Mode
 * * SMW_AEAD_MODE_NAME_CHACHA20_POLY1305: ChaCha20 stream cipher with Poly1305 MAC mode
 * * SMW_AEAD_MODE_NAME_NB: Number of AEAD modes
 */
typedef enum {
	SMW_AEAD_MODE_NAME_NONE,
	SMW_AEAD_MODE_NAME_CCM,
	SMW_AEAD_MODE_NAME_GCM,
	SMW_AEAD_MODE_NAME_CHACHA20_POLY1305,
	SMW_AEAD_MODE_NAME_NB

} smw_aead_mode_t;

/**
 * typedef smw_cipher_op_type_t - Cipher operation type name
 *
 * Values:
 * * SMW_CIPHER_OP_TYPE_NAME_NONE: No cipher operation type specified
 * * SMW_CIPHER_OP_TYPE_NAME_ENCRYPT: Encrypt operation type
 * * SMW_CIPHER_OP_TYPE_NAME_DECRYPT: Decrypt operation type
 * * SMW_CIPHER_OP_TYPE_NAME_NB: Number of cipher operation types
 */
typedef enum {
	SMW_CIPHER_OP_TYPE_NAME_NONE,
	SMW_CIPHER_OP_TYPE_NAME_ENCRYPT,
	SMW_CIPHER_OP_TYPE_NAME_DECRYPT,
	SMW_CIPHER_OP_TYPE_NAME_NB

} smw_cipher_op_type_t;

/**
 * typedef smw_aead_op_type_t - AEAD operation type name
 *
 * Values:
 * * SMW_AEAD_OP_TYPE_NAME_NONE: No AEAD operation specified
 * * SMW_AEAD_OP_TYPE_NAME_ENCRYPT: AEAD encrypt operation
 * * SMW_AEAD_OP_TYPE_NAME_DECRYPT: AEAD decrypt operation
 * * SMW_AEAD_OP_TYPE_NAME_NB: Number of AEAD operations
 */
typedef enum {
	SMW_AEAD_OP_TYPE_NAME_NONE,
	SMW_AEAD_OP_TYPE_NAME_ENCRYPT,
	SMW_AEAD_OP_TYPE_NAME_DECRYPT,
	SMW_AEAD_OP_TYPE_NAME_NB

} smw_aead_op_type_t;

#endif /* __SMW_NAMES_H__ */
