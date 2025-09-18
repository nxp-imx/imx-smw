/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
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
 * * SMW_OPERATION_NAME_STORAGE_GET_DATA_INFO: Get data info
 * * SMW_OPERATION_NAME_IS_OBJECT_PRESENT: Check if object is present in storage
 * * SMW_OPERATION_NAME_HASH_MULTI_PART: Hash multi-part
 * * SMW_OPERATION_NAME_ASYMM_ENCRYPT: Asymmetric encryption
 * * SMW_OPERATION_NAME_ASYMM_DECRYPT: Asymmetric decryption
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
	SMW_OPERATION_NAME_STORAGE_GET_DATA_INFO,
	SMW_OPERATION_NAME_IS_OBJECT_PRESENT,
	SMW_OPERATION_NAME_HASH_MULTI_PART,
	SMW_OPERATION_NAME_ASYMM_ENCRYPT,
	SMW_OPERATION_NAME_ASYMM_DECRYPT,
	SMW_OPERATION_NAME_NB
} smw_operation_t;

/**
 * typedef smw_object_type_t - Object type name
 *
 * Values:
 * * SMW_OBJECT_TYPE_NAME_NONE: No object type specified
 * * SMW_OBJECT_TYPE_NAME_DATA: Data Object
 * * SMW_OBJECT_TYPE_NAME_SECRET_KEY: Symmetric Secret Key Object
 * * SMW_OBJECT_TYPE_NAME_PUBLIC_KEY: Asymmetric Public Key Object
 * * SMW_OBJECT_TYPE_NAME_KEY_PAIR: Asymmetric Key Pair Object
 * * SMW_OBJECT_TYPE_NAME_CERT: Certificate Object
 * * SMW_OBJECT_TYPE_NAME_NB: Number of object types
 */
typedef enum {
	SMW_OBJECT_TYPE_NAME_NONE,
	SMW_OBJECT_TYPE_NAME_DATA,
	SMW_OBJECT_TYPE_NAME_SECRET_KEY,
	SMW_OBJECT_TYPE_NAME_PUBLIC_KEY,
	SMW_OBJECT_TYPE_NAME_KEY_PAIR,
	SMW_OBJECT_TYPE_NAME_CERT,
	SMW_OBJECT_TYPE_NAME_NB
} smw_object_type_t;

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
 * * SMW_KEY_TYPE_NAME_DERIVE: Derived key
 * * SMW_KEY_TYPE_NAME_HKDF_IKM: HKDF IKM key
 * * SMW_KEY_TYPE_NAME_X25519: Montgomery Elliptic Curve25519 key
 * * SMW_KEY_TYPE_NAME_EL2GO_PROV_OEM_KEY: EdgeLock 2GO Provisioning OEM Key
 * * SMW_KEY_TYPE_NAME_ED448: Twisted Edwards 448 key
 * * SMW_KEY_TYPE_NAME_X448: Montgomery Elliptic Curve448 key
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
	SMW_KEY_TYPE_NAME_DERIVE,
	SMW_KEY_TYPE_NAME_HKDF_IKM,
	SMW_KEY_TYPE_NAME_X25519,
	SMW_KEY_TYPE_NAME_EL2GO_PROV_OEM_KEY,
	SMW_KEY_TYPE_NAME_ED448,
	SMW_KEY_TYPE_NAME_X448,
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
 * * SMW_HASH_ALGO_NAME_SHAKE_256: Secure Hash Algorithm KECCAK, 256 bits
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
	SMW_HASH_ALGO_NAME_SHAKE256,
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
 * * SMW_CIPHER_MODE_NAME_OFB: Output Feedback Block mode
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
	SMW_CIPHER_MODE_NAME_OFB,
	SMW_CIPHER_MODE_NAME_NB
} smw_cipher_mode_t;

/**
 * typedef smw_aead_mode_t - AEAD mode name
 *
 * Values:
 * * SMW_AEAD_MODE_NAME_NONE: No AEAD mode specified
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

/**
 * typedef smw_key_format_t - Key format name
 *
 * Values:
 * * SMW_KEY_FORMAT_NAME_NONE: No key format specified
 * * SMW_KEY_FORMAT_NAME_HEX: Hexadecimal value (no encoding)
 * * SMW_KEY_FORMAT_NAME_BASE64: Base 64 encoding value
 * * SMW_KEY_FORMAT_NAME_NB: Number of key formats
 */
typedef enum {
	SMW_KEY_FORMAT_NAME_NONE,
	SMW_KEY_FORMAT_NAME_HEX,
	SMW_KEY_FORMAT_NAME_BASE64,
	SMW_KEY_FORMAT_NAME_NB,
} smw_key_format_t;

/**
 * typedef smw_signature_algo_t - Signature algorithm name
 *
 * Values:
 * * SMW_SIGNATURE_ALGO_NAME_NONE: No signature algorithm specified
 * * SMW_SIGNATURE_ALGO_NAME_DEFAULT: Signature algorithm is given by the key type
 * * SMW_SIGNATURE_ALGO_NAME_ECDSA: Elliptic Curve Digital Signature Algorithm
 * * SMW_SIGNATURE_ALGO_NAME_EDDSA: Edwards-curve Digital Signature Algorithm
 * * SMW_SIGNATURE_ALGO_NAME_DSA: Digital Signature Algorithm
 * * SMW_SIGNATURE_ALGO_NAME_RSA: Rivest, Shamir and Adleman signature algorithm
 * * SMW_SIGNATURE_ALGO_NAME_TLS_1_2: Transport Layer Security 1.2 signature algorithm
 * * SMW_SIGNATURE_ALGO_NAME_NB: Number of signature algorithms
 */
typedef enum {
	SMW_SIGNATURE_ALGO_NAME_NONE,
	SMW_SIGNATURE_ALGO_NAME_DEFAULT,
	SMW_SIGNATURE_ALGO_NAME_ECDSA,
	SMW_SIGNATURE_ALGO_NAME_EDDSA,
	SMW_SIGNATURE_ALGO_NAME_DSA,
	SMW_SIGNATURE_ALGO_NAME_RSA,
	SMW_SIGNATURE_ALGO_NAME_TLS_1_2,
	SMW_SIGNATURE_ALGO_NAME_NB
} smw_signature_algo_t;

/**
 * typedef smw_signature_type_t - Signature type name
 *
 * Values:
 * * SMW_SIGNATURE_TYPE_NAME_NONE: No signature type specified
 * * SMW_SIGNATURE_TYPE_NAME_DEFAULT: Default signature type
 * * SMW_SIGNATURE_TYPE_NAME_PKCS1_1_5: Public-Key Cryptography Standards #1 v1.5
 * * SMW_SIGNATURE_TYPE_NAME_PSS: Probabilistic Signature Scheme
 * * SMW_SIGNATURE_TYPE_NAME_CLIENT: TLS client signature
 * * SMW_SIGNATURE_TYPE_NAME_SERVER: TLS server signature
 * * SMW_SIGNATURE_TYPE_NAME_CMAC: Cipher-based Message Authentication Code
 * * SMW_SIGNATURE_TYPE_NAME_NB: Number of signature types
 */
typedef enum {
	SMW_SIGNATURE_TYPE_NAME_NONE,
	SMW_SIGNATURE_TYPE_NAME_DEFAULT,
	SMW_SIGNATURE_TYPE_NAME_PKCS1_1_5,
	SMW_SIGNATURE_TYPE_NAME_PSS,
	SMW_SIGNATURE_TYPE_NAME_CLIENT,
	SMW_SIGNATURE_TYPE_NAME_SERVER,
	SMW_SIGNATURE_TYPE_NAME_CMAC,
	SMW_SIGNATURE_TYPE_NAME_NB
} smw_signature_type_t;

/**
 * typedef smw_tls12_kea_t - TLS 1.2 Key exchange algorithm name
 *
 * Values:
 * * SMW_TLS12_KEA_NAME_NONE: No TLS 1.2 Key exchange algorithm specified
 * * SMW_TLS12_KEA_NAME_DH_DSS: Diffie-Hellman signed with DSS
 * * SMW_TLS12_KEA_NAME_DH_RSA: Diffie-Hellman signed with RSA
 * * SMW_TLS12_KEA_NAME_DHE_DSS: Diffie-Hellman key Exchange signed with DSS
 * * SMW_TLS12_KEA_NAME_DHE_RSA: Diffie-Hellman key Exchange signed with RSA
 * * SMW_TLS12_KEA_NAME_ECDH_ECDSA: Elliptic Curve Diffie-Hellman signed with ECDSA
 * * SMW_TLS12_KEA_NAME_ECDH_RSA: Elliptic Curve Diffie-Hellman signed with RSA
 * * SMW_TLS12_KEA_NAME_ECDHE_ECDSA: Elliptic Curve Diffie-Hellman key Exchange signed with ECDSA
 * * SMW_TLS12_KEA_NAME_ECDHE_RSA: Elliptic Curve Diffie-Hellman key Exchange signed with RSA
 * * SMW_TLS12_KEA_NAME_RSA: Rivest–Shamir–Adleman
 * * SMW_TLS12_KEA_NAME_NB: Number of TLS 1.2 Key exchange algorithms
 */
typedef enum {
	SMW_TLS12_KEA_NAME_NONE,
	SMW_TLS12_KEA_NAME_DH_DSS,
	SMW_TLS12_KEA_NAME_DH_RSA,
	SMW_TLS12_KEA_NAME_DHE_DSS,
	SMW_TLS12_KEA_NAME_DHE_RSA,
	SMW_TLS12_KEA_NAME_ECDH_ECDSA,
	SMW_TLS12_KEA_NAME_ECDH_RSA,
	SMW_TLS12_KEA_NAME_ECDHE_ECDSA,
	SMW_TLS12_KEA_NAME_ECDHE_RSA,
	SMW_TLS12_KEA_NAME_RSA,
	SMW_TLS12_KEA_NAME_NB
} smw_tls12_kea_t;

/**
 * typedef smw_tls12_enc_t - TLS 1.2 encryption algorithm name
 *
 * Values:
 * * SMW_TLS12_ENC_NAME_NONE: No TLS 1.2 encryption algorithm specified
 * * SMW_TLS12_ENC_NAME_3DES_EDE_CBC: Triple DES Encrypt-Decrypt-Encrypt with CBC
 * * SMW_TLS12_ENC_NAME_AES_128_CBC: Advanced Encryption Standard 128 bits with CBC
 * * SMW_TLS12_ENC_NAME_AES_128_GCM: Advanced Encryption Standard 128 bits with GCM
 * * SMW_TLS12_ENC_NAME_AES_256_CBC: Advanced Encryption Standard 256 bits with CBC
 * * SMW_TLS12_ENC_NAME_AES_256_GCM: Advanced Encryption Standard 256 bits with GCM
 * * SMW_TLS12_ENC_NAME_RC4_128: Rivest Cipher 4 128 bits
 * * SMW_TLS12_ENC_NAME_AES_128_CCM: Advanced Encryption Standard 128 bits with CCM
 * * SMW_TLS12_ENC_NAME_AES_256_CCM: Advanced Encryption Standard 256 bits with CCM
 * * SMW_TLS12_ENC_NAME_CHACHA20_POLY1305: ChaCha20 stream cipher with Poly1305 MAC
 * * SMW_TLS12_ENC_NAME_NB: Number of TLS 1.2 encryption algorithms
 */
typedef enum {
	SMW_TLS12_ENC_NAME_NONE,
	SMW_TLS12_ENC_NAME_3DES_EDE_CBC,
	SMW_TLS12_ENC_NAME_AES_128_CBC,
	SMW_TLS12_ENC_NAME_AES_128_GCM,
	SMW_TLS12_ENC_NAME_AES_256_CBC,
	SMW_TLS12_ENC_NAME_AES_256_GCM,
	SMW_TLS12_ENC_NAME_RC4_128,
	SMW_TLS12_ENC_NAME_AES_128_CCM,
	SMW_TLS12_ENC_NAME_AES_256_CCM,
	SMW_TLS12_ENC_NAME_CHACHA20_POLY1305,
	SMW_TLS12_ENC_NAME_NB
} smw_tls12_enc_t;

/**
 * typedef smw_tls12_op_t - TLS 1.2 operation name
 *
 * Values:
 * * SMW_TLS12_OP_NAME_NONE: No TLS 1.2 operation name specified
 * * SMW_TLS12_OP_NAME_MASTER_SECRET: TLS 1.2 master secret
 * * SMW_TLS12_OP_NAME_KEY_EXPANSION: TLS 1.2 key expansion
 * * SMW_TLS12_OP_NAME_NB: Number of TLS 1.2 operation names
 */
typedef enum {
	SMW_TLS12_OP_NAME_NONE,
	SMW_TLS12_OP_NAME_MASTER_SECRET,
	SMW_TLS12_OP_NAME_KEY_EXPANSION,
	SMW_TLS12_OP_NAME_NB
} smw_tls12_op_t;

/**
 * typedef smw_oem_master_key_op_t - OEM Master key derivation operation name
 *
 * Values:
 * * SMW_OEM_MK_OP_NAME_NONE: No operation name specified
 * * SMW_OEM_MK_OP_NAME_DERIVE: Derive the OEM Master key
 * * SMW_OEM_MK_OP_NAME_PREPARE: Prepare the OEM Master key payload to sign
 * * SMW_OEM_MK_OP_NAME_NB: Number of operation names
 */
typedef enum {
	SMW_OEM_MK_OP_NAME_NONE,
	SMW_OEM_MK_OP_NAME_DERIVE,
	SMW_OEM_MK_OP_NAME_PREPARE,
	SMW_OEM_MK_OP_NAME_NB
} smw_oem_master_key_op_t;

/**
 * typedef smw_lifecycle_t - Device lifecycle name
 *
 * Values:
 * * SMW_LIFECYCLE_NAME_NONE: No lifecycle specified
 * * SMW_LIFECYCLE_NAME_OPEN: Current
 * * SMW_LIFECYCLE_NAME_OPEN: Open
 * * SMW_LIFECYCLE_NAME_CLOSED: Closed
 * * SMW_LIFECYCLE_NAME_CLOSED_LOCKED: Closed-locked
 * * SMW_LIFECYCLE_NAME_OEM_RETURN: OEM return
 * * SMW_LIFECYCLE_NAME_NXP_RETURN: NXP return
 * * SMW_LIFECYCLE_NAME_NXP_NB: Number of lifecycles
 */
typedef enum {
	SMW_LIFECYCLE_NAME_NONE,
	SMW_LIFECYCLE_NAME_CURRENT,
	SMW_LIFECYCLE_NAME_OPEN,
	SMW_LIFECYCLE_NAME_CLOSED,
	SMW_LIFECYCLE_NAME_CLOSED_LOCKED,
	SMW_LIFECYCLE_NAME_OEM_RETURN,
	SMW_LIFECYCLE_NAME_NXP_RETURN,
	SMW_LIFECYCLE_NAME_NB
} smw_lifecycle_t;

/**
 * typedef smw_kdf_t - Key Derivation Function name
 *
 * Values:
 * * SMW_KDF_NAME_NONE: No Key Derivation Function name specified
 * * SMW_KDF_NAME_HKDF: HMAC-Based Key Derivation Function
 * * SMW_KDF_NAME_HKDF_EXTRACT: HMAC-Based Key Derivation Extract step Function
 * * SMW_KDF_NAME_HKDF_EXPAND: HMAC-Based Key Derivation Expand step Function
 * * SMW_KDF_NAME_TLS12_KEY_EXCHANGE: TLS 1.2 Key Exchange
 * * SMW_KDF_NAME_ECDH: ECDH Key Exchange
 * * SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE: TLS 1.2 "Operation-based" Key Exchange
 * * SMW_KDF_NAME_TLS13_KEY_EXCHANGE: TLS 1.3 Key Exchange
 * * SMW_KDF_NAME_OEM_MASTER_KEY: OEM Master key derivation
 * * SMW_KDF_NAME_NB: Number of Key Derivation Functions
 */
typedef enum {
	SMW_KDF_NAME_NONE,
	SMW_KDF_NAME_HKDF,
	SMW_KDF_NAME_HKDF_EXTRACT,
	SMW_KDF_NAME_HKDF_EXPAND,
	SMW_KDF_NAME_TLS12_KEY_EXCHANGE,
	SMW_KDF_NAME_ECDH,
	SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE,
	SMW_KDF_NAME_TLS13_KEY_EXCHANGE,
	SMW_KDF_NAME_OEM_MASTER_KEY,
	SMW_KDF_NAME_NB
} smw_kdf_t;

/**
 * typedef smw_asymmetric_encryption_algo_t - Asymmetric encryption/decryption algo name
 *
 * Values:
 * * SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE: No encryption/decryption algorithm specified
 * * SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_RSA: RSA encryption/decryption algorithm
 * * SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NB: Number of encryption/decryption algorithms
 */
typedef enum {
	SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE,
	SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_RSA,
	SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NB
} smw_asymmetric_encryption_algo_t;

/**
 * typedef smw_asymmetric_encryption_mode_t - Asymmetric encryption/decryption padding scheme name
 *
 * Values:
 * * SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NONE: No Encryption padding scheme name specified
 * * SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_PKCS1_1_5: Public-Key Cryptography Standards #1 v1.5
 * * SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_OAEP: Optimal Asymmetric Encryption Padding
 * * SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NO_PAD: Asymmetric Encryption/decryption with no padding
 * * SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NB: Number of encryption padding schemes
 */
typedef enum {
	SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NONE,
	SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_PKCS1_1_5,
	SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_OAEP,
	SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NO_PAD,
	SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NB
} smw_asymmetric_encryption_mode_t;

#endif /* __SMW_NAMES_H__ */
