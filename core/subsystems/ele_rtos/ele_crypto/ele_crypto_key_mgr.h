/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_KEY_MGR_H__
#define __ELE_CRYPTO_KEY_MGR_H__

#include "ele_common.h"

/*******************************************************************************
 * Key generate definitions
 ******************************************************************************/

/**
 * key_type_t - Key types
 * KEYTYPE_AES: AES key type, used for cipher encryption/decryption, authenticated encryption,
 *              MAC generation/verification (CMAC), and import key (as KEK)
 * KEYTYPE_DERIVE: Derive key type, used for TLS 1.2 compute key block and TLS finish data
 * KEYTYPE_HMAC: HMAC key type, used for MAC generation/verification
 * KEYTYPE_SM4: SM4 key type, used for cipher encryption/decryption
 * KEYTYPE_ECC_PUB_KEY_BRAINPOOL_R1: ECC public key type for Brainpool R1 curve,
 *                                   used for signature verification
 * KEYTYPE_ECC_PUB_KEY_SECP_NIST: ECC public key type for SECP NIST curve,
 *                                used for signature verification
 * KEYTYPE_RSA_PUB_KEY: RSA public key type, used for signature verification
 * KEYTYPE_ECC_KEY_PAIR_BRAINPOOL_R1: ECC key pair type for Brainpool R1 curve,
 *                                    used for signature generation, key exchange,
 *                                    TLS 1.2 key derivation and agreement.
 * KEYTYPE_ECC_KEY_PAIR_SECP_R1_NIST: ECC key pair type for SECP R1 NIST curve,
 *                                    used for signature generation, key exchange,
 *                                    TLS 1.2 key derivation and agreement
 * KEYTYPE_RSA_KEY_PAIR: RSA key pair type, used for signature generation and verification
 *
 * NOTE: For asymmetric keys, even if the key type is mentioned as KEY PAIR,
 * only the private key is stored in the key group.
 */
typedef enum {
	KEYTYPE_AES = 0x2400u,
	KEYTYPE_DERIVE = 0x1200u,
	KEYTYPE_HMAC = 0x1100u,
	KEYTYPE_SM4 = 0x2405u,
	KEYTYPE_ECC_PUB_KEY_BRAINPOOL_R1 = 0x4130u,
	KEYTYPE_ECC_PUB_KEY_SECP_NIST = 0x4112u,
	KEYTYPE_RSA_PUB_KEY = 0x4001u,
	KEYTYPE_ECC_KEY_PAIR_BRAINPOOL_R1 = 0x7130u,
	KEYTYPE_ECC_KEY_PAIR_SECP_R1_NIST = 0x7112u,
	KEYTYPE_RSA_KEY_PAIR = 0x7001u,
} key_type_t;

/* key_lifetime_t - Key Lifetime */
typedef enum {
	KEY_VOLATILE = 0x100,
	KEY_PERSISTENT = 0x101,
	KEY_VOLATILE_PERMANENT = 0x180,
	KEY_PERSISTENT_PERMANENT = 0x181,
} key_lifetime_t;

/**
 * key_usage_t - Key Usage.
 * KEYUSAGE_CACHE: Permission to cache the key in the EdgeLock Secure Enclave internal
 *                 secure RAM memory.
 * KEYUSAGE_ENCRYPT: Permission to encrypt a message with the key. It could be cipher encryption,
 *                   AEAD encryption or asymmetric encryption operation.
 * KEYUSAGE_DECRYPT: Permission to decrypt a message with the key. It could be cipher decryption,
 *                   AEAD decryption or asymmetric decryption operation.
 * KEYUSAGE_SIGNMESSAGE: Permission to sign a message with the key. It could be a MAC generation
 *                       or an asymmetric message signature operation.
 * KEYUSAGE_VERIFYMESSAGE: Permission to verify a message signature with the key. It could be a
 *                         MAC verification or an asymmetric message signature
 *                         verification operation.
 * KEYUSAGE_SIGNHASH: Permission to sign a hashed message with the key with an
 *                    asymmetric signature operation.
 * KEYUSAGE_VERIFYHASH: Permission to verify a hashed message signature with the key with an
 *                      asymmetric signature verification operation.
 * KEYUSAGE_DERIVE: Permission to derive other keys from this key.
 *
 * NOTE: As these values are bitmap values, several usage could be set.
 */
typedef enum {
	KEYUSAGE_CACHE = 0x0004u,
	KEYUSAGE_ENCRYPT = 0x0100u,
	KEYUSAGE_DECRYPT = 0x0200u,
	KEYUSAGE_SIGNMESSAGE = 0x0400u,
	KEYUSAGE_VERIFYMESSAGE = 0x0800u,
	KEYUSAGE_SIGNHASH = 0x1000u,
	KEYUSAGE_VERIFYHASH = 0x2000u,
	KEYUSAGE_DERIVE = 0x4000u,
} key_usage_t;

/* key_size_t - Key Size */
typedef enum {
	KEYSIZE_AES_128 = 128u,
	KEYSIZE_AES_192 = 192u,
	KEYSIZE_AES_256 = 256u,
	KEYSIZE_DERIVE_256 = 256u,
	KEYSIZE_DERIVE_384 = 384u,
	KEYSIZE_HMAC_224 = 224u,
	KEYSIZE_HMAC_256 = 256u,
	KEYSIZE_HMAC_384 = 384u,
	KEYSIZE_HMAC_512 = 512u,
	KEYSIZE_SM4_128 = 128u,
	KEYSIZE_ECC_KEY_PAIR_BRAINPOOL_R1_224 = 224u,
	KEYSIZE_ECC_KEY_PAIR_BRAINPOOL_R1_256 = 256u,
	KEYSIZE_ECC_KEY_PAIR_BRAINPOOL_R1_384 = 384u,
	KEYSIZE_ECC_KEY_PAIR_SECP_R1_NIST_224 = 224u,
	KEYSIZE_ECC_KEY_PAIR_SECP_R1_NIST_256 = 256u,
	KEYSIZE_ECC_KEY_PAIR_SECP_R1_NIST_384 = 384u,
	KEYSIZE_ECC_KEY_PAIR_SECP_R1_NIST_521 = 521u,
	KEYSIZE_RSA_KEY_PAIR_2048 = 2048u,
	KEYSIZE_RSA_KEY_PAIR_3072 = 3072u,
	KEYSIZE_RSA_KEY_PAIR_4096 = 4096u,
} key_size_t;

/**
 * key_permitted_alg_t - Key Permitted algorithm
 * PERMITTED_HMAC_SHA256: Key can be used for HMAC SHA256 algorithm
 * PERMITTED_HMAC_SHA384: Key can be used for HMAC SHA384 algorithm
 * PERMITTED algorithms values computation allows to truncate the HMAC output length
 * or to set a minimum MAC output length. The following section describe how to encode
 * truncated MAC algorithm.
 * LEN (Bit 16 to 21):
 * - LEN = 0 specifies the default output MAC length.
 *   Its only compatible with W set to 0.
 * - LEN > 0x08 specifies a truncated output MAC length.
 *   It could be a specific or a minimum length according to W bit value. W (Bit 15):
 *   - W = 0 indicates a specific output MAC length. In this case,
 *     the output MAC length set by the user must be equal to the value set by LEN bits.
 *   - W = 1 indicates a minimum output MAC length. It must be at least 8
 *     and cannot be greater that the default algorithm MAC length.
 *     In this case, the output MAC length set by the user must be greater
 *     than or equal to the value set by LEN bits and less than or equal
 *     to the default algorithm MAC length (hash algorithm length).
 *     HASH_TYPE (Bit 0 to 7):
 *     - HASH_TYPE = 0x09 indicates SHA256 algorithm.
 *     - HASH_TYPE = 0x0A indicates SHA384 algorithm.
 *     - No other values are supported.
 * PERMITTED_CMAC: Key can be used for CMAC algorithm. The output MAC length is always 16 bytes.
 * PERMITTED_CTR: Key can be used for CTR mode of operation for AES algorithm
 * PERMITTED_ECB: Key can be used for ECB mode of operation for AES algorithm with no padding
 * PERMITTED_CBC: Key can be used for CBC mode of operation for AES algorithm with no padding
 * PERMITTED_CFB: Key can be used for CFB mode of operation for AES algorithm
 * PERMITTED_OFB: Key can be used for OFB mode of operation for AES algorithm
 * PERMITTED_ALL_CIPHER: Key can be used for all supported modes of operation for
 *                        AES algorithm with no padding.
 *                        It is only available at key creation.
 *                        Supported modes: CMAC, CTR, ECB (no padding), CBC (no padding)
 * PERMITTED_CCM: Key can be used for CCM mode of operation for AES algorithm
 * PERMITTED_GCM: Key can be used for GCM mode of operation for AES algorithm
 * PERMITTED_ALL_AEAD: Key can be used for all supported AEAD modes.
 *                     It is only available at key creation. Supported modes: CCM, GCM.
 * PERMITTED_KEK_CCM: Key can be used for CCM mode of operation for AES algorithm for
 *                    key encryption key (KEK) during import operation
 * PERMITTED_KEK_GCM: Key can be used for GCM mode of operation for AES algorithm for
 *                    key encryption key (KEK) during import operation
 * PERMITTED_CHACHA20_POLY1305: Key can be used for ChaCha20-Poly1305 algorithm
 * PERMITTED_RSA_PKCS1_V1_5_SHA1: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                or verification with SHA1 hash algorithm
 * PERMITTED_RSA_PKCS1_V1_5_SHA224: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                  or verification with SHA224 hash algorithm
 * PERMITTED_RSA_PKCS1_V1_5_SHA256: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                  or verification with SHA256 hash algorithm
 * PERMITTED_RSA_PKCS1_V1_5_SHA384: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                  or verification with SHA384 hash algorithm
 * PERMITTED_RSA_PKCS1_V1_5_SHA512: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                  or verification with SHA512 hash algorithm
 * PERMITTED_RSA_PKCS1_V1_5_ANY_HASH: Key can be used for RSA PKCS1 v1.5 signature generation
 *                                    or verification with any hash algorithm.
 *                                    It is only available at key creation.
 * PERMITTED_RSA_PKCS1_PSS_MGF1_SHA1: Key can be used for RSA PKCS1 PSS signature generation
 *                                    or verification with MGF1 and SHA1 hash algorithm.
 * PERMITTED_RSA_PKCS1_PSS_MGF1_SHA224: Key can be used for RSA PKCS1 PSS signature generation
 *                                      or verification with MGF1 and SHA224 hash algorithm
 * PERMITTED_RSA_PKCS1_PSS_MGF1_SHA256: Key can be used for RSA PKCS1 PSS signature generation
 *                                      or verification with MGF1 and SHA256 hash algorithm
 * PERMITTED_RSA_PKCS1_PSS_MGF1_SHA384: Key can be used for RSA PKCS1 PSS signature generation
 *                                      or verification with MGF1 and SHA384 hash algorithm
 * PERMITTED_RSA_PKCS1_PSS_MGF1_SHA512: Key can be used for RSA PKCS1 PSS signature generation
 *                                      or verification with MGF1 and SHA512 hash algorithm
 * PERMITTED_RSA_PKCS1_PSS_MGF1_ANY_HASH: Key can be used for RSA PKCS1 PSS signature generation
 *                                        or verification with MGF1 and any hash algorithm.
 *                                        It is only available at key creation.
 * PERMITTED_ECDSA_SHA224: Key can be used for ECDSA signature generation
 *                         or verification with SHA224 hash algorithm
 * PERMITTED_ECDSA_SHA256: Key can be used for ECDSA signature generation
 *                         or verification with SHA256 hash algorithm
 * PERMITTED_ECDSA_SHA384: Key can be used for ECDSA signature generation
 *                         or verification with SHA384 hash algorithm
 * PERMITTED_ECDSA_SHA512: Key can be used for ECDSA signature generation
 *                         or verification with SHA512 hash algorithm
 * PERMITTED_ED25519PH: Key can be used for Ed25519ph signature generation or verification
 * PERMITTED_ED448PH: Key can be used for Ed448ph signature generation or verification
 * PERMITTED_PURE_EDDSA: Key can be used for pure EdDSA signature generation or verification
 * PERMITTED_EDDSA_ALL: Key can be used for all EdDSA signature generation or verification.
 *                      It is only available at key creation.
 *                      Supported modes: Ed25519ph, Ed448ph and pure EdDSA.
 * PERMITTED_ECDH_SHA_256: Key can be used for ECDH key agreement with SHA256
 * PERMITTED_ECDH_HKDF_SHA256: Key can be used for ECDH key agreement with HKDF and SHA256
 * PERMITTED_ECDH_HKDF_SHA384: Key can be used for ECDH key agreement with HKDF and SHA384
 * PERMITTED_TLS_1_2_PRF_ECDH_SHA256: Key can be used for TLS 1.2 PRF key derivation
 *                                    with ECDH and SHA256
 * PERMITTED_TLS_1_2_PRF_ECDH_SHA384: Key can be used for TLS 1.2 PRF key derivation
 *                                    with ECDH and SHA384
 * PERMITTED_TLS1_2_MASTER_SECRET_SHA256: Key can be used for TLS 1.2 master secret key derivation
 *                                        with SHA256
 * PERMITTED_TLS1_2_MASTER_SECRET_SHA384: Key can be used for TLS 1.2 master secret key derivation
 *                                        with SHA384
 * PERMITTED_TLS1_2_MASTER_SECRET_SHA_ANY: Key can be used for TLS 1.2 master secret key derivation
 *                                         with any hash algorithm. It is only available at
 *                                         key creation.
 * PERMITTED_TLS1_3_EARLY_SECRET_SHA_ANY: Key can be used for TLS 1.3 early secret key derivation
 *                                        with any hash algorithm. It is only available
 *                                        at key creation.
 * PERMITTED_TLS1_3_MASTER_SECRET_SHA256: Key can be used for TLS 1.3 master secret key derivation
 *                                        with SHA256
 * PERMITTED_TLS1_3_MASTER_SECRET_SHA384: Key can be used for TLS 1.3 master secret key derivation
 *                                        with SHA384
 * PERMITTED_TLS1_3_MASTER_SECRET_SHA_ANY: Key can be used for TLS 1.3 master secret key derivation
 *                                         with any hash algorithm.
 *                                         It is only available at key creation.
 * PERMITTED_ATTEST_CMAC: Key can be used for attestation with CMAC algorithm
 * PERMITTED_ATTEST_ECDSA_SHA224: Key can be used for attestation with ECDSA signature generation
 *                                or verification with SHA224 hash algorithm
 * PERMITTED_ATTEST_ECDSA_SHA256: Key can be used for attestation with ECDSA signature generation
 *                                or verification with SHA256 hash algorithm
 * PERMITTED_ATTEST_ECDSA_SHA384: Key can be used for attestation with ECDSA signature generation
 *                                or verification with SHA384 hash algorithm
 * PERMITTED_ATTEST_ECDSA_SHA512: Key can be used for attestation with ECDSA signature generation
 *                                or verification with SHA512 hash algorithm
 * PERMITTED_RSA_PKCS1_V15_CRYPT: Key can be used for RSA PKCS1 v1.5 encryption or decryption
 * PERMITTED_RSA_PKCS1_OAEP_SHA1: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                with SHA1 hash algorithm
 * PERMITTED_RSA_PKCS1_OAEP_SHA224: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                  with SHA224 hash algorithm
 * PERMITTED_RSA_PKCS1_OAEP_SHA256: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                  with SHA256 hash algorithm
 * PERMITTED_RSA_PKCS1_OAEP_SHA384: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                  with SHA384 hash algorithm
 * PERMITTED_RSA_PKCS1_OAEP_SHA512: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                  with SHA512 hash algorithm
 * PERMITTED_RSA_PKCS1_OAEP_SHA_ANY: Key can be used for RSA PKCS1 OAEP encryption or decryption
 *                                   with any hash algorithm. It is only available at key creation.
 * PERMITTED_RSA_PKCS1_CRYPT_ALL: Key can be used for all supported RSA PKCS1 encryption or
 *                                decryption. It is only available at key creation.
 * Supported modes: RSA PKCS1 v1.5 and RSA OAEP with any hash algorithm.
 */
typedef enum {
	PERMITTED_HMAC_SHA256 = 0x03800009u,
	PERMITTED_HMAC_SHA384 = 0x0380000Au,
	PERMITTED_CMAC = 0x03C00200u,
	PERMITTED_CTR = 0x04C01000u,
	PERMITTED_ECB = 0x04404400u,
	PERMITTED_CBC = 0x04404000u,
	PERMITTED_CFB = 0x04C01100u,
	PERMITTED_OFB = 0x04C01200u,
	PERMITTED_ALL_CIPHER = 0x84C0FF00u,
	PERMITTED_CCM = 0x05500100u,
	PERMITTED_GCM = 0x05500200u,
	PERMITTED_ALL_AEAD = 0x8550FF00u,
	PERMITTED_KEK_CCM = 0x85500100u,
	PERMITTED_KEK_GCM = 0x85500200u,
	PERMITTED_CHACHA20_POLY1305 = 0x05100500u,
	PERMITTED_RSA_PKCS1_V1_5_SHA1 = 0x06000205u,
	PERMITTED_RSA_PKCS1_V1_5_SHA224 = 0x06000208u,
	PERMITTED_RSA_PKCS1_V1_5_SHA256 = 0x06000209u,
	PERMITTED_RSA_PKCS1_V1_5_SHA384 = 0x0600020Au,
	PERMITTED_RSA_PKCS1_V1_5_SHA512 = 0x0600020Bu,
	PERMITTED_RSA_PKCS1_V1_5_ANY_HASH = 0x060002FFu,
	PERMITTED_RSA_PKCS1_PSS_MGF1_SHA1 = 0x06000305u,
	PERMITTED_RSA_PKCS1_PSS_MGF1_SHA224 = 0x06000308u,
	PERMITTED_RSA_PKCS1_PSS_MGF1_SHA256 = 0x06000309u,
	PERMITTED_RSA_PKCS1_PSS_MGF1_SHA384 = 0x0600030Au,
	PERMITTED_RSA_PKCS1_PSS_MGF1_SHA512 = 0x0600030Bu,
	PERMITTED_RSA_PKCS1_PSS_MGF1_ANY_HASH =
		0x060003FFu, /* Only available at key creation */
	PERMITTED_ECDSA_SHA224 = 0x06000608u,
	PERMITTED_ECDSA_SHA256 = 0x06000609u,
	PERMITTED_ECDSA_SHA384 = 0x0600060Au,
	PERMITTED_ECDSA_SHA512 = 0x0600060Bu,
	PERMITTED_ED25519PH = 0x0600090Bu,
	PERMITTED_ED448PH = 0x06000915u,
	PERMITTED_PURE_EDDSA = 0x06000800u,
	PERMITTED_EDDSA_ALL = 0x86000800u,
	PERMITTED_ECDH_SHA_256 = 0x8902EF09u,
	PERMITTED_ECDH_HKDF_SHA256 = 0x09020109u,
	PERMITTED_ECDH_HKDF_SHA384 = 0x0902010A,
	PERMITTED_TLS_1_2_PRF_ECDH_SHA256 = 0x09020209u,
	PERMITTED_TLS_1_2_PRF_ECDH_SHA384 = 0x0902020Au,
	PERMITTED_TLS1_2_MASTER_SECRET_SHA256 = 0x8800E009u,
	PERMITTED_TLS1_2_MASTER_SECRET_SHA384 = 0x8800E00Au,
	PERMITTED_TLS1_2_MASTER_SECRET_SHA_ANY = 0x8800E0FFu,
	PERMITTED_TLS1_3_EARLY_SECRET_SHA_ANY = 0x8800D0FFu,
	PERMITTED_TLS1_3_MASTER_SECRET_SHA256 = 0x8800D209u,
	PERMITTED_TLS1_3_MASTER_SECRET_SHA384 = 0x8800D20Au,
	PERMITTED_TLS1_3_MASTER_SECRET_SHA_ANY = 0x8800D2FFu,
	PERMITTED_ATTEST_CMAC = 0x83C00200u,
	PERMITTED_ATTEST_ECDSA_SHA224 = 0x86000608u,
	PERMITTED_ATTEST_ECDSA_SHA256 = 0x86000609u,
	PERMITTED_ATTEST_ECDSA_SHA384 = 0x8600060Au,
	PERMITTED_ATTEST_ECDSA_SHA512 = 0x8600060Bu,
	PERMITTED_RSA_PKCS1_V15_CRYPT = 0x07000200u,
	PERMITTED_RSA_PKCS1_OAEP_SHA1 = 0x07000305u,
	PERMITTED_RSA_PKCS1_OAEP_SHA224 = 0x07000308u,
	PERMITTED_RSA_PKCS1_OAEP_SHA256 = 0x07000309u,
	PERMITTED_RSA_PKCS1_OAEP_SHA384 = 0x0700030Au,
	PERMITTED_RSA_PKCS1_OAEP_SHA512 = 0x0700030Bu,
	PERMITTED_RSA_PKCS1_OAEP_SHA_ANY = 0x070003FFu,
	PERMITTED_RSA_PKCS1_CRYPT_ALL = 0x8700FF00u,
} key_permitted_alg_t;

/**
 * key_lifecycle_t - Key Lifecycle
 * KEYLIFECYCLE_OPEN: Key is in open state.
 * KEYLIFECYCLE_CLOSED: Key is in closed state.
 * KEYLIFECYCLE_CLOSED_LOCKED: Key is in closed and locked state.
 */
typedef enum {
	KEYLIFECYCLE_OPEN = 0x1u,
	KEYLIFECYCLE_CLOSED = 0x2u,
	KEYLIFECYCLE_CLOSED_LOCKED = 0x4u,
} key_lifecycle_t;

/**
 * ele_gen_key_t - Key generation structure
 * @pub_key_size: Size in bytes of the output buffer for the generated public key
 *                (ignored for symmetric keys)
 * @key_group: Key group identifier. It must be a value in the range 0-100 and is ignored
 *             if a symmetric key is generated.
 * @key_lifetime: Key lifetime attribute. Refer to key_lifetime_t enum
 * @key_usage: Key usage attribute. Refer to key_usage_t enum
 * @key_type: Key type. Refer to key_type_t enum
 * @key_size: Key size. Refer to key_size_t enum
 * @permitted_alg: Permitted algorithm attribute. Refer to key_permitted_alg_t enum
 * @pub_key_addr: Address in the requester space where to store the generated public key
 *                (ignored for symmetric keys)
 * @key_lifecycle: Key lifecycle attribute. Refer to key_lifecycle_t enum
 * @key_id: Key identifier. User specified ID only supported by persistent and permanent keys.
 *          Set to 0 to let FW choose an ID - supported by all persistence levels.
 *          For supported ID ranges, refer to the ELE API documentation.
 */
typedef struct {
	uint16_t pub_key_size;
	uint16_t key_group;
	uint32_t key_lifetime;
	uint32_t key_usage;
	uint16_t key_type;
	uint16_t key_size;
	uint32_t permitted_alg;
	void *pub_key_addr;
	uint32_t key_lifecycle;
	uint32_t key_id;
} ele_gen_key_t;

/**
 * ele_key_attribute_t - Key attributes structure
 * @key_type: Key type. Refer to key_type_t enum
 * @key_size: Key size. Refer to key_size_t enum
 * @key_lifetime: Key lifetime attribute. Refer to key_lifetime_t enum
 * @key_usage: Key usage attribute. Refer to key_usage_t enum
 * @permitted_alg: Permitted algorithm attribute. Refer to key_permitted_alg_t enum
 * @key_lifecycle: Key lifecycle attribute. Refer to key_lifecycle_t enum
 */
typedef struct {
	uint16_t key_size;
	uint16_t key_type;
	uint32_t key_lifetime;
	uint32_t key_usage;
	uint32_t permitted_alg;
	uint32_t key_lifecycle;
} ele_key_attribute_t;

/**
 * ele_open_key_service() - Open ELE Key Management Service
 * @mu: MU peripheral base address
 * @keystore_handle_id: Unique session ID obtained by calling ele_open_keystore()
 * @key_handle_id: Pointer where unique key management handle ID word will be stored
 *
 * This function opens Key Management Service for EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_open_key_service(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t *key_handle_id);

/**
 * ele_close_key_service() - Close ELE Key Management Service
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 *
 * This function closes the Key Management Service for EdgeLock Enclave.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_close_key_service(s3mu_t *mu, uint32_t key_handle_id);

/**
 * ele_generate_key() - ELE Generate Key
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 * @conf: Pointer where key generate configuration structure can be found
 * @key_id: Pointer where unique Key ID word will be stored
 * @out_size: Pointer where to save the resulting key size or the expected
 *           size of the key buffer, if the buffer is found to be too small, in which case
 *           an error is also returned
 * @monotonic: If true, the monotonic counter flag is set
 * @sync: If true, the SYNC flag is set
 *
 * This function generates a key inside given keys store in the EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 * Status_ELE_BufferTooSmall       - Buffer too small
 */
status_t ele_generate_key(s3mu_t *mu, uint32_t key_handle_id,
			  ele_gen_key_t *conf, uint32_t *key_id,
			  uint16_t *out_size, bool monotonic, bool sync);

/**
 * ele_generate_pub_key() - ELE Generate Public Key
 * @mu: MU peripheral base address
 * @keystore_handle_id: Unique session ID obtained by calling ele_open_keystore()
 * @key_id: Identifier of asymmetric key inside ELE
 * @output: Output buffer where the public key will be written
 * @out_key_size: Length in bytes of output key buffer
 * @out_size: Pointer where to save the resulting key size or the expected
 *            size of the key buffer, if the buffer is found to be too small, in which case
 *            an error is also returned
 *
 * This function generates a public key from private asymmetric key inside EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 * Status_ELE_BufferTooSmall       - Buffer too small
 */
status_t ele_generate_pub_key(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t key_id, uint32_t *output,
			      uint32_t out_key_size, uint16_t *out_size);

/**
 * ele_delete_key() - ELE Delete Key
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 * @key_id: Unique key ID obtained by calling ele_generate_key()
 * @monotonic: If true, the monotonic counter flag is set
 * @sync: If true, the SYNC flag is set
 *
 * This function deletes a key from a keystore in the EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_delete_key(s3mu_t *mu, uint32_t key_handle_id, uint32_t key_id,
			bool monotonic, bool sync);

/**
 * ele_get_key_attribute() - Get attributes of a key stored in
 *                         EdgeLock Secure Enclave key storage
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 * @key_id: Identifier of the key which attributes are returned.
 * @key_attribute: Pointer to the key attribute structure that will be filled
 *                with the key attributes
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_key_attribute(s3mu_t *mu, uint32_t key_handle_id,
			       uint32_t key_id,
			       ele_key_attribute_t *key_attribute);

/**
 * ele_import_key_option_t - Import key options
 * IMPORT_KEY_OPTION_ELE: The TLV payload is an ELE blob containing the key in the format defined by
 * the ELE API. It is the default option if no option is set.
 * IMPORT_KEY_OPTION_EL2GO: The TLV payload is an EdgeLock2Go blob containing the key in the format
 * defined by the EdgeLock2Go API.
 */
typedef enum {
	IMPORT_KEY_OPTION_ELE = 0u,
	IMPORT_KEY_OPTION_EL2GO = 1u,
} ele_import_key_option_t;

/**
 * ele_import_key() - Import an EdgeLock2Go or ELE key.
 * @mu: MU peripheral base address
 * @key_handle_id: Identifier of a key management sevice opened with ele_open_key_service()
 * @input: Pointer to the TLV blob containing the key to be imported
 * @input_size: The size of the input TLV blob in Bytes
 * @key_group_auto: Set to true to let ELE select the key group to import the key into
 * @key_group_id: Identifier of the keygroup to import the key into if keyGroupAuto is false
 * @option: Specifies if the TLV blob is an EdgeLock2Go option or an ELE option
 * @sync: If true, the SYNC flag is set
 * @monotonic: If true, the monotonic counter flag is set
 * @key_id: Output parameter returning the ID of the imported key
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_import_key(s3mu_t *mu, uint32_t key_handle_id, uint8_t *input,
			uint32_t input_size, bool key_group_auto,
			uint16_t key_group_id, ele_import_key_option_t option,
			bool sync, bool monotonic, uint32_t *key_id);

#endif /* __ELE_CRYPTO_KEY_MGR_H__ */
