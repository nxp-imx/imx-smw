/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef __SMW_ATTR_H__
#define __SMW_ATTR_H__

#include <stdint.h>

/**
 * DOC:
 * The attributes API defines the bitmasks that represent attributes
 * associated to a key or data.
 * It also defines macros to write or read these attributes.
 */

/**
 * typedef smw_attr_algo_t - Algorithm parameters
 *
 * 64-bits field used to define an algorithm and its parameters.
 *
 * - Main algorithm
 * - Mode, if any
 * - Curve, if any
 * - Hash, if any
 * - Operation class
 * - Salt length, if any
 * - MAC length, if any
 * - Tag length, if any
 * - Signature parameters, if any
 *
 * +------------------------------------------------------------------+
 * | Bits                                                             |
 * +---------+-------------+-----------+---------+--------+-----------+
 * | [61:40] | [39:32]     | [31:24]   | [23:16] | [15:8] | [7:0]     |
 * +---------+-------------+-----------+---------+--------+-----------+
 * |         | Additional  | Operation | Hash    | Mode / | Main      |
 * +         +             +           +         +        +           +
 * |         | parameters  | class     |         | Curve  | algorithm |
 * +---------+-------------+-----------+---------+--------+-----------+
 *
 * Additional parameters:
 *
 *  - MAC Truncated length
 *
 * +-------------+--------------------------------------+
 * | Bits[39:32] | Description                          |
 * +---+---------+                                      +
 * | 8 | [7:0]   |                                      |
 * +---+---------+--------------------------------------+
 * | M | Length  | Length of the MAC truncated length   |
 * +---+---------+--------------------------------------+
 *
 * M is 1 if Length is minimum length, 0 otherwise.
 *
 *  - AEAD Tag length
 *
 * +-------------+--------------------------------------+
 * | Bits[39:32] | Description                          |
 * +---+---------+                                      +
 * | 8 | [7:0]   |                                      |
 * +---+---------+--------------------------------------+
 * | M | Length  | AEAD Tag length                      |
 * +---+---------+--------------------------------------+
 *
 * M is 1 if Length is minimum length, 0 otherwise.
 *
 *  - Signature (RSA-PSS) Salt length
 *
 * +-------------+--------------------------------------+
 * | Bits[39:32] | Description                          |
 * +---+---------+                                      +
 * | 8 | [7:0]   |                                      |
 * +---+---------+--------------------------------------+
 * | M | Length  | RSA-PSS Salt length                  |
 * +---+---------+--------------------------------------+
 *
 * M is 1 if Length is minimum length, 0 otherwise.
 *
 *  - Signature (ECDSA)
 *
 * +-------------+--------------------------------------+
 * | Bits[39:32] | Description                          |
 * +---+---------+                                      +
 * | 8 | [7:0]   |                                      |
 * +---+---------+--------------------------------------+
 * | 1 | --      | ECDSA signature message is hashed    |
 * +---+---------+--------------------------------------+
 *
 *  - Signature (EDDSA)
 *
 * +-------------+--------------------------------------+
 * | Bits[39:32] | Description                          |
 * +---+---------+                                      +
 * | 8 | [7:0]   |                                      |
 * +---+---------+--------------------------------------+
 * | H | 0x01    | EDDSA signature type is pre-hashed   |
 * +---+---------+--------------------------------------+
 * | H | 0x02    | EDDSA signature type is with context |
 * +---+---------+--------------------------------------+
 *
 * H is 1 if message to sign or verify is already hashed, 0 otherwise.
 */
typedef uint64_t smw_attr_algo_t;

/**
 * typedef smw_attr_usage_t - Permitted usages
 *
 * 32-bits field used to define the permitted usages.
 *
 * - Cache (Ca)
 * - Copy (Co)
 * - Export (Ex)
 * - Encrypt (En)
 * - Decrypt (Dec)
 * - Sign message (Sm)
 * - Verify message (Vm)
 * - Sign hash (Sh)
 * - Verify hash (Vh)
 * - Derive (Der)
 *
 * The permitted usages bitfield is described below.
 *
 * +-------------------------------------------------+
 * | Bits                                            |
 * +---------+---+---+---+---+---+---+---+---+---+---+
 * | [31:10] | 9 | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
 * +---------+---+---+---+---+---+---+---+---+---+---+
 * |         |Der| Vh| Sh| Vm| Sm|Dec| En| Ex| Co| Ca|
 * +---------+---+---+---+---+---+---+---+---+---+---+
 */
typedef uint32_t smw_attr_usage_t;

/**
 * typedef smw_attr_attributes_t - Attributes
 *
 * 32-bits field used to define the attributes.
 *
 * - Persistence: Transient, persistent, permanent
 * - Lifecycle: Open, closed, closed locked
 * - R/W flags: Read only (Rl), read once (Rc)
 *
 * The attributes bitfield is described below.
 *
 * +-------------------------------------------------------+
 * | Bits                                                  |
 * +---------+---+---+-----------+-----------+-------------+
 * | [31:18] | 17| 16|   [15:8]  |   [7:4]   |    [3:0]    |
 * +---------+---+---+-----------+-----------+-------------+
 * |         | Rl| Rc| Lifecycle |           | Persistence |
 * +---------+---+---+-----------+-----------+-------------+
 */
typedef uint32_t smw_attr_attributes_t;

/**
 * typedef smw_attr_storage_id_t - Storage identifier
 *
 * 32-bits field used to define the storage identifier.
 *
 * The storage identifier is related to the Secure Subsystem.
 * It is not the purpose of this API to modify it.
 */
typedef uint32_t smw_attr_storage_id_t;

/**
 * DOC: SMW_ATTR_xxx_OFFSET (smw_attr_algo_t)
 * Parameters offsets in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_ALGO_OFFSET: Algorithm offset.
 * - SMW_ATTR_MODE_OFFSET: Mode offset.
 * - SMW_ATTR_CURVE_OFFSET: Curve offset.
 * - SMW_ATTR_HASH_OFFSET: Hash offset.
 * - SMW_ATTR_CLASS_OFFSET: Class offset.
 * - SMW_ATTR_ADD_ATTR_OFFSET: Additional parameters offset.
 */
#define SMW_ATTR_ALGO_OFFSET	  0u
#define SMW_ATTR_MODE_OFFSET	  8u
#define SMW_ATTR_CURVE_OFFSET	  8u
#define SMW_ATTR_HASH_OFFSET	  16u
#define SMW_ATTR_CLASS_OFFSET	  24u
#define SMW_ATTR_ADD_PARAM_OFFSET 32u

/**
 * DOC: SMW_ATTR_xxx_MASK (smw_attr_algo_t)
 * Parameters masks in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_ALGO_MASK: Algorithm mask.
 * - SMW_ATTR_MODE_MASK: Mode mask.
 * - SMW_ATTR_CURVE_MASK: Curve mask.
 * - SMW_ATTR_HASH_MASK: Hash mask.
 * - SMW_ATTR_CLASS_MASK: Class mask.
 * - SMW_ATTR_ADD_PARAM_MASK: Additional parameters mask.
 */
#define SMW_ATTR_ALGO_MASK	((smw_attr_algo_t)0xFF)
#define SMW_ATTR_MODE_MASK	((smw_attr_algo_t)0xFF)
#define SMW_ATTR_CURVE_MASK	((smw_attr_algo_t)0xFF)
#define SMW_ATTR_HASH_MASK	((smw_attr_algo_t)0xFF)
#define SMW_ATTR_CLASS_MASK	((smw_attr_algo_t)0xFF)
#define SMW_ATTR_ADD_PARAM_MASK ((smw_attr_algo_t)0xFF)

/**
 * DOC: SMW_ATTR_LENGTH_MIN_FLAG
 * Flag indicating the length bits represent a minimum length
 * in &typedef smw_attr_algo_t
 */
#define SMW_ATTR_LENGTH_MIN_FLAG ((smw_attr_algo_t)0x80)

/**
 * DOC: SMW_ATTR_SALT_xxx
 * Salt length in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_SALT_OFFSET: Salt length offset.
 * - SMW_ATTR_SALT_MASK: Salt length mask.
 * - SMW_ATTR_SALT_MIN_FLAG: Salt length is a minimum salt length.
 */
#define SMW_ATTR_SALT_OFFSET   SMW_ATTR_ADD_PARAM_OFFSET
#define SMW_ATTR_SALT_MASK     SMW_ATTR_ADD_PARAM_MASK
#define SMW_ATTR_SALT_MIN_FLAG SMW_ATTR_LENGTH_MIN_FLAG

/**
 * DOC: SMW_ATTR_MAC_xxx
 * MAC length in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_MAC_OFFSET: MAC length offset.
 * - SMW_ATTR_MAC_MASK: MAC length mask.
 * - SMW_ATTR_MAC_MIN_FLAG: MAC length is a minimum MAC length.
 */
#define SMW_ATTR_MAC_OFFSET   SMW_ATTR_ADD_PARAM_OFFSET
#define SMW_ATTR_MAC_MASK     SMW_ATTR_ADD_PARAM_MASK
#define SMW_ATTR_MAC_MIN_FLAG SMW_ATTR_LENGTH_MIN_FLAG

/**
 * DOC: SMW_ATTR_TAG_xxx
 * Tag length in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_TAG_OFFSET: Tag length offset.
 * - SMW_ATTR_TAG_MASK: Tag length mask.
 * - SMW_ATTR_TAG_MIN_FLAG: Tag length is a minimum tag length.
 */
#define SMW_ATTR_TAG_OFFSET   SMW_ATTR_ADD_PARAM_OFFSET
#define SMW_ATTR_TAG_MASK     SMW_ATTR_ADD_PARAM_MASK
#define SMW_ATTR_TAG_MIN_FLAG SMW_ATTR_LENGTH_MIN_FLAG

/**
 * DOC: SMW_ATTR_SIGN_PARAM_xxx
 * Asymmetric Signature parameters in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_SIGN_PARAM_OFFSET: Signature parameters offset.
 * - SMW_ATTR_SIGN_PARAM_MASK: Signature parameters mask.
 * - SMW_ATTR_SIGN_PARAM_EDDSA_NONE: No Signature EDDSA type.
 * - SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED: Signature EDDSA is pre-hashed type.
 * - SMW_ATTR_SIGN_PARAM_EDDSA_CONTEXT: Signature EDDSA is context type.
 */
#define SMW_ATTR_SIGN_PARAM_OFFSET SMW_ATTR_ADD_PARAM_OFFSET
#define SMW_ATTR_SIGN_PARAM_MASK                                               \
	(SMW_ATTR_ADD_PARAM_MASK & ~SMW_ATTR_SIGN_HASHED_FLAG)
#define SMW_ATTR_SIGN_PARAM_EDDSA_NONE	    0x00
#define SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED 0x01
#define SMW_ATTR_SIGN_PARAM_EDDSA_CONTEXT   0x02

/**
 * DOC: SMW_ATTR_SIGN_HASHED_FLAG
 * Flag indicating if the message to sign or verify given in signature
 * operation is already hashed in &typedef smw_attr_algo_t
 */
#define SMW_ATTR_SIGN_HASHED_FLAG ((smw_attr_algo_t)0x80)

/**
 * DOC: SMW_ATTR_ALGO_xxx
 * Main algorithm identifier in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_ALGO_NONE: No algorithm defined.
 * - SMW_ATTR_ALGO_AES: Advanced Encryption Standard.
 * - SMW_ATTR_ALGO_DES: Data Encryption Standard.
 * - SMW_ATTR_ALGO_DES3: Triple DES.
 * - SMW_ATTR_ALGO_CHACHA20: ChaCha20-Poly1305 .
 * - SMW_ATTR_ALGO_SM4: ShāngMì 4.
 * - SMW_ATTR_ALGO_RSA: Rivest–Shamir–Adleman.
 * - SMW_ATTR_ALGO_SM2: ShāngMì 2.
 * - SMW_ATTR_ALGO_HMAC: Hash-based message authentication code.
 * - SMW_ATTR_ALGO_DSA: Digital Signature Algorithm.
 * - SMW_ATTR_ALGO_ECDSA: Elliptic Curve Digital Signature Algorithm.
 * - SMW_ATTR_ALGO_EDDSA: Edwards-curve Digital Signature Algorithm.
 * - SMW_ATTR_ALGO_DH: Diffie–Hellman.
 * - SMW_ATTR_ALGO_ECDH: Elliptic-curve Diffie–Hellman.
 * - SMW_ATTR_ALGO_HKDF: HMAC-based Key Derivation Function.
 * - SMW_ATTR_ALGO_HKDF_EXTRACT: HMAC-based Key Derivation Function Extract step.
 * - SMW_ATTR_ALGO_HKDF_EXPAND: HMAC-based Key Derivation Function Expand step.
 * - SMW_ATTR_ALGO_TLS_1_2: Transport Layer Security 1.2.
 * - SMW_ATTR_ALGO_TLS_1_3: Transport Layer Security 1.3.
 * - SMW_ATTR_ALGO_HASH: Hash.
 */
#define SMW_ATTR_ALGO_NONE	   0x00
#define SMW_ATTR_ALGO_AES	   0x01
#define SMW_ATTR_ALGO_DES	   0x02
#define SMW_ATTR_ALGO_DES3	   0x03
#define SMW_ATTR_ALGO_CHACHA20	   0x04
#define SMW_ATTR_ALGO_SM4	   0x05
#define SMW_ATTR_ALGO_RSA	   0x06
#define SMW_ATTR_ALGO_SM2	   0x07
#define SMW_ATTR_ALGO_HMAC	   0x08
#define SMW_ATTR_ALGO_DSA	   0x09
#define SMW_ATTR_ALGO_ECDSA	   0x0A
#define SMW_ATTR_ALGO_EDDSA	   0x0B
#define SMW_ATTR_ALGO_DH	   0x0C
#define SMW_ATTR_ALGO_ECDH	   0x0D
#define SMW_ATTR_ALGO_HKDF	   0x0E
#define SMW_ATTR_ALGO_HKDF_EXTRACT 0x0F
#define SMW_ATTR_ALGO_HKDF_EXPAND  0x10
#define SMW_ATTR_ALGO_TLS_1_2	   0x11
#define SMW_ATTR_ALGO_TLS_1_3	   0x12
#define SMW_ATTR_ALGO_HASH	   0xFF

/**
 * DOC: SMW_ATTR_MODE_xxx
 * Mode associated to the main algorithm in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_MODE_NONE: No mode defined.
 * - SMW_ATTR_MODE_ECB_NO_PAD: Electronic Code Book No Padding.
 * - SMW_ATTR_MODE_CBC_NO_PAD: Cipher block chaining No Padding.
 * - SMW_ATTR_MODE_CFB: Ciphertext Feedback.
 * - SMW_ATTR_MODE_CTR: Counter Mode.
 * - SMW_ATTR_MODE_CTS: Ciphertext Stealing.
 * - SMW_ATTR_MODE_OFB: Output Feedback.
 * - SMW_ATTR_MODE_XTS: XEX Tweakable Block Ciphertext Stealing.
 * - SMW_ATTR_MODE_CCM: Counter with CBC-MAC Mode.
 * - SMW_ATTR_MODE_GCM: Galois/Counter Mode.
 * - SMW_ATTR_MODE_PKCS1_1_5: Public-Key Cryptography Standards 1.5.
 * - SMW_ATTR_MODE_OAEP: Optimal Asymmetric Encryption Padding.
 * - SMW_ATTR_MODE_PSS: Probabilistic Signature Scheme.
 * - SMW_ATTR_MODE_PKCS5: Password-Based Cryptography Specification.
 * - SMW_ATTR_MODE_CMAC: Cipher-based Message Authentication Code.
 * - SMW_ATTR_MODE_POLY1305: Poly1305-AES.
 * - SMW_ATTR_MODE_CLIENT: Client (TLS 1.2).
 * - SMW_ATTR_MODE_SERVER: Sever (TLS 1.2).
 * - SMW_ATTR_MODE_NO_PAD: Asymmetric Encryption with no padding.
 * - SMW_ATTR_MODE_ANY: Any mode.
 */
#define SMW_ATTR_MODE_NONE	 0x00
#define SMW_ATTR_MODE_ECB_NO_PAD 0x01
#define SMW_ATTR_MODE_CBC_NO_PAD 0x02
#define SMW_ATTR_MODE_CFB	 0x03
#define SMW_ATTR_MODE_CTR	 0x04
#define SMW_ATTR_MODE_CTS	 0x05
#define SMW_ATTR_MODE_OFB	 0x06
#define SMW_ATTR_MODE_XTS	 0x07
#define SMW_ATTR_MODE_CCM	 0x08
#define SMW_ATTR_MODE_GCM	 0x09
#define SMW_ATTR_MODE_PKCS1_1_5	 0x0A
#define SMW_ATTR_MODE_OAEP	 0x0B
#define SMW_ATTR_MODE_PSS	 0x0C
#define SMW_ATTR_MODE_PKCS5	 0x0D
#define SMW_ATTR_MODE_CMAC	 0x0E
#define SMW_ATTR_MODE_POLY1305	 0x0F
#define SMW_ATTR_MODE_CLIENT	 0x10
#define SMW_ATTR_MODE_SERVER	 0x11
#define SMW_ATTR_MODE_NO_PAD	 0x12
#define SMW_ATTR_MODE_ANY	 0xFF

/**
 * DOC: SMW_ATTR_CURVE_xxx
 * Curve associated to the main algorithm in &typedef smw_attr_algo_t
 *
 * - SMW_ATTR_CURVE_NONE: No curve defined.
 * - SMW_ATTR_CURVE_SECP_R1: Secp R1 curve (aka NIST P).
 * - SMW_ATTR_CURVE_BRAINPOOL_R1: Brainpool R1 curve.
 * - SMW_ATTR_CURVE_BRAINPOOL_T1: Brainpool T1 curve.
 * - SMW_ATTR_CURVE_ED25519: Twisted Edwards25519.
 * - SMW_ATTR_CURVE_ED448: Twisted Edwards448.
 * - SMW_ATTR_CURVE_ANY: Any curve.
 */
#define SMW_ATTR_CURVE_NONE	    0x00
#define SMW_ATTR_CURVE_SECP_R1	    0x01
#define SMW_ATTR_CURVE_BRAINPOOL_R1 0x02
#define SMW_ATTR_CURVE_BRAINPOOL_T1 0x03
#define SMW_ATTR_CURVE_ED25519	    0x04
#define SMW_ATTR_CURVE_ED448	    0x05
#define SMW_ATTR_CURVE_ANY	    0xFF

/**
 * DOC: SMW_ATTR_HASH_xxx
 * Hash algorithm associated to the main algorithm in &typedef smw_attr_algo_t
 * or hash algorithm used in case of digest operation
 *
 * - SMW_ATTR_HASH_NONE: No hash algorithm defined.
 * - SMW_ATTR_HASH_MD5: Message Digest 5.
 * - SMW_ATTR_HASH_SHA1: Secure Hash Algorithm 1.
 * - SMW_ATTR_HASH_SHA224: Secure Hash Algorithm 2, 224 bits.
 * - SMW_ATTR_HASH_SHA256: Secure Hash Algorithm 2, 256 bits.
 * - SMW_ATTR_HASH_SHA384: Secure Hash Algorithm 2, 384 bits.
 * - SMW_ATTR_HASH_SHA512: Secure Hash Algorithm 2, 512 bits.
 * - SMW_ATTR_HASH_SHA3_224: Secure Hash Algorithm 3, 224 bits.
 * - SMW_ATTR_HASH_SHA3_256: Secure Hash Algorithm 3, 256 bits.
 * - SMW_ATTR_HASH_SHA3_384: Secure Hash Algorithm 3, 384 bits.
 * - SMW_ATTR_HASH_SHA3_512: Secure Hash Algorithm 3, 512 bits.
 * - SMW_ATTR_HASH_SM3: ShangMi 3.
 * - SMW_ATTR_HASH_SHAKE128: Shake128.
 * - SMW_ATTR_HASH_SHAKE256: Shake1256.
 * - SMW_ATTR_HASH_ANY: Any hash algorithm.
 */
#define SMW_ATTR_HASH_NONE     0x00
#define SMW_ATTR_HASH_MD5      0x01
#define SMW_ATTR_HASH_SHA1     0x02
#define SMW_ATTR_HASH_SHA224   0x03
#define SMW_ATTR_HASH_SHA256   0x04
#define SMW_ATTR_HASH_SHA384   0x05
#define SMW_ATTR_HASH_SHA512   0x06
#define SMW_ATTR_HASH_SHA3_224 0x07
#define SMW_ATTR_HASH_SHA3_256 0x08
#define SMW_ATTR_HASH_SHA3_384 0x09
#define SMW_ATTR_HASH_SHA3_512 0x0A
#define SMW_ATTR_HASH_SM3      0x0B
#define SMW_ATTR_HASH_SHAKE128 0x0C
#define SMW_ATTR_HASH_SHAKE256 0x0D
#define SMW_ATTR_HASH_ANY      0xFF

/**
 * DOC: SMW_ATTR_CLASS_xxx
 * Class of operation of the main algorithm in &typedef smw_attr_algo_t
 * or hash algorithm used in case of digest operation
 *
 * - SMW_ATTR_CLASS_NONE: No class of operation defined.
 * - SMW_ATTR_CLASS_DIGEST: Digest calculation.
 * - SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION: Symmetric encryption.
 * - SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION: Asymmetric encryption.
 * - SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE: Asymmetric signature.
 * - SMW_ATTR_CLASS_MAC: Message Authentication Code.
 * - SMW_ATTR_CLASS_AEAD: Authenticated Encryption with Associated Data.
 * - SMW_ATTR_CLASS_KEY_DERIVATION: Key derivation.
 * - SMW_ATTR_CLASS_KEY_ATTESTATION: Key attestation.
 */
#define SMW_ATTR_CLASS_NONE		     0x00
#define SMW_ATTR_CLASS_DIGEST		     0x01
#define SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION  0x02
#define SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION 0x03
#define SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE  0x04
#define SMW_ATTR_CLASS_MAC		     0x05
#define SMW_ATTR_CLASS_AEAD		     0x06
#define SMW_ATTR_CLASS_KEY_DERIVATION	     0x07
#define SMW_ATTR_CLASS_KEY_ATTESTATION	     0x08

/**
 * DOC: SMW_ATTR_USAGE_xxx
 * Key usage in &typedef smw_attr_usage_t
 *
 * - SMW_ATTR_USAGE_NONE: No key usage defined.
 * - SMW_ATTR_USAGE_CACHE: Permission to cache the key.
 * - SMW_ATTR_USAGE_COPY: Permission to copy the key.
 * - SMW_ATTR_USAGE_EXPORT: Permission to export the key.
 * - SMW_ATTR_USAGE_ENCRYPT: Permission to encrypt a message with the key.
 * - SMW_ATTR_USAGE_DECRYPT: Permission to decrypt a message with the key.
 * - SMW_ATTR_USAGE_SIGN_MESSAGE: Permission to sign a message with the key.
 * - SMW_ATTR_USAGE_VERIFY_MESSAGE: Permission to verify a message signature
 *   with the key.
 * - SMW_ATTR_USAGE_SIGN_HASH: Permission to sign a message hash with the key.
 * - SMW_ATTR_USAGE_VERIFY_HASH: Permission to verify a message hash with the
 *   key.
 * - SMW_ATTR_USAGE_DERIVE: Permission to derive other keys from this key.
 */
#define SMW_ATTR_USAGE_NONE	      0x00000000
#define SMW_ATTR_USAGE_CACHE	      0x00000001
#define SMW_ATTR_USAGE_COPY	      0x00000002
#define SMW_ATTR_USAGE_EXPORT	      0x00000004
#define SMW_ATTR_USAGE_ENCRYPT	      0x00000008
#define SMW_ATTR_USAGE_DECRYPT	      0x00000010
#define SMW_ATTR_USAGE_SIGN_MESSAGE   0x00000020
#define SMW_ATTR_USAGE_VERIFY_MESSAGE 0x00000040
#define SMW_ATTR_USAGE_SIGN_HASH      0x00000080
#define SMW_ATTR_USAGE_VERIFY_HASH    0x00000100
#define SMW_ATTR_USAGE_DERIVE	      0x00000200

/**
 * DOC: SMW_ATTR_xxx_OFFSET (smw_attr_attributes_t)
 * Attributes offsets in &typedef smw_attr_attributes_t
 *
 * - SMW_ATTR_PERSISTENCE_OFFSET: Persistence offset.
 * - SMW_ATTR_LIFECYCLE_OFFSET: Lifecycle offset.
 * - SMW_ATTR_RW_FLAGS_OFFSET: R/W flags offset.
 */
#define SMW_ATTR_PERSISTENCE_OFFSET 0u
#define SMW_ATTR_LIFECYCLE_OFFSET   8u
#define SMW_ATTR_RW_FLAGS_OFFSET    16u

/**
 * DOC: SMW_ATTR_xxx_MASK (smw_attr_attributes_t)
 * Attributes masks in &typedef smw_attr_attributes_t
 *
 * - SMW_ATTR_PERSISTENCE_MASK: Persistence mask.
 * - SMW_ATTR_LIFECYCLE_MASK: Lifecycle mask.
 * - SMW_ATTR_RW_FLAGS_MASK: R/W flags mask.
 */
#define SMW_ATTR_PERSISTENCE_MASK ((smw_attr_attributes_t)0x0F)
#define SMW_ATTR_LIFECYCLE_MASK	  ((smw_attr_attributes_t)0xFF)
#define SMW_ATTR_RW_FLAGS_MASK	  ((smw_attr_attributes_t)0xFF)

/**
 * DOC: SMW_ATTR_PERSISTENCE_xxx
 * Persistence in &typedef smw_attr_attributes_t
 *
 * - SMW_ATTR_PERSISTENCE_TRANSIENT: Transient.
 * - SMW_ATTR_PERSISTENCE_PERSISTENT: Persistent.
 * - SMW_ATTR_PERSISTENCE_PERMANENT: Permanent.
 */
#define SMW_ATTR_PERSISTENCE_TRANSIENT	0x0
#define SMW_ATTR_PERSISTENCE_PERSISTENT 0x1
#define SMW_ATTR_PERSISTENCE_PERMANENT	0x2

/**
 * DOC: SMW_ATTR_LIFECYCLE_xxx
 * Lifecycle in &typedef smw_attr_attributes_t
 *
 * - SMW_ATTR_LIFECYCLE_CURRENT: Current lifecycle.
 * - SMW_ATTR_LIFECYCLE_OPEN: Open.
 * - SMW_ATTR_LIFECYCLE_CLOSED: Closed.
 * - SMW_ATTR_LIFECYCLE_CLOSED_LOCKED: Close locked.
 */
#define SMW_ATTR_LIFECYCLE_CURRENT	 0x01
#define SMW_ATTR_LIFECYCLE_OPEN		 0x02
#define SMW_ATTR_LIFECYCLE_CLOSED	 0x04
#define SMW_ATTR_LIFECYCLE_CLOSED_LOCKED 0x08

/**
 * DOC: SMW_ATTR_RW_FLAGS_xxx
 * R/W flags in &typedef smw_attr_attributes_t
 *
 * - SMW_ATTR_RW_FLAGS_NONE: No R/W flag defined.
 * - SMW_ATTR_RW_FLAGS_READ_ONLY: Read only.
 * - SMW_ATTR_RW_FLAGS_READ_ONCE: Read once.
 */
#define SMW_ATTR_RW_FLAGS_NONE	    0x00
#define SMW_ATTR_RW_FLAGS_READ_ONLY 0x01
#define SMW_ATTR_RW_FLAGS_READ_ONCE 0x02

/* Utils macros used to define the attributes API */
#define SMW_ATTR_NAME(group, name)                                             \
	((SMW_ATTR_##group##_##name & SMW_ATTR_##group##_MASK)                 \
	 << SMW_ATTR_##group##_OFFSET)

#define SMW_ATTR_VALUE(group, value)                                           \
	(((smw_attr_algo_t)(value) & (SMW_ATTR_##group##_MASK))                \
	 << SMW_ATTR_##group##_OFFSET)

#define SMW_ATTR_SET_CLEAR_NAME(flags, group, name)                            \
	(((flags) & ~(SMW_ATTR_##group##_MASK << SMW_ATTR_##group##_OFFSET)) | \
	 (SMW_ATTR_##group##_##name << SMW_ATTR_##group##_OFFSET))

#define SMW_ATTR_SET_CLEAR_VALUE(flags, group, value)                          \
	(((flags) & ~(SMW_ATTR_##group##_MASK << SMW_ATTR_##group##_OFFSET)) | \
	 (((typeof(flags))(value) & (SMW_ATTR_##group##_MASK))                 \
	  << SMW_ATTR_##group##_OFFSET))

#define SMW_ATTR_GET_VALUE(flags, group)                                       \
	(((flags) >> SMW_ATTR_##group##_OFFSET) & SMW_ATTR_##group##_MASK)

#define SMW_ATTR_SET_MASK(flags, group, name)                                  \
	((flags) |= SMW_ATTR_##group##_##name)

#define SMW_ATTR_IS_MASK_SET(flags, group, name)                               \
	(((flags) & (SMW_ATTR_##group##_##name)) == SMW_ATTR_##group##_##name)

#define SMW_ATTR_IS_NAME_SET(flags, group, name)                               \
	((((flags) >> SMW_ATTR_##group##_OFFSET) &                             \
	  (SMW_ATTR_##group##_MASK)) == SMW_ATTR_##group##_##name)

#define SMW_ATTR_SET_NAME_SHIFTED(flags, group, name)                          \
	((flags) | (SMW_ATTR_##group##_##name << SMW_ATTR_##group##_OFFSET))

#define SMW_ATTR_IS_NAME_SHIFTED_SET(flags, group, name)                       \
	((((flags) >> SMW_ATTR_##group##_OFFSET) &                             \
	  (SMW_ATTR_##group##_##name)) == SMW_ATTR_##group##_##name)

/**
 * SMW_ATTR_SET_LENGTH() - Set length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Length associated to @algo.
 *
 * This macro sets the length.
 *
 * Return:
 * A valid algorithm with length bits set to @length.
 */
#define SMW_ATTR_SET_LENGTH(algo, length)                                      \
	(((algo) & ~(SMW_ATTR_ADD_PARAM_MASK << SMW_ATTR_ADD_PARAM_OFFSET)) |  \
	 (((smw_attr_algo_t)(length) & (SMW_ATTR_ADD_PARAM_MASK) &             \
	   ~SMW_ATTR_LENGTH_MIN_FLAG)                                          \
	  << SMW_ATTR_ADD_PARAM_OFFSET))

/**
 * SMW_ATTR_SET_MIN_LENGTH() - Set min length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Length associated to @algo.
 *
 * This macro sets the min length.
 *
 * Return:
 * A valid algorithm with min length bits set to @length.
 */
#define SMW_ATTR_SET_MIN_LENGTH(algo, length)                                  \
	(((algo) & ~(SMW_ATTR_ADD_PARAM_MASK << SMW_ATTR_ADD_PARAM_OFFSET)) |  \
	 ((((smw_attr_algo_t)(length) & (SMW_ATTR_ADD_PARAM_MASK)) |           \
	   SMW_ATTR_LENGTH_MIN_FLAG)                                           \
	  << SMW_ATTR_ADD_PARAM_OFFSET))

/**
 * SMW_ATTR_IS_MIN_LENGTH() - Whether the min length bit is set.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the min length bit is set or not.
 *
 * Return:
 * 1 if the min length bit is set, 0 otherwise.
 */
#define SMW_ATTR_IS_MIN_LENGTH(algo)                                           \
	((((algo) >> SMW_ATTR_ADD_PARAM_OFFSET) & SMW_ATTR_ADD_PARAM_MASK &    \
	  SMW_ATTR_LENGTH_MIN_FLAG) == SMW_ATTR_LENGTH_MIN_FLAG)

/**
 * SMW_ATTR_GET_LENGTH() - Get length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns the length value set for @algo.
 *
 * Return:
 * Length set for @algo.
 */
#define SMW_ATTR_GET_LENGTH(algo)                                              \
	(((algo) >> SMW_ATTR_ADD_PARAM_OFFSET) & SMW_ATTR_ADD_PARAM_MASK &     \
	 ~SMW_ATTR_LENGTH_MIN_FLAG)

/**
 * SMW_ATTR_SET_SALT_LENGTH() - Set salt length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Salt length associated to @algo.
 *
 * This macro sets the salt length.
 *
 * Return:
 * A valid algorithm with salt length bits set to @length.
 */
#define SMW_ATTR_SET_SALT_LENGTH(algo, length) SMW_ATTR_SET_LENGTH(algo, length)

/**
 * SMW_ATTR_SET_MAC_LENGTH() - Set MAC length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: MAC length associated to @algo.
 *
 * This macro sets the MAC length.
 *
 * Return:
 * A valid algorithm with MAC length bits set to @length.
 */
#define SMW_ATTR_SET_MAC_LENGTH(algo, length) SMW_ATTR_SET_LENGTH(algo, length)

/**
 * SMW_ATTR_SET_TAG_LENGTH() - Set tag length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Tag length associated to @algo.
 *
 * This macro sets the tag length.
 *
 * Return:
 * A valid algorithm with tag length bits set to @length.
 */
#define SMW_ATTR_SET_TAG_LENGTH(algo, length) SMW_ATTR_SET_LENGTH(algo, length)

/**
 * SMW_ATTR_SET_MIN_SALT_LENGTH() - Set min salt length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Salt length associated to @algo.
 *
 * This macro sets the min salt length.
 *
 * Return:
 * A valid algorithm with min salt length bits set to @length.
 */
#define SMW_ATTR_SET_MIN_SALT_LENGTH(algo, length)                             \
	SMW_ATTR_SET_MIN_LENGTH(algo, length)

/**
 * SMW_ATTR_SET_MIN_MAC_LENGTH() - Set min MAC length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: MAC length associated to @algo.
 *
 * This macro sets the min MAC length.
 *
 * Return:
 * A valid algorithm with min MAC length bits set to @length.
 */
#define SMW_ATTR_SET_MIN_MAC_LENGTH(algo, length)                              \
	SMW_ATTR_SET_MIN_LENGTH(algo, length)

/**
 * SMW_ATTR_SET_MIN_TAG_LENGTH() - Set min tag length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @length: Tag length associated to @algo.
 *
 * This macro sets the min tag length.
 *
 * Return:
 * A valid algorithm with min tag length bits set to @length.
 */
#define SMW_ATTR_SET_MIN_TAG_LENGTH(algo, length)                              \
	SMW_ATTR_SET_MIN_LENGTH(algo, length)

/**
 * SMW_ATTR_IS_MIN_SALT_LENGTH() - Whether the min salt length bit is set.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the min salt length bit is set or not.
 *
 * Return:
 * 1 if the min salt length bit is set, 0 otherwise.
 */
#define SMW_ATTR_IS_MIN_SALT_LENGTH(algo) SMW_ATTR_IS_MIN_LENGTH(algo)

/**
 * SMW_ATTR_IS_MIN_MAC_LENGTH() - Whether the min MAC length bit is set.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the min MAC length bit is set or not.
 *
 * Return:
 * 1 if the min MAC length bit is set, 0 otherwise.
 */
#define SMW_ATTR_IS_MIN_MAC_LENGTH(algo) SMW_ATTR_IS_MIN_LENGTH(algo)

/**
 * SMW_ATTR_IS_MIN_TAG_LENGTH() - Whether the min tag length bit is set.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the min tag length bit is set or not.
 *
 * Return:
 * 1 if the min tag length bit is set, 0 otherwise.
 */
#define SMW_ATTR_IS_MIN_TAG_LENGTH(algo) SMW_ATTR_IS_MIN_LENGTH(algo)

/**
 * SMW_ATTR_GET_SALT_LENGTH() - Get salt length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns the salt length value set for @algo.
 *
 * Return:
 * Length set for @algo.
 */
#define SMW_ATTR_GET_SALT_LENGTH(algo) SMW_ATTR_GET_LENGTH(algo)

/**
 * SMW_ATTR_GET_MAC_LENGTH() - Get MAC length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns the MAC length value set for @algo.
 *
 * Return:
 * Length set for @algo.
 */
#define SMW_ATTR_GET_MAC_LENGTH(algo) SMW_ATTR_GET_LENGTH(algo)

/**
 * SMW_ATTR_GET_TAG_LENGTH() - Get tag length.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns the tag length value set for @algo.
 *
 * Return:
 * Length set for @algo.
 */
#define SMW_ATTR_GET_TAG_LENGTH(algo) SMW_ATTR_GET_LENGTH(algo)

/**
 * SMW_ATTR_SET_MSG_HASHED() - Set Asymmetric signature message hashed flag.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro sets the signature flag indicating input message is hashed.
 *
 * Return:
 * A valid algorithm with signature message flag set.
 */
#define SMW_ATTR_SET_MSG_HASHED(algo)                                          \
	((algo) | (SMW_ATTR_SIGN_HASHED_FLAG << SMW_ATTR_SIGN_PARAM_OFFSET))

/**
 * SMW_ATTR_IS_MSG_HASHED() - Whether signature message hashed flag is set.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the signature input message hashed flag is set or
 * not.
 *
 * Return:
 * 1 if the message hashed flag is set, 0 otherwise.
 */
#define SMW_ATTR_IS_MSG_HASHED(algo)                                           \
	((((algo) >> SMW_ATTR_SIGN_PARAM_OFFSET) &                             \
	  SMW_ATTR_SIGN_HASHED_FLAG) == SMW_ATTR_SIGN_HASHED_FLAG)

/**
 * SMW_ATTR_GET_SIGN_PARAM() - Get Asymmetric signature parameter.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns the signature parameter set for @algo.
 *
 * Return:
 * Signature parameter set for @algo.
 */
#define SMW_ATTR_GET_SIGN_PARAM(algo)                                          \
	(((algo) >> SMW_ATTR_SIGN_PARAM_OFFSET) & SMW_ATTR_SIGN_PARAM_MASK)

/**
 * SMW_ATTR_SET_SIGN_PARAM() - Set Asymmetric signature parameter.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 * @param: Parameter associated to @algo.
 *
 * This macro sets the signature parameter.
 *
 * Return:
 * A valid algorithm with signature parameter set to @param.
 */
#define SMW_ATTR_SET_SIGN_PARAM(algo, param)                                   \
	(((algo) &                                                             \
	  ~(SMW_ATTR_SIGN_PARAM_MASK << SMW_ATTR_SIGN_PARAM_OFFSET)) |         \
	 (((smw_attr_algo_t)(param) & (SMW_ATTR_SIGN_PARAM_MASK))              \
	  << SMW_ATTR_SIGN_PARAM_OFFSET))

/**
 * SMW_ATTR_SET_SIGN_EDDSA_PREHASHED() - Set EDDSA pre-hashed signature.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro sets the asymmetric EDDSA signature parameter pre-hashed.
 *
 * Return:
 * A valid algorithm with EDDSA signature parameter pre-hashed set.
 */
#define SMW_ATTR_SET_SIGN_EDDSA_PREHASHED(algo)                                \
	SMW_ATTR_SET_SIGN_PARAM(algo, SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED)

/**
 * SMW_ATTR_IS_SIGN_EDDSA_PREHASHED() - Whether the signature EDDSA is pre-hashed.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the asymmetric EDDSA signature parameter
 * pre-hashed is set or not.
 *
 * Return:
 * 1 if the signature message is pre-hashed type, 0 otherwise.
 */
#define SMW_ATTR_IS_SIGN_EDDSA_PREHASHED(algo)                                 \
	SMW_ATTR_IS_MASK_SET(SMW_ATTR_GET_SIGN_PARAM(algo), SIGN_PARAM,        \
			     EDDSA_PREHASHED)

/**
 * SMW_ATTR_SET_SIGN_EDDSA_CONTEXT() - Set EDDSA context signature.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro sets the asymmetric EDDSA signature parameter context.
 *
 * Return:
 * A valid algorithm with EDDSA signature parameter context set.
 */
#define SMW_ATTR_SET_SIGN_EDDSA_CONTEXT(algo)                                  \
	SMW_ATTR_SET_SIGN_PARAM(algo, SMW_ATTR_SIGN_PARAM_EDDSA_CONTEXT)

/**
 * SMW_ATTR_IS_SIGN_EDDSA_CONTEXT() - Whether the EDDSE signature uses a context.
 * @algo: A valid algorithm. See &smw_attr_algo_t.
 *
 * This macro returns whether the asymmetric EDDSA signature parameter context
 * is set or not.
 *
 * Return:
 * 1 if the signature message uses a context, 0 otherwise.
 */
#define SMW_ATTR_IS_SIGN_EDDSA_CONTEXT(algo)                                   \
	SMW_ATTR_IS_MASK_SET(SMW_ATTR_GET_SIGN_PARAM(algo), SIGN_PARAM,        \
			     EDDSA_CONTEXT)

/**
 * SMW_ATTR_ALGO_DIGEST() - Build a digest algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds a digest algorithm using the @hash algorithm.
 *
 * Return:
 * A valid digest algorithm.
 */
#define SMW_ATTR_ALGO_DIGEST(hash)                                             \
	(SMW_ATTR_NAME(CLASS, DIGEST) | SMW_ATTR_NAME(ALGO, HASH) |            \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION() - Build a symmetric encryption algorithm.
 * @algo: A valid main algorithm for symmetric encryption. See smw_attr_algo_t.
 * @mode: A valid mode. See smw_attr_algo_t.
 *
 * This macro builds a symmetric encryption algorithm given
 * the main algorithm @algo and the @mode.
 *
 * Return:
 * A valid symmetric encryption algorithm.
 */
#define SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(algo, mode)                         \
	(SMW_ATTR_NAME(CLASS, SYMMETRIC_ENCRYPTION) |                          \
	 SMW_ATTR_VALUE(ALGO, algo) | SMW_ATTR_VALUE(MODE, mode))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION() - Build an asymmetric encryption
 * algorithm.
 * @algo: A valid main algorithm for asymmetric encryption. See smw_attr_algo_t.
 * @mode: A valid mode. See smw_attr_algo_t.
 *
 * This macro builds an asymmetric encryption algorithm given
 * the main algorithm @algo and the @mode.
 *
 * Return:
 * A valid asymmetric encryption algorithm.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION(algo, mode)                        \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_ENCRYPTION) |                         \
	 SMW_ATTR_VALUE(ALGO, algo) | SMW_ATTR_VALUE(MODE, mode))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA() - Build an asymmetric signature
 * ECDSA algorithm.
 * @curve: A valid curve. See smw_attr_algo_t.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an asymmetric signature ECDSA algorithm given
 * the @curve and the @hash algorithm.
 *
 * Return:
 * A valid asymmetric signature ECDSA algorithm.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(curve, hash)                  \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, ECDSA) | SMW_ATTR_VALUE(CURVE, curve) |           \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA() - Build an asymmetric signature
 * EDDSA algorithm.
 * @curve: A valid curve. See smw_attr_algo_t.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 * @param: A valid EDDSA parameter algorithm. See smw_attr_algo_t
 *
 * This macro builds an asymmetric signature EDDSA algorithm given
 * the @curve, the @hash algorithm and the @param parameter.
 *
 * The @hash algorithm function of the signature scheme and may not be used.
 *
 * Return:
 * A valid asymmetric signature EDDSA algorithm.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(curve, hash, param)           \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, EDDSA) | SMW_ATTR_VALUE(CURVE, curve) |           \
	 SMW_ATTR_VALUE(HASH, hash) | SMW_ATTR_VALUE(SIGN_PARAM, param))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_DSA() - Build an asymmetric signature
 * DSA algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an asymmetric signature DSA algorithm given
 * the @hash algorithm.
 *
 * Return:
 * A valid asymmetric signature DSA algorithm.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_DSA(hash)                           \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, DSA) | SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA() - Build an asymmetric signature
 * RSA algorithm.
 * @mode: A valid mode. See smw_attr_algo_t.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 * @salt: Salt length.
 *
 * This macro builds an asymmetric signature RSA algorithm given
 * the @mode, the @hash algorithm and the @salt length.
 *
 * Return:
 * A valid asymmetric signature RSA algorithm.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(mode, hash, salt)               \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, RSA) | SMW_ATTR_VALUE(MODE, mode) |               \
	 SMW_ATTR_VALUE(HASH, hash) | SMW_ATTR_VALUE(SALT, salt))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_CLIENT() - Build an asymmetric
 * signature TLS1.2 algorithm with label `CLIENT`.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an asymmetric signature TLS1.2 algorithm
 * with `CLIENT` label given the @hash algorithm.
 *
 * Return:
 * A valid asymmetric signature TLS1.2 algorithm with label `CLIENT`.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_CLIENT(hash)                \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, TLS_1_2) | SMW_ATTR_NAME(MODE, CLIENT) |          \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_SERVER() - Build an asymmetric
 * signature TLS1.2 algorithm with label `SERVER`.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an asymmetric signature TLS1.2 algorithm
 * with `SERVER` label given the @hash algorithm.
 *
 * Return:
 * A valid asymmetric signature TLS1.2 algorithm with label `SERVER`.
 */
#define SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_SERVER(hash)                \
	(SMW_ATTR_NAME(CLASS, ASYMMETRIC_SIGNATURE) |                          \
	 SMW_ATTR_NAME(ALGO, TLS_1_2) | SMW_ATTR_NAME(MODE, SERVER) |          \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_MAC() - Build a MAC algorithm.
 * @algo: A valid main algorithm. See smw_attr_algo_t.
 * @mode: A valid mode. See smw_attr_algo_t.
 * @mac: MAC length.
 *
 * This macro builds a MAC algorithm given the main algorithm @algo,
 * the @mode and the @hash algorithm.
 * The main algorithm @algo is not HMAC.
 *
 * Return:
 * A valid MAC algorithm.
 */
#define SMW_ATTR_ALGO_MAC(algo, mode, mac)                                     \
	(SMW_ATTR_NAME(CLASS, MAC) | SMW_ATTR_VALUE(ALGO, algo) |              \
	 SMW_ATTR_VALUE(MODE, mode) | SMW_ATTR_VALUE(MAC, mac))

/**
 * SMW_ATTR_ALGO_MAC_HMAC() - Build a HMAC algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 * @mac: MAC length.
 *
 * This macro builds a HMAC algorithm given the @hash algorithm
 * and the @mac length.
 *
 * Return:
 * A valid HMAC algorithm.
 */
#define SMW_ATTR_ALGO_MAC_HMAC(hash, mac)                                      \
	(SMW_ATTR_NAME(CLASS, MAC) | SMW_ATTR_NAME(ALGO, HMAC) |               \
	 SMW_ATTR_VALUE(HASH, hash) | SMW_ATTR_VALUE(MAC, mac))

/**
 * SMW_ATTR_ALGO_AEAD() - Build an AEAD algorithm.
 * @algo: A valid main algorithm. See smw_attr_algo_t.
 * @mode: A valid mode. See smw_attr_algo_t.
 * @tag: Tag length.
 *
 * This macro builds an AEAD algorithm given the main algorithm @algo,
 * the @mode and the @tag length.
 *
 * Return:
 * A valid AEAD algorithm.
 */
#define SMW_ATTR_ALGO_AEAD(algo, mode, tag)                                    \
	(SMW_ATTR_NAME(CLASS, AEAD) | SMW_ATTR_VALUE(ALGO, algo) |             \
	 SMW_ATTR_VALUE(MODE, mode) | SMW_ATTR_VALUE(TAG, tag))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_HKDF() - Build an HKDF key derivation algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an HKDF key derivation algorithm given the @hash algorithm.
 *
 * Return:
 * A valid HKDF key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(hash)                                \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, HKDF) |    \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_DH() - Build the DH key derivation algorithm.
 *
 * This macro builds the DH key derivation algorithm.
 *
 * Return:
 * DH key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_DH()                                      \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, DH))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_ECDH() - Build the ECDH key derivation algorithm.
 *
 * This macro builds the ECDH key derivation algorithm.
 *
 * Return:
 * ECDH key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_ECDH()                                    \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, ECDH))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_EDDSA() - Build an EDDSA key derivation algorithm.
 * @curve: A valid curve. See smw_attr_algo_t.
 *
 * This macro builds an EDDSA key derivation algorithm given the @curve.
 *
 * Return:
 * A valid EDDSA key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_EDDSA(curve)                              \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, EDDSA) |   \
	 SMW_ATTR_VALUE(CURVE, curve))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_TLS12() - Build the TLS 1.2 derivation algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds the TLS 1.2 key derivation algorithm.
 *
 * Return:
 * TLS 1.2 key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_TLS12(hash)                               \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, TLS_1_2) | \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_KEY_DERIVATION_TLS13() - Build the TLS 1.3 derivation algorithm.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds the TLS 1.3 key derivation algorithm.
 *
 * Return:
 * TLS 1.3 key derivation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_DERIVATION_TLS13(hash)                               \
	(SMW_ATTR_NAME(CLASS, KEY_DERIVATION) | SMW_ATTR_NAME(ALGO, TLS_1_3) | \
	 SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_ALGO_KEY_ATTESTATION_MAC() - Build a MAC key attestation algorithm.
 * @algo: A valid main algorithm. See smw_attr_algo_t.
 * @mode: A valid mode. See smw_attr_algo_t.
 * @mac: MAC length.
 *
 * This macro builds a MAC key attestation algorithm
 * given the main algorithm @algo, the @mode and the @mac length.
 *
 * Return:
 * A valid MAC key attestation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_ATTESTATION_MAC(algo, mode, mac)                     \
	(SMW_ATTR_NAME(CLASS, KEY_ATTESTATION) | SMW_ATTR_VALUE(ALGO, algo) |  \
	 SMW_ATTR_VALUE(MODE, mode) | SMW_ATTR_VALUE(MAC, mac))

/**
 * SMW_ATTR_ALGO_KEY_ATTESTATION_ECDSA() - Build an ECDSA key attestation
 * algorithm.
 * @curve: A valid curve. See smw_attr_algo_t.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro builds an ECDSA key attestation algorithm
 * given the @curve and the @hash algorithm.
 *
 * Return:
 * A valid ECDSA key attestation algorithm.
 */
#define SMW_ATTR_ALGO_KEY_ATTESTATION_ECDSA(curve, hash)                       \
	(SMW_ATTR_NAME(CLASS, KEY_ATTESTATION) | SMW_ATTR_NAME(ALGO, ECDSA) |  \
	 SMW_ATTR_VALUE(CURVE, curve) | SMW_ATTR_VALUE(HASH, hash))

/**
 * SMW_ATTR_GET_ALGO() - Get the main algorithm.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 *
 * This macro extracts the main algorithm of @algo.
 *
 * Return:
 * The main algorithm.
 */
#define SMW_ATTR_GET_ALGO(algo) SMW_ATTR_GET_VALUE(algo, ALGO)

/**
 * SMW_ATTR_GET_MODE() - Get the mode.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 *
 * This macro extracts the mode of @algo.
 *
 * Return:
 * The mode.
 */
#define SMW_ATTR_GET_MODE(algo) SMW_ATTR_GET_VALUE(algo, MODE)

/**
 * SMW_ATTR_GET_CURVE() - Get the curve.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 *
 * This macro extracts the curve of @algo.
 *
 * Return:
 * The curve.
 */
#define SMW_ATTR_GET_CURVE(algo) SMW_ATTR_GET_VALUE(algo, CURVE)

/**
 * SMW_ATTR_GET_HASH() - Get the hash algorithm.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 *
 * This macro extracts the hash algorithm of @algo.
 *
 * Return:
 * The hash algorithm.
 */
#define SMW_ATTR_GET_HASH(algo) SMW_ATTR_GET_VALUE(algo, HASH)

/**
 * SMW_ATTR_GET_CLASS() - Get the class.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 *
 * This macro extracts the class of @algo.
 *
 * Return:
 * The class.
 */
#define SMW_ATTR_GET_CLASS(algo) SMW_ATTR_GET_VALUE(algo, CLASS)

/**
 * SMW_ATTR_SET_HASH() - Set the hash algorithm.
 * @algo: A valid algorithm. See smw_attr_algo_t.
 * @hash: A valid hash algorithm. See smw_attr_algo_t.
 *
 * This macro sets the hash algorithm of @algo.
 *
 * Return:
 * A valid algorithm.
 */
#define SMW_ATTR_SET_HASH(algo, hash) SMW_ATTR_SET_CLEAR_VALUE(algo, HASH, hash)

/**
 * SMW_ATTR_USAGE_SET_CACHE() - Set cache operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets cache operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_CACHE(usage) SMW_ATTR_SET_MASK(usage, USAGE, CACHE)

/**
 * SMW_ATTR_USAGE_SET_COPY() - Set copy operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets copy operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_COPY(usage) SMW_ATTR_SET_MASK(usage, USAGE, COPY)

/**
 * SMW_ATTR_USAGE_SET_EXPORT() - Set export operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets export operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_EXPORT(usage) SMW_ATTR_SET_MASK(usage, USAGE, EXPORT)

/**
 * SMW_ATTR_USAGE_SET_ENCRYPT() - Set encrypt operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets encrypt operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_ENCRYPT(usage)                                      \
	SMW_ATTR_SET_MASK(usage, USAGE, ENCRYPT)

/**
 * SMW_ATTR_USAGE_SET_DECRYPT() - Set decrypt operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets decrypt operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_DECRYPT(usage)                                      \
	SMW_ATTR_SET_MASK(usage, USAGE, DECRYPT)

/**
 * SMW_ATTR_USAGE_SET_SIGN_MESSAGE() - Set sign message operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets sign message operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_SIGN_MESSAGE(usage)                                 \
	SMW_ATTR_SET_MASK(usage, USAGE, SIGN_MESSAGE)

/**
 * SMW_ATTR_USAGE_SET_VERIFY_MESSAGE() - Set verify message operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets verify message operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_VERIFY_MESSAGE(usage)                               \
	SMW_ATTR_SET_MASK(usage, USAGE, VERIFY_MESSAGE)

/**
 * SMW_ATTR_USAGE_SET_SIGN_HASH() - Set sign hash operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets sign hash operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_SIGN_HASH(usage)                                    \
	SMW_ATTR_SET_MASK(usage, USAGE, SIGN_HASH)

/**
 * SMW_ATTR_USAGE_SET_VERIFY_HASH() - Set verify hash operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets verify hash operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_VERIFY_HASH(usage)                                  \
	SMW_ATTR_SET_MASK(usage, USAGE, VERIFY_HASH)

/**
 * SMW_ATTR_USAGE_SET_DERIVE() - Set derive operation.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro sets derive operation as permitted usage.
 *
 * Return:
 * A valid usage.
 */
#define SMW_ATTR_USAGE_SET_DERIVE(usage) SMW_ATTR_SET_MASK(usage, USAGE, DERIVE)

/**
 * SMW_ATTR_USAGE_IS_CACHE() - Whether the cache operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the cache operation is permitted or not.
 *
 * Return:
 * 1 if the cache operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_CACHE(usage) SMW_ATTR_IS_MASK_SET(usage, USAGE, CACHE)

/**
 * SMW_ATTR_USAGE_IS_COPY() - Whether the copy operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the copy operation is permitted or not.
 *
 * Return:
 * 1 if the copy operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_COPY(usage) SMW_ATTR_IS_MASK_SET(usage, USAGE, COPY)

/**
 * SMW_ATTR_USAGE_IS_EXPORT() - Whether the export operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the export operation is permitted or not.
 *
 * Return:
 * 1 if the export operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_EXPORT(usage)                                        \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, EXPORT)

/**
 * SMW_ATTR_USAGE_IS_ENCRYPT() - Whether the encrypt operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the encrypt operation is permitted or not.
 *
 * Return:
 * 1 if the encrypt operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_ENCRYPT(usage)                                       \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, ENCRYPT)

/**
 * SMW_ATTR_USAGE_IS_DECRYPT() - Whether the decrypt operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the decrypt operation is permitted or not.
 *
 * Return:
 * 1 if the decrypt operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_DECRYPT(usage)                                       \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, DECRYPT)

/**
 * SMW_ATTR_USAGE_IS_SIGN_MESSAGE() - Whether the sign message operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the sign message operation is permitted or not.
 *
 * Return:
 * 1 if the sign message operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_SIGN_MESSAGE(usage)                                  \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, SIGN_MESSAGE)

/**
 * SMW_ATTR_USAGE_IS_VERIFY_MESSAGE() - Whether the verify message operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the verify message operation is permitted or not.
 *
 * Return:
 * 1 if the verify message operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_VERIFY_MESSAGE(usage)                                \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, VERIFY_MESSAGE)

/**
 * SMW_ATTR_USAGE_IS_SIGN_HASH() - Whether the sign hash operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the sign hash operation is permitted or not.
 *
 * Return:
 * 1 if the sign hash operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_SIGN_HASH(usage)                                     \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, SIGN_HASH)

/**
 * SMW_ATTR_USAGE_IS_VERIFY_HASH() - Whether the verify hash operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the verify hash operation is permitted or not.
 *
 * Return:
 * 1 if the verify hash operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_VERIFY_HASH(usage)                                   \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, VERIFY_HASH)

/**
 * SMW_ATTR_USAGE_IS_DERIVE() - Whether the derive operation is permitted.
 * @usage: A usage. See smw_attr_usage_t.
 *
 * This macro returns whether the derive operation is permitted or not.
 *
 * Return:
 * 1 if the derive operation is permitted, 0 otherwise.
 */
#define SMW_ATTR_USAGE_IS_DERIVE(usage)                                        \
	SMW_ATTR_IS_MASK_SET(usage, USAGE, DERIVE)

/**
 * SMW_ATTR_SET_PERSISTENCE() - Set persistence.
 * @attr: Attributes. See smw_attr_attributes_t.
 * @persistence: Persistence.
 *
 * This macro sets @persistence.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_PERSISTENCE(attr, persistence)                            \
	SMW_ATTR_SET_CLEAR_VALUE(attr, PERSISTENCE, persistence)

/**
 * SMW_ATTR_GET_PERSISTENCE() - Get persistence.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro gets persistence.
 *
 * Return:
 * Persistence
 */
#define SMW_ATTR_GET_PERSISTENCE(attr) SMW_ATTR_GET_VALUE(attr, PERSISTENCE)

/**
 * SMW_ATTR_SET_TRANSIENT() - Set transient persistence.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets transient persistence.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_TRANSIENT(attr)                                           \
	SMW_ATTR_SET_CLEAR_NAME(attr, PERSISTENCE, TRANSIENT)

/**
 * SMW_ATTR_SET_PERSISTENT() - Set persistent persistence.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets persistent persistence.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_PERSISTENT(attr)                                          \
	SMW_ATTR_SET_CLEAR_NAME(attr, PERSISTENCE, PERSISTENT)

/**
 * SMW_ATTR_SET_PERMANENT() - Set permanent persistence.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets permanent persistence.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_PERMANENT(attr)                                           \
	SMW_ATTR_SET_CLEAR_NAME(attr, PERSISTENCE, PERMANENT)

/**
 * SMW_ATTR_IS_TRANSIENT() - Whether the persistence is transient.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the persistence is transient or not.
 *
 * Return:
 * 1 if the persistence is transient, 0 otherwise.
 */
#define SMW_ATTR_IS_TRANSIENT(attr)                                            \
	SMW_ATTR_IS_NAME_SET(attr, PERSISTENCE, TRANSIENT)

/**
 * SMW_ATTR_IS_PERSISTENT() - Whether the persistence is persistent.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the persistence is persistent or not.
 *
 * Return:
 * 1 if the persistence is persistent, 0 otherwise.
 */
#define SMW_ATTR_IS_PERSISTENT(attr)                                           \
	SMW_ATTR_IS_NAME_SET(attr, PERSISTENCE, PERSISTENT)

/**
 * SMW_ATTR_IS_PERMANENT() - Whether the persistence is permanent.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the persistence is permanent or not.
 *
 * Return:
 * 1 if the persistence is permanent, 0 otherwise.
 */
#define SMW_ATTR_IS_PERMANENT(attr)                                            \
	SMW_ATTR_IS_NAME_SET(attr, PERSISTENCE, PERMANENT)

/**
 * SMW_ATTR_SET_LC_CURRENT() - Set current lifecycle.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets current lifecycle.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_LC_CURRENT(attr)                                          \
	SMW_ATTR_SET_NAME_SHIFTED(attr, LIFECYCLE, CURRENT)

/**
 * SMW_ATTR_SET_LC_OPEN() - Set open lifecycle.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets open lifecycle.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_LC_OPEN(attr)                                             \
	SMW_ATTR_SET_NAME_SHIFTED(attr, LIFECYCLE, OPEN)

/**
 * SMW_ATTR_SET_LC_CLOSED() - Set closed lifecycle.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets closed lifecycle.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_LC_CLOSED(attr)                                           \
	SMW_ATTR_SET_NAME_SHIFTED(attr, LIFECYCLE, CLOSED)

/**
 * SMW_ATTR_SET_LC_CLOSED_LOCKED() - Set closed-locked lifecycle.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets closed-locked lifecycle.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_LC_CLOSED_LOCKED(attr)                                    \
	SMW_ATTR_SET_NAME_SHIFTED(attr, LIFECYCLE, CLOSED_LOCKED)

/**
 * SMW_ATTR_IS_LC_CURRENT() - Whether the lifecycle is current.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the lifecycle is current or not.
 *
 * Return:
 * 1 if the lifecycle is current, 0 otherwise.
 */
#define SMW_ATTR_IS_LC_CURRENT(attr)                                           \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, LIFECYCLE, CURRENT)

/**
 * SMW_ATTR_IS_LC_OPEN() - Whether the lifecycle is open.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the lifecycle is open or not.
 *
 * Return:
 * 1 if the lifecycle is open, 0 otherwise.
 */
#define SMW_ATTR_IS_LC_OPEN(attr)                                              \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, LIFECYCLE, OPEN)

/**
 * SMW_ATTR_IS_LC_CLOSED() - Whether the lifecycle is closed.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the lifecycle is closed or not.
 *
 * Return:
 * 1 if the lifecycle is closed, 0 otherwise.
 */
#define SMW_ATTR_IS_LC_CLOSED(attr)                                            \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, LIFECYCLE, CLOSED)

/**
 * SMW_ATTR_IS_LC_CLOSED_LOCKED() - Whether the lifecycle is closed-locked.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the lifecycle is closed-locked or not.
 *
 * Return:
 * 1 if the lifecycle is closed-locked, 0 otherwise.
 */
#define SMW_ATTR_IS_LC_CLOSED_LOCKED(attr)                                     \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, LIFECYCLE, CLOSED_LOCKED)

/**
 * SMW_ATTR_SET_READ_ONLY() - Set read-only flag.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets read-only flag.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_READ_ONLY(attr)                                           \
	SMW_ATTR_SET_NAME_SHIFTED(attr, RW_FLAGS, READ_ONLY)

/**
 * SMW_ATTR_SET_READ_ONCE() - Set read-once flag.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro sets read-once flag.
 *
 * Return:
 * Attributes
 */
#define SMW_ATTR_SET_READ_ONCE(attr)                                           \
	SMW_ATTR_SET_NAME_SHIFTED(attr, RW_FLAGS, READ_ONCE)

/**
 * SMW_ATTR_IS_READ_ONLY() - Whether the read-only flag is set.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the read-only flag is set or not.
 *
 * Return:
 * 1 if the read-only flag is set, 0 otherwise.
 */
#define SMW_ATTR_IS_READ_ONLY(attr)                                            \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, RW_FLAGS, READ_ONLY)

/**
 * SMW_ATTR_IS_READ_ONCE() - Whether the read-once flag is set.
 * @attr: Attributes. See smw_attr_attributes_t.
 *
 * This macro returns whether the read-once flag is set or not.
 *
 * Return:
 * 1 if the read-once flag is set, 0 otherwise.
 */
#define SMW_ATTR_IS_READ_ONCE(attr)                                            \
	SMW_ATTR_IS_NAME_SHIFTED_SET(attr, RW_FLAGS, READ_ONCE)

#endif /* __SMW_ATTR_H__ */
