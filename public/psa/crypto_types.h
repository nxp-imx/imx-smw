/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_CRYPTO_TYPES_H__
#define __PSA_CRYPTO_TYPES_H__

/**
 * DOC:
 * This file declares types that encode errors, algorithms, key types, policies, etc.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.0.1
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/a
 */

/**
 * typedef psa_algorithm_t - Encoding of a cryptographic algorithm.
 *
 * This is a structured bitfield that identifies the category and type of algorithm. The range of
 * algorithm identifier values is divided as follows\:
 *
 * - 0x00000000
 *	Reserved as an invalid algorithm identifier.
 *
 * - 0x00000001 - 0x7fffffff
 *	Specification-defined algorithm identifiers. Algorithm identifiers defined by this standard
 *	always have bit 31 clear. Unallocated algorithm identifier values in this range are
 *	reserved for future use.
 *
 * - 0x80000000 - 0xffffffff
 *	Implementation-defined algorithm identifiers. Implementations that define additional
 *	algorithms must use an encoding with bit 31 set. The related support macros will be easier
 *	to write if these algorithm identifier encodings also respect the bitwise structure used by
 *	standard encodings.
 *
 * For algorithms that can be applied to multiple key types, this identifier does not encode the
 * key type. For example, for symmetric ciphers based on a block cipher, &typedef psa_algorithm_t
 * encodes the block cipher mode and the padding mode while the block cipher itself is encoded via
 * &typedef psa_key_type_t.
 *
 * Values:
 * * PSA_ALG_ANY_HASH
 * * PSA_ALG_CBC_MAC
 * * PSA_ALG_CBC_NO_PADDING
 * * PSA_ALG_CBC_PKCS7
 * * PSA_ALG_CCM
 * * PSA_ALG_CFB
 * * PSA_ALG_CHACHA20_POLY1305
 * * PSA_ALG_CMAC
 * * PSA_ALG_CTR
 * * PSA_ALG_ECB_NO_PADDING
 * * PSA_ALG_ECDH
 * * PSA_ALG_ECDSA_ANY
 * * PSA_ALG_FFDH
 * * PSA_ALG_GCM
 * * PSA_ALG_MD2
 * * PSA_ALG_MD4
 * * PSA_ALG_MD5
 * * PSA_ALG_NONE
 * * PSA_ALG_OFB
 * * PSA_ALG_RIPEMD160
 * * PSA_ALG_RSA_PKCS1V15_CRYPT
 * * PSA_ALG_RSA_PKCS1V15_SIGN_RAW
 * * PSA_ALG_SHA3_224
 * * PSA_ALG_SHA3_256
 * * PSA_ALG_SHA3_384
 * * PSA_ALG_SHA3_512
 * * PSA_ALG_SHA_1
 * * PSA_ALG_SHA_224
 * * PSA_ALG_SHA_256
 * * PSA_ALG_SHA_384
 * * PSA_ALG_SHA_512
 * * PSA_ALG_SHA_512_224
 * * PSA_ALG_SHA_512_256
 * * PSA_ALG_SM3
 * * PSA_ALG_STREAM_CIPHER
 * * PSA_ALG_XTS
 */
typedef uint32_t psa_algorithm_t;

/**
 * typedef psa_dh_family_t - The type of PSA finite-field Diffie-Hellman group family identifiers.
 *
 * The group family identifier is required to create an Diffie-Hellman key using the
 * PSA_KEY_TYPE_DH_KEY_PAIR() or PSA_KEY_TYPE_DH_PUBLIC_KEY() macros.
 *
 * The specific Diffie-Hellman group within a family is identified by the key_bits attribute of the
 * key.
 *
 * The range of Diffie-Hellman group family identifier values is divided as follows\:
 *
 * - 0x00 - 0x7f
 *	DH group family identifiers defined by this standard. Unallocated values in this range are
 *	reserved for future use.
 *
 * - 0x80 - 0xff
 *	Implementations that define additional families must use an encoding in this range.
 */
typedef uint8_t psa_dh_family_t;

/**
 * typedef psa_ecc_family_t - The type of PSA elliptic curve family identifiers.
 *
 * The curve identifier is required to create an ECC key using the PSA_KEY_TYPE_ECC_KEY_PAIR() or
 * PSA_KEY_TYPE_ECC_PUBLIC_KEY() macros.
 *
 * The specific ECC curve within a family is identified by the key_bits attribute of the key.
 *
 * The range of Elliptic curve family identifier values is divided as follows\:
 *
 * - 0x00 - 0x7f
 *	ECC family identifiers defined by this standard. Unallocated values in this range are
 *	reserved for future use.
 *
 * - 0x80 - 0xff
 *	Implementations that define additional families must use an encoding in this range.
 */
typedef uint8_t psa_ecc_family_t;

/**
 * typedef psa_key_derivation_step_t - Encoding of the step of a key derivation.
 */
typedef uint16_t psa_key_derivation_step_t;

/**
 * typedef psa_key_id_t - Key identifier.
 *
 * A key identifiers can be a permanent name for a persistent key, or a transient reference to
 * volatile key.
 */
typedef uint32_t psa_key_id_t;

/**
 * typedef psa_key_lifetime_t - Encoding of key lifetimes.
 *
 * The lifetime of a key indicates where it is stored and which application and system actions will
 * create and destroy it.
 *
 * Lifetime values have the following structure\:
 *
 * - Bits[7:0]: Persistence level
 *
 *   This value indicates what device management actions can cause it to be destroyed. In
 *   particular, it indicates whether the key is volatile or persistent. See
 *   &typedef psa_key_persistence_t for more information.
 *
 *   PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) returns the persistence level for a key lifetime
 *   value.
 *
 * - Bits[31:8]: Location indicator
 *
 *   This value indicates where the key material is stored (or at least where it is accessible in
 *   cleartext) and where operations on the key are performed. See &typedef psa_key_location_t for
 *   more information.
 *
 *   PSA_KEY_LIFETIME_GET_LOCATION(lifetime) returns the location indicator for a key lifetime
 *   value.
 *
 * Volatile keys (PSA_KEY_LIFETIME_VOLATILE) are automatically destroyed when the application
 * instance terminates or on a power reset of the device. Persistent keys are preserved until the
 * application explicitly destroys them or until an implementation-specific device management event
 * occurs, for example, a factory reset.
 *
 * Persistent keys (PSA_KEY_LIFETIME_PERSISTENT) have a unique key identifier of type
 * &typedef psa_key_id_t per application instantiating the library. This identifier remains valid
 * throughout the lifetime of the key, even if the application instance that created the key
 * terminates.
 */
typedef uint32_t psa_key_lifetime_t;

/**
 * typedef psa_key_location_t - Encoding of key location indicators.
 *
 * If an implementation of this API can make calls to external cryptoprocessors such as secure
 * elements, the location of a key indicates which secure element performs the operations on the
 * key. If the key material is not stored persistently inside the secure element, it must be stored
 * in a wrapped form such that only the secure element can access the key material in cleartext.
 *
 * Values for location indicators defined by this specification are shown below.
 *
 *   .. tabularcolumns:: |\Y{0.3}|\Y{0.7}|
 *
 *   +------------------------+--------------------------------------------------------------------+
 *   | **Location indicator** | **Definition**                                                     |
 *   +========================+====================================================================+
 *   | 0                      | Primary local storage.                                             |
 *   |                        |                                                                    |
 *   |                        | The primary local storage is typically the same storage area that  |
 *   |                        | contains the key metadata.                                         |
 *   +------------------------+--------------------------------------------------------------------+
 *   | 1                      | Primary secure element.                                            |
 *   |                        |                                                                    |
 *   |                        | HSM or ELE Secure Subsystems are primary secure elements. As a     |
 *   |                        | guideline, secure elements may provide higher resistance against   |
 *   |                        | side channel and physical attacks than the primary local storage,  |
 *   |                        | but may have restrictions on supported key types, sizes, policies  |
 *   |                        | and operations and may have different performance characteristics. |
 *   +------------------------+--------------------------------------------------------------------+
 *   | 2 - 0x7fffff           | Other locations defined by a PSA specification.                    |
 *   |                        |                                                                    |
 *   |                        | The PSA Cryptography API does not currently assign any meaning to  |
 *   |                        | these locations, but future versions of this specification or      |
 *   |                        | other PSA specifications may do so.                                |
 *   +------------------------+--------------------------------------------------------------------+
 *   | 0x800000 - 0xffffff    | Vendor-defined locations.                                          |
 *   |                        |                                                                    |
 *   |                        | No PSA specification will assign a meaning to locations in this    |
 *   |                        | range.                                                             |
 *   +------------------------+--------------------------------------------------------------------+
 *
 * Note:
 *	Key location indicators are 24-bit values. Key management interfaces operate on lifetimes
 *	(see &typedef psa_key_lifetime_t), and encode the location as the upper 24 bits of a 32-bit
 *	value.
 */
typedef uint32_t psa_key_location_t;

/**
 * typedef psa_key_persistence_t - Encoding of key persistence levels.
 *
 * What distinguishes different persistence levels is which device management events can cause keys
 * to be destroyed. For example, power reset, transfer of device ownership, or a factory reset are
 * device management events that can affect keys at different persistence levels. The specific
 * management events which affect persistent keys at different levels is outside the scope of the
 * PSA Cryptography specification.
 *
 * Values for persistence levels defined by this specification are shown below.
 *
 *   .. tabularcolumns:: |\Y{0.5}|\Y{0.5}|
 *
 *   +-------------------------------------+-------------------------------------------------------+
 *   | **Persistence level**               | **Definition**                                        |
 *   +=====================================+=======================================================+
 *   | 0 = PSA_KEY_PERSISTENCE_VOLATILE    | Volatile key.                                         |
 *   |                                     |                                                       |
 *   |                                     | A volatile key is automatically destroyed by the      |
 *   |                                     | implementation when the application instance          |
 *   |                                     | terminates. In particular, a volatile key is          |
 *   |                                     | automatically destroyed on a power reset of the       |
 *   |                                     | device.                                               |
 *   +-------------------------------------+-------------------------------------------------------+
 *   | 1 = PSA_KEY_PERSISTENCE_DEFAULT     | Persistent key with a default lifetime.               |
 *   |                                     |                                                       |
 *   |                                     | Applications should use this value if they have no    |
 *   |                                     | specific needs that are only met by                   |
 *   |                                     | implementation-specific features.                     |
 *   +-------------------------------------+-------------------------------------------------------+
 *   | 2 - 127                             | Persistent key with a PSA-specified lifetime.         |
 *   |                                     |                                                       |
 *   |                                     | The PSA Cryptography specification does not define    |
 *   |                                     | the meaning of these values, but other PSA            |
 *   |                                     | specifications may do so.                             |
 *   +-------------------------------------+-------------------------------------------------------+
 *   | 128 - 254                           | Persistent key with a vendor-specified lifetime.      |
 *   |                                     |                                                       |
 *   |                                     | No PSA specification will define the meaning of these |
 *   |                                     | values, so implementations may choose the meaning     |
 *   |                                     | freely. As a guideline, higher persistence levels     |
 *   |                                     | should cause a key to survive more management events  |
 *   |                                     | than lower levels.                                    |
 *   +-------------------------------------+-------------------------------------------------------+
 *   | 255 = PSA_KEY_PERSISTENCE_READ_ONLY | Read-only or write-once key.                          |
 *   |                                     |                                                       |
 *   |                                     | A key with this persistence level cannot be           |
 *   |                                     | destroyed.                                            |
 *   |                                     |                                                       |
 *   |                                     | Note that keys that are read-only due to policy       |
 *   |                                     | restrictions rather than due to physical limitations  |
 *   |                                     | should not have this persistence level.               |
 *   +-------------------------------------+-------------------------------------------------------+
 *
 * Note:
 *	Key persistence levels are 8-bit values. Key management interfaces operate on lifetimes
 *	(see &typedef psa_key_lifetime_t), and encode the persistence value as the lower 8 bits of
 *	a 32-bit value.
 */
typedef uint8_t psa_key_persistence_t;

/**
 * typedef psa_key_type_t - Encoding of a key type.
 *
 * This is a structured bitfield that identifies the category and type of key. The range of key
 * type values is divided as follows\:
 *
 * - PSA_KEY_TYPE_NONE == 0
 *	Reserved as an invalid key type.
 *
 * - 0x0001 - 0x7fff
 *	Specification-defined key types. Key types defined by this standard always have bit 15
 *	clear. Unallocated key type values in this range are reserved for future use.
 *
 * - 0x8000 - 0xffff
 *	No additional key type is defined.
 */
typedef uint16_t psa_key_type_t;

/**
 * typedef psa_key_usage_t - Encoding of permitted usage on a key.
 */
typedef uint32_t psa_key_usage_t;

#endif /* __PSA_CRYPTO_TYPES_H__ */
