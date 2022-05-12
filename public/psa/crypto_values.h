/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_CRYPTO_VALUES_H__
#define __PSA_CRYPTO_VALUES_H__

/**
 * DOC:
 * This file declares macros to build and analyze values of integral types defined in
 * crypto_types.h.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.0.1
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/a
 */

#define PSA_ALG_HASH_MASK	      ((psa_algorithm_t)0x000000ff)
#define PSA_ALG_ANY_HASH	      ((psa_algorithm_t)0x020000ff)
#define PSA_ALG_CBC_MAC		      ((psa_algorithm_t)0x03c00100)
#define PSA_ALG_CBC_NO_PADDING	      ((psa_algorithm_t)0x04404000)
#define PSA_ALG_CBC_PKCS7	      ((psa_algorithm_t)0x04404100)
#define PSA_ALG_CCM		      ((psa_algorithm_t)0x05500100)
#define PSA_ALG_CFB		      ((psa_algorithm_t)0x04c01100)
#define PSA_ALG_CHACHA20_POLY1305     ((psa_algorithm_t)0x05100500)
#define PSA_ALG_CMAC		      ((psa_algorithm_t)0x03c00200)
#define PSA_ALG_CTR		      ((psa_algorithm_t)0x04c01000)
#define PSA_ALG_ECB_NO_PADDING	      ((psa_algorithm_t)0x04404400)
#define PSA_ALG_ECDH		      ((psa_algorithm_t)0x09020000)
#define PSA_ALG_ECDSA_ANY	      ((psa_algorithm_t)0x06000600)
#define PSA_ALG_FFDH		      ((psa_algorithm_t)0x09010000)
#define PSA_ALG_GCM		      ((psa_algorithm_t)0x05500200)
#define PSA_ALG_MD2		      ((psa_algorithm_t)0x02000001)
#define PSA_ALG_MD4		      ((psa_algorithm_t)0x02000002)
#define PSA_ALG_MD5		      ((psa_algorithm_t)0x02000003)
#define PSA_ALG_NONE		      ((psa_algorithm_t)0)
#define PSA_ALG_OFB		      ((psa_algorithm_t)0x04c01200)
#define PSA_ALG_RIPEMD160	      ((psa_algorithm_t)0x02000004)
#define PSA_ALG_RSA_PKCS1V15_CRYPT    ((psa_algorithm_t)0x07000200)
#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW ((psa_algorithm_t)0x06000200)
#define PSA_ALG_SHA3_224	      ((psa_algorithm_t)0x02000010)
#define PSA_ALG_SHA3_256	      ((psa_algorithm_t)0x02000011)
#define PSA_ALG_SHA3_384	      ((psa_algorithm_t)0x02000012)
#define PSA_ALG_SHA3_512	      ((psa_algorithm_t)0x02000013)
#define PSA_ALG_SHA_1		      ((psa_algorithm_t)0x02000005)
#define PSA_ALG_SHA_224		      ((psa_algorithm_t)0x02000008)
#define PSA_ALG_SHA_256		      ((psa_algorithm_t)0x02000009)
#define PSA_ALG_SHA_384		      ((psa_algorithm_t)0x0200000a)
#define PSA_ALG_SHA_512		      ((psa_algorithm_t)0x0200000b)
#define PSA_ALG_SHA_512_224	      ((psa_algorithm_t)0x0200000c)
#define PSA_ALG_SHA_512_256	      ((psa_algorithm_t)0x0200000d)
#define PSA_ALG_SM3		      ((psa_algorithm_t)0x02000014)
#define PSA_ALG_STREAM_CIPHER	      ((psa_algorithm_t)0x04800100)
#define PSA_ALG_XTS		      ((psa_algorithm_t)0x0440ff00)

#define PSA_ALG_AEAD_TAG_LENGTH_MASK ((psa_algorithm_t)0x003f0000)
#define PSA_AEAD_TAG_LENGTH_OFFSET   16

#define PSA_ALG_MAC_TRUNCATION_MASK ((psa_algorithm_t)0x003f0000)
#define PSA_MAC_TRUNCATION_OFFSET   16

#define PSA_ALG_CIPHER_MAC_BASE		 ((psa_algorithm_t)0x03c00000)
#define PSA_ALG_DETERMINISTIC_ECDSA_BASE ((psa_algorithm_t)0x06000700)
#define PSA_ALG_ECDSA_BASE		 ((psa_algorithm_t)0x06000600)
#define PSA_ALG_HKDF_BASE		 ((psa_algorithm_t)0x08000100)
#define PSA_ALG_HMAC_BASE		 ((psa_algorithm_t)0x03800000)
#define PSA_ALG_RSA_OAEP_BASE		 ((psa_algorithm_t)0x07000300)
#define PSA_ALG_RSA_PKCS1V15_SIGN_BASE	 ((psa_algorithm_t)0x06000200)
#define PSA_ALG_RSA_PSS_BASE		 ((psa_algorithm_t)0x06000300)
#define PSA_ALG_TLS12_PRF_BASE		 ((psa_algorithm_t)0x08000200)
#define PSA_ALG_TLS12_PSK_TO_MS_BASE	 ((psa_algorithm_t)0x08000300)

#define PSA_ALG_CATEGORY_MASK		       ((psa_algorithm_t)0x7f000000)
#define PSA_ALG_CATEGORY_AEAD		       ((psa_algorithm_t)0x05000000)
#define PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION ((psa_algorithm_t)0x07000000)
#define PSA_ALG_CATEGORY_CIPHER		       ((psa_algorithm_t)0x04000000)
#define PSA_ALG_CATEGORY_HASH		       ((psa_algorithm_t)0x02000000)
#define PSA_ALG_CATEGORY_KEY_AGREEMENT	       ((psa_algorithm_t)0x09000000)
#define PSA_ALG_CATEGORY_KEY_DERIVATION	       ((psa_algorithm_t)0x08000000)
#define PSA_ALG_CATEGORY_MAC		       ((psa_algorithm_t)0x03000000)
#define PSA_ALG_CATEGORY_SIGN		       ((psa_algorithm_t)0x06000000)

#define PSA_ALG_AEAD_FROM_BLOCK_FLAG ((psa_algorithm_t)0x00400000)
#define PSA_ALG_CIPHER_STREAM_FLAG   ((psa_algorithm_t)0x00800000)

#define PSA_ALG_KEY_DERIVATION_MASK  ((psa_algorithm_t)0xfe00ffff)
#define PSA_ALG_KEY_AGREEMENT_MASK   ((psa_algorithm_t)0xffff0000)
#define PSA_ALG_MAC_SUBCATEGORY_MASK ((psa_algorithm_t)0x00c00000)

#define PSA_KEY_TYPE_CATEGORY_MASK	 ((psa_key_type_t)0x7000)
#define PSA_KEY_TYPE_CATEGORY_RAW	 ((psa_key_type_t)0x1000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC	 ((psa_key_type_t)0x2000)
#define PSA_KEY_TYPE_CATEGORY_FLAG_PAIR	 ((psa_key_type_t)0x3000)
#define PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY ((psa_key_type_t)0x4000)
#define PSA_KEY_TYPE_CATEGORY_KEY_PAIR	 ((psa_key_type_t)0x7000)

#define PSA_KEY_TYPE_DH_GROUP_MASK	((psa_key_type_t)0x00ff)
#define PSA_KEY_TYPE_DH_KEY_PAIR_BASE	((psa_key_type_t)0x7200)
#define PSA_KEY_TYPE_DH_PUBLIC_KEY_BASE ((psa_key_type_t)0x4200)

#define PSA_KEY_TYPE_ECC_CURVE_MASK	 ((psa_key_type_t)0x00ff)
#define PSA_KEY_TYPE_ECC_KEY_PAIR_BASE	 ((psa_key_type_t)0x7100)
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE ((psa_key_type_t)0x4100)

#define PSA_ALG_ECDSA_DETERMINISTIC_FLAG ((psa_algorithm_t)0x00000100)

/**
 * PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG() - An AEAD algorithm with the default tag length.
 * @aead_alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(aead_alg) is true).
 *
 * This macro can be used to construct the AEAD algorithm with default tag length from an AEAD
 * algorithm with a shortened tag. See also PSA_ALG_AEAD_WITH_SHORTENED_TAG().
 *
 * Return:
 * The corresponding AEAD algorithm with the default tag length for that algorithm.
 */
#define PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg)                         \
	((PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, 0) ==                      \
	  PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0)) ?                   \
		 PSA_ALG_CCM :                                                 \
		 (PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, 0) ==              \
		  PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0)) ?           \
		 PSA_ALG_GCM :                                                 \
		 (PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, 0) ==              \
		  PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305,   \
						  0)) ?                        \
		 PSA_ALG_CHACHA20_POLY1305 :                                   \
		 PSA_ALG_NONE)

/**
 * PSA_ALG_AEAD_WITH_SHORTENED_TAG() - Macro to build a AEAD algorithm with a shortened tag.
 * @aead_alg: An AEAD algorithm identifier (value of &typedef psa_algorithm_t such that
 *            PSA_ALG_IS_AEAD(aead_alg) is true).
 * @tag_length: Desired length of the authentication tag in bytes.
 *
 * An AEAD algorithm with a shortened tag is similar to the corresponding AEAD algorithm, but has
 * an authentication tag that consists of fewer bytes. Depending on the algorithm, the tag length
 * might affect the calculation of the ciphertext.
 *
 * The AEAD algorithm with a default length tag can be recovered using
 * PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG().
 *
 * Return:
 * The corresponding AEAD algorithm with the specified tag length.
 *
 * Unspecified if @aead_alg is not a supported AEAD algorithm or if @tag_length is not valid for
 * the specified AEAD algorithm.
 */
#define PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length)                  \
	((psa_algorithm_t)(((aead_alg) & ~PSA_ALG_AEAD_TAG_LENGTH_MASK) |      \
			   (((tag_length) << PSA_AEAD_TAG_LENGTH_OFFSET) &     \
			    PSA_ALG_AEAD_TAG_LENGTH_MASK)))

/**
 * PSA_ALG_DETERMINISTIC_ECDSA() - Deterministic ECDSA signature scheme, with hashing.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *            This includes PSA_ALG_ANY_HASH when specifying the algorithm in a key policy.
 *
 * This algorithm can be used with both the message and hash signature functions.
 *
 * **Note**:
 *	When based on the same hash algorithm, the verification operations for PSA_ALG_ECDSA and
 *	PSA_ALG_DETERMINISTIC_ECDSA are identical. A signature created using PSA_ALG_ECDSA can be
 *	verified with the same key using either PSA_ALG_ECDSA or PSA_ALG_DETERMINISTIC_ECDSA.
 *	Similarly, a signature created using PSA_ALG_DETERMINISTIC_ECDSA can be verified with the
 *	same key using either PSA_ALG_ECDSA or PSA_ALG_DETERMINISTIC_ECDSA.
 *
 *	In particular, it is impossible to determine whether a signature was produced with
 *	deterministic ECDSA or with randomized ECDSA: it is only possible to verify that a
 *	signature was made with ECDSA with the private key corresponding to the public key used for
 *	the verification.
 *
 * This is the deterministic ECDSA signature scheme defined by Deterministic Usage of the Digital
 * Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA) [RFC6979].
 *
 * The representation of a signature is the same as with PSA_ALG_ECDSA().
 *
 * Return:
 * The corresponding deterministic ECDSA signature algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)                                  \
	((psa_algorithm_t)(PSA_ALG_DETERMINISTIC_ECDSA_BASE |                  \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_ECDSA() - The randomized ECDSA signature scheme, with hashing.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *            This includes PSA_ALG_ANY_HASH when specifying the algorithm in a key policy.
 *
 * This algorithm can be used with both the message and hash signature functions.
 *
 * This algorithm is randomized: each invocation returns a different, equally valid signature.
 *
 * **Note**:
 *	When based on the same hash algorithm, the verification operations for PSA_ALG_ECDSA and
 *	PSA_ALG_DETERMINISTIC_ECDSA are identical. A signature created using PSA_ALG_ECDSA can be
 *	verified with the same key using either PSA_ALG_ECDSA or PSA_ALG_DETERMINISTIC_ECDSA.
 *	Similarly, a signature created using PSA_ALG_DETERMINISTIC_ECDSA can be verified with the
 *	same key using either PSA_ALG_ECDSA or PSA_ALG_DETERMINISTIC_ECDSA.
 *
 * In particular, it is impossible to determine whether a signature was produced with deterministic
 * ECDSA or with randomized ECDSA\: it is only possible to verify that a signature was made with
 * ECDSA with the private key corresponding to the public key used for the verification.
 *
 * This signature scheme is defined by SEC 1: Elliptic Curve Cryptography [SEC1], and also by Public
 * Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature
 * Algorithm (ECDSA) [X9-62], with a random per-message secret number k.
 *
 * The representation of the signature as a byte string consists of the concatenation of the
 * signature values r and s. Each of r and s is encoded as an N-octet string, where N is the length
 * of the base point of the curve in octets. Each value is represented in big-endian order, with the
 * most significant octet first.
 *
 * Return:
 * The corresponding randomized ECDSA signature algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_ECDSA(hash_alg)                                                \
	((psa_algorithm_t)(PSA_ALG_ECDSA_BASE |                                \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_FULL_LENGTH_MAC() - Macro to construct the MAC algorithm with a full length MAC, from a
 * truncated MAC algorithm.
 * @mac_alg: A MAC algorithm identifier (value of &typedef psa_algorithm_t such that
 *           PSA_ALG_IS_MAC(mac_alg) is true). This can be a truncated or untruncated MAC
 *           algorithm.
 *
 * Return:
 * The corresponding MAC algorithm with a full length MAC.
 *
 * Unspecified if alg is not a supported MAC algorithm.
 */
#define PSA_ALG_FULL_LENGTH_MAC(mac_alg)                                       \
	((psa_algorithm_t)((mac_alg) & ~PSA_ALG_MAC_TRUNCATION_MASK))

/**
 * PSA_ALG_GET_HASH() - Get the hash used by a composite algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * The following composite algorithms require a hash algorithm\:
 *
 * - PSA_ALG_ECDSA()
 * - PSA_ALG_HKDF()
 * - PSA_ALG_HMAC()
 * - PSA_ALG_RSA_OAEP()
 * - PSA_ALG_IS_RSA_PKCS1V15_SIGN()
 * - PSA_ALG_RSA_PSS()
 * - PSA_ALG_TLS12_PRF()
 * - PSA_ALG_TLS12_PSK_TO_MS()
 *
 * Return:
 * The underlying hash algorithm if @alg is a composite algorithm that uses a hash algorithm.
 *
 * PSA_ALG_NONE if @alg is not a composite algorithm that uses a hash.
 */
#define PSA_ALG_GET_HASH(alg)                                                  \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		((_alg & PSA_ALG_HASH_MASK) == 0 ?                             \
			 PSA_ALG_NONE :                                        \
			 PSA_ALG_CATEGORY_HASH | (_alg & PSA_ALG_HASH_MASK));  \
	})

/**
 * PSA_ALG_HKDF() - Macro to build an HKDF algorithm.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *
 * This is the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) specified by HMAC-based
 * Extract-and-Expand Key Derivation Function (HKDF) [RFC5869].
 *
 * This key derivation algorithm uses the following inputs\:
 *
 * - PSA_KEY_DERIVATION_INPUT_SALT is the salt used in the “extract” step. It is optional; if
 *   omitted, the derivation uses an empty salt.
 *
 * - PSA_KEY_DERIVATION_INPUT_SECRET is the secret key used in the “extract” step.
 *
 * - PSA_KEY_DERIVATION_INPUT_INFO is the info string used in the “expand” step.
 *
 * If PSA_KEY_DERIVATION_INPUT_SALT is provided, it must be before PSA_KEY_DERIVATION_INPUT_SECRET.
 * PSA_KEY_DERIVATION_INPUT_INFO can be provided at any time after setup and before starting to
 * generate output.
 *
 * Each input may only be passed once.
 *
 * Return:
 * The corresponding HKDF algorithm. For example, PSA_ALG_HKDF(PSA_ALG_SHA_256) is HKDF using
 * HMAC-SHA-256.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_HKDF(hash_alg)                                                 \
	((psa_algorithm_t)(PSA_ALG_HKDF_BASE |                                 \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_HMAC() - Macro to build an HMAC message-authentication-code algorithm from an underlying
 * hash algorithm.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *
 * For example, PSA_ALG_HMAC(PSA_ALG_SHA_256) is HMAC-SHA-256.
 *
 * The HMAC construction is defined in HMAC: Keyed-Hashing for Message Authentication [RFC2104].
 *
 * Return:
 * The corresponding HMAC algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_HMAC(hash_alg)                                                 \
	((psa_algorithm_t)(PSA_ALG_HMAC_BASE |                                 \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_IS_AEAD() - Whether the specified algorithm is an authenticated encryption with
 * associated data (AEAD) algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an AEAD algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg is not a
 * supported algorithm identifier.
 *
 */
#define PSA_ALG_IS_AEAD(alg)                                                   \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_AEAD)

/**
 * PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER() - Whether the specified algorithm is an AEAD mode on a block
 * cipher.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an AEAD algorithm which is an AEAD mode based on a block cipher, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg)                                   \
	(((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_AEAD_FROM_BLOCK_FLAG)) ==   \
	 (PSA_ALG_CATEGORY_AEAD | PSA_ALG_AEAD_FROM_BLOCK_FLAG))

/**
 * PSA_ALG_IS_ASYMMETRIC_ENCRYPTION() - Whether the specified algorithm is an asymmetric encryption
 * algorithm, also known as public-key encryption algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an asymmetric encryption algorithm, 0 otherwise. This macro can return either 0 or 1
 * if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)                                  \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) ==                                  \
	 PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION)

/**
 * PSA_ALG_IS_BLOCK_CIPHER_MAC() - Whether the specified algorithm is a MAC algorithm based on a
 * block cipher.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a MAC algorithm based on a block cipher, 0 otherwise. This macro can return either 0
 * or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg)                                       \
	(((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) ==   \
	 PSA_ALG_CIPHER_MAC_BASE)

/**
 * PSA_ALG_IS_CIPHER() - Whether the specified algorithm is a symmetric cipher algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a symmetric cipher algorithm, 0 otherwise. This macro can return either 0 or 1 if
 * @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_CIPHER(alg)                                                 \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_CIPHER)

/**
 * PSA_ALG_IS_DETERMINISTIC_ECDSA() - Whether the specified algorithm is deterministic ECDSA.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * See also PSA_ALG_IS_ECDSA() and PSA_ALG_IS_RANDOMIZED_ECDSA().
 *
 * Return:
 * 1 if @alg is a deterministic ECDSA algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)                                    \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_DETERMINISTIC_ECDSA_BASE)

/**
 * PSA_ALG_IS_ECDH() - Whether the specified algorithm is an elliptic curve Diffie-Hellman
 * algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * This includes the raw elliptic curve Diffie-Hellman algorithm as well as elliptic curve
 * Diffie-Hellman followed by any supporter key derivation algorithm.
 *
 * Return:
 * 1 if @alg is an elliptic curve Diffie-Hellman algorithm, 0 otherwise. This macro can return
 * either 0 or 1 if @alg is not a supported key agreement algorithm identifier.
 */
#define PSA_ALG_IS_ECDH(alg)                                                   \
	(PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) == PSA_ALG_ECDH)

/**
 * PSA_ALG_IS_ECDSA() - Whether the specified algorithm is ECDSA.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an ECDSA algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_ECDSA(alg)                                                  \
	(((alg) & ~PSA_ALG_HASH_MASK & ~PSA_ALG_ECDSA_DETERMINISTIC_FLAG) ==   \
	 PSA_ALG_ECDSA_BASE)

/**
 * PSA_ALG_IS_FFDH() - Whether the specified algorithm is a finite field Diffie-Hellman algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * This includes the raw finite field Diffie-Hellman algorithm as well as finite-field
 * Diffie-Hellman followed by any supporter key derivation algorithm.
 *
 * Return:
 * 1 if @alg is a finite field Diffie-Hellman algorithm, 0 otherwise. This macro can return either 0
 * or 1 if @alg is not a supported key agreement algorithm identifier.
 *
 */
#define PSA_ALG_IS_FFDH(alg)                                                   \
	(PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) == PSA_ALG_FFDH)

/**
 * PSA_ALG_IS_HASH() - Whether the specified algorithm is a hash algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * See Hash algorithms for a list of defined hash algorithms.
 *
 * Return:
 * 1 if @alg is a hash algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg is not a
 * supported algorithm identifier.
 */
#define PSA_ALG_IS_HASH(alg)                                                   \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_HASH)

/**
 * PSA_ALG_IS_HASH_AND_SIGN() - Whether the specified algorithm is a hash-and-sign algorithm that
 * signs exactly the hash value.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * This macro identifies algorithms that can be used with psa_sign_hash() that use the exact message
 * hash value as an input the signature operation. This excludes hash-and-sign algorithms that
 * require a encoded or modified hash for the signature step in the algorithm, such as
 * PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * Return:
 * 1 if @alg is a hash-and-sign algorithm that signs exactly the hash value, 0 otherwise. This macro
 * can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_HASH_AND_SIGN(alg)                                          \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		(PSA_ALG_IS_RSA_PSS(_alg) ||                                   \
		 PSA_ALG_IS_RSA_PKCS1V15_SIGN(_alg) ||                         \
		 PSA_ALG_IS_ECDSA(_alg));                                      \
	})

/**
 * PSA_ALG_IS_HKDF() - Whether the specified algorithm is an HKDF algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * HKDF is a family of key derivation algorithms that are based on a hash function and the HMAC
 * construction.
 *
 * Return:
 * 1 if @alg is an HKDF algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg is not a
 * supported key derivation algorithm identifier.
 */
#define PSA_ALG_IS_HKDF(alg) (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_HKDF_BASE)

/**
 * PSA_ALG_IS_HMAC() - Whether the specified algorithm is an HMAC algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * HMAC is a family of MAC algorithms that are based on a hash function.
 *
 * Return:
 * 1 if alg is an HMAC algorithm, 0 otherwise. This macro can return either 0 or 1 if alg is not a
 * supported algorithm identifier.
 */
#define PSA_ALG_IS_HMAC(alg)                                                   \
	(((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) ==   \
	 PSA_ALG_HMAC_BASE)

/**
 * PSA_ALG_IS_KEY_AGREEMENT() - Whether the specified algorithm is a key agreement algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a key agreement algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg
 * is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_KEY_AGREEMENT(alg)                                          \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_KEY_AGREEMENT)

/**
 * PSA_ALG_IS_KEY_DERIVATION() - Whether the specified algorithm is a key derivation algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a key derivation algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg
 * is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_KEY_DERIVATION(alg)                                         \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_KEY_DERIVATION)

/**
 * PSA_ALG_IS_MAC() - Whether the specified algorithm is a MAC algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a MAC algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg is not a
 * supported algorithm identifier.
 */
#define PSA_ALG_IS_MAC(alg)                                                    \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_MAC)

/**
 * PSA_ALG_IS_RANDOMIZED_ECDSA() - Whether the specified algorithm is randomized ECDSA.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * See also PSA_ALG_IS_ECDSA() and PSA_ALG_IS_DETERMINISTIC_ECDSA().
 *
 * Return:
 * 1 if @alg is a randomized ECDSA algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_RANDOMIZED_ECDSA(alg)                                       \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_ECDSA_BASE)

/**
 * PSA_ALG_IS_RAW_KEY_AGREEMENT() - Whether the specified algorithm is a raw key agreement
 * algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * A raw key agreement algorithm is one that does not specify a key derivation function. Usually,
 * raw key agreement algorithms are constructed directly with a PSA_ALG_xxx macro while non-raw key
 * agreement algorithms are constructed with PSA_ALG_KEY_AGREEMENT().
 *
 * The raw key agreement algorithm can be extracted from a full key agreement algorithm identifier
 * using PSA_ALG_KEY_AGREEMENT_GET_BASE().
 *
 * Return:
 * 1 if @alg is a raw key agreement algorithm, 0 otherwise. This macro can return either 0 or 1 if
 * @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)                                      \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		(PSA_ALG_IS_KEY_AGREEMENT(_alg) &&                             \
		 PSA_ALG_KEY_AGREEMENT_GET_KDF(_alg) ==                        \
			 PSA_ALG_CATEGORY_KEY_DERIVATION);                     \
	})
/**
 * PSA_ALG_IS_RSA_OAEP() - Whether the specified algorithm is an RSA OAEP encryption algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an RSA OAEP algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_RSA_OAEP(alg)                                               \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_OAEP_BASE)

/**
 * PSA_ALG_IS_RSA_PKCS1V15_SIGN() - Whether the specified algorithm is an RSA PKCS#1 v1.5 signature
 * algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an RSA PKCS#1 v1.5 signature algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)                                      \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_PKCS1V15_SIGN_BASE)

/**
 * PSA_ALG_IS_RSA_PSS() - Whether the specified algorithm is an RSA PSS signature algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an RSA PSS signature algorithm, 0 otherwise.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_RSA_PSS(alg)                                                \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_PSS_BASE)

/**
 * PSA_ALG_IS_SIGN() - Whether the specified algorithm is an asymmetric signature algorithm, also
 * known as public-key signature algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is an asymmetric signature algorithm, 0 otherwise. This macro can return either 0 or 1
 * if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_SIGN(alg)                                                   \
	(((alg) & (PSA_ALG_CATEGORY_MASK)) == PSA_ALG_CATEGORY_SIGN)

/**
 * PSA_ALG_IS_SIGN_HASH() - Whether the specified algorithm is a signature algorithm that can be
 * used with psa_sign_hash() and psa_verify_hash().
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a signature algorithm that can be used to sign a hash. 0 @alg alg is a signature
 * algorithm that can only be used to sign a message. 0 if @alg is not a signature algorithm. This
 * macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_SIGN_HASH(alg) PSA_ALG_IS_SIGN(alg)

/**
 * PSA_ALG_IS_SIGN_MESSAGE() - Whether the specified algorithm is a signature algorithm that can be
 * used with psa_sign_message() and psa_verify_message().
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a signature algorithm that can be used to sign a message. 0 if @alg is a signature
 * algorithm that can only be used to sign an already-calculated hash. 0 if @alg is not a signature
 * algorithm. This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_SIGN_MESSAGE(alg)                                           \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		(PSA_ALG_IS_SIGN(_alg) && _alg != PSA_ALG_ECDSA_ANY &&         \
		 _alg != PSA_ALG_RSA_PKCS1V15_SIGN_RAW);                       \
	})

/**
 * PSA_ALG_IS_STREAM_CIPHER() - Whether the specified algorithm is a stream cipher.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * A stream cipher is a symmetric cipher that encrypts or decrypts messages by applying a
 * bitwise-xor with a stream of bytes that is generated from a key.
 *
 * Return:
 * 1 if @alg is a stream cipher algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg
 * is not a supported algorithm identifier or if it is not a symmetric cipher algorithm.
 */
#define PSA_ALG_IS_STREAM_CIPHER(alg)                                          \
	(((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_CIPHER_STREAM_FLAG)) ==     \
	 (PSA_ALG_CATEGORY_CIPHER | PSA_ALG_CIPHER_STREAM_FLAG))

/**
 * PSA_ALG_IS_TLS12_PRF() - Whether the specified algorithm is a TLS-1.2 PRF algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a TLS-1.2 PRF algorithm, 0 otherwise. This macro can return either 0 or 1 if @alg is
 * not a supported key derivation algorithm identifier.
 */
#define PSA_ALG_IS_TLS12_PRF(alg)                                              \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_TLS12_PRF_BASE)

/**
 * PSA_ALG_IS_TLS12_PSK_TO_MS() - Whether the specified algorithm is a TLS-1.2 PSK to MS algorithm.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Return:
 * 1 if @alg is a TLS-1.2 PSK to MS algorithm, 0 otherwise. This macro can return either 0 or 1 if
 * @alg is not a supported key derivation algorithm identifier.
 */
#define PSA_ALG_IS_TLS12_PSK_TO_MS(alg)                                        \
	(((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_TLS12_PSK_TO_MS_BASE)

/**
 * PSA_ALG_IS_WILDCARD() - Whether the specified algorithm encoding is a wildcard.
 * @alg: An algorithm identifier (value of &typedef psa_algorithm_t).
 *
 * Wildcard algorithm values can only be used to set the permitted algorithm field in a key policy,
 * wildcard values cannot be used to perform an operation.
 *
 * See PSA_ALG_ANY_HASH for example of how a wildcard algorithm can be used in a key policy.
 *
 * Return:
 * 1 if @alg is a wildcard algorithm encoding.
 *
 * 0 if @alg is a non-wildcard algorithm encoding that is suitable for an operation.
 *
 * This macro can return either 0 or 1 if @alg is not a supported algorithm identifier.
 */
#define PSA_ALG_IS_WILDCARD(alg) (PSA_ALG_GET_HASH(alg) == PSA_ALG_ANY_HASH)

/**
 * PSA_ALG_KEY_AGREEMENT() - Macro to build a combined algorithm that chains a key agreement with a
 * key derivation.
 * @ka_alg: A key agreement algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_KEY_AGREEMENT(ka_alg)
 *          is true).
 * @kdf_alg: A key derivation algorithm (PSA_ALG_XXX value such that
 *           PSA_ALG_IS_KEY_DERIVATION(kdf_alg) is true).
 *
 * A combined key agreement algorithm is used with a multi-part key derivation operation, using a
 * call to psa_key_derivation_key_agreement().
 *
 * The component parts of a key agreement algorithm can be extracted using
 * PSA_ALG_KEY_AGREEMENT_GET_BASE() and PSA_ALG_KEY_AGREEMENT_GET_KDF().
 *
 * Return:
 * The corresponding key agreement and derivation algorithm.
 *
 * Unspecified if @ka_alg is not a supported key agreement algorithm or @kdf_alg is not a supported
 * key derivation algorithm.
 */
#define PSA_ALG_KEY_AGREEMENT(ka_alg, kdf_alg) ((ka_alg) | (kdf_alg))

/**
 * PSA_ALG_KEY_AGREEMENT_GET_BASE() - Get the raw key agreement algorithm from a full key agreement
 * algorithm.
 * @alg: A key agreement algorithm identifier (value of &typedef psa_algorithm_t such that
 *       PSA_ALG_IS_KEY_AGREEMENT(alg) is true).
 *
 * See also PSA_ALG_KEY_AGREEMENT() and PSA_ALG_KEY_AGREEMENT_GET_KDF().
 *
 * Return:
 * The underlying raw key agreement algorithm if @alg is a key agreement algorithm.
 *
 * Unspecified if @alg is not a key agreement algorithm or if it is not supported by the
 * implementation.
 */
#define PSA_ALG_KEY_AGREEMENT_GET_BASE(alg)                                    \
	((psa_algorithm_t)((alg) & (PSA_ALG_KEY_AGREEMENT_MASK)))

/**
 * PSA_ALG_KEY_AGREEMENT_GET_KDF() - Get the key derivation algorithm used in a full key agreement
 * algorithm.
 * @alg: A key agreement algorithm identifier (value of &typedef psa_algorithm_t such that
 *       PSA_ALG_IS_KEY_AGREEMENT(alg) is true).
 *
 * See also PSA_ALG_KEY_AGREEMENT() and PSA_ALG_KEY_AGREEMENT_GET_BASE().
 *
 * Return:
 * The underlying key derivation algorithm if @alg is a key agreement algorithm.
 *
 * Unspecified if @alg is not a key agreement algorithm or if it is not supported by the
 * implementation.
 */
#define PSA_ALG_KEY_AGREEMENT_GET_KDF(alg)                                     \
	((psa_algorithm_t)((alg) & (PSA_ALG_KEY_DERIVATION_MASK)))

/**
 * PSA_ALG_RSA_OAEP() - The RSA OAEP asymmetric encryption algorithm.
 * @hash_alg: The hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true) to
 *            use for MGF1.
 *
 * This encryption scheme is defined by [RFC8017] §7.1 under the name RSAES-OAEP, with the mask
 * generation function MGF1 defined in [RFC8017] Appendix B.
 *
 * Return:
 * The corresponding RSA OAEP encryption algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_RSA_OAEP(hash_alg)                                             \
	((psa_algorithm_t)(PSA_ALG_RSA_OAEP_BASE |                             \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_RSA_PKCS1V15_SIGN() - The RSA PKCS#1 v1.5 message signature scheme, with hashing.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *            This includes PSA_ALG_ANY_HASH when specifying the algorithm in a key policy.
 *
 * This algorithm can be used with both the message and hash signature functions.
 *
 * This signature scheme is defined by PKCS #1: RSA Cryptography Specifications Version 2.2
 * [RFC8017] §8.2 under the name RSASSA-PKCS1-v1_5.
 *
 * When used with psa_sign_hash() or psa_verify_hash(), the provided hash parameter is used as H
 * from step 2 onwards in the message encoding algorithm EMSA-PKCS1-V1_5-ENCODE() in [RFC8017]
 * §9.2. H is usually the message digest, using the @hash_alg hash algorithm.
 *
 * Return:
 * The corresponding RSA PKCS#1 v1.5 signature algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)                                    \
	((psa_algorithm_t)(PSA_ALG_RSA_PKCS1V15_SIGN_BASE |                    \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_RSA_PSS() - The RSA PSS message signature scheme, with hashing.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *            This includes PSA_ALG_ANY_HASH when specifying the algorithm in a key policy.
 *
 * This algorithm can be used with both the message and hash signature functions.
 *
 * This algorithm is randomized: each invocation returns a different, equally valid signature.
 *
 * This is the signature scheme defined by [RFC8017] §8.1 under the name RSASSA-PSS, with the
 * following options\:
 *
 * - The mask generation function is MGF1 defined by [RFC8017] Appendix B.
 *
 * - The salt length is equal to the length of the hash.
 *
 * - The specified hash algorithm is used to hash the input message, to create the salted hash, and
 *   for the mask generation.
 *
 * Return:
 * The corresponding RSA PSS signature algorithm.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 *
 */
#define PSA_ALG_RSA_PSS(hash_alg)                                              \
	((psa_algorithm_t)(PSA_ALG_RSA_PSS_BASE |                              \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_TLS12_PRF() - Macro to build a TLS-1.2 PRF algorithm.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *
 * TLS 1.2 uses a custom pseudorandom function (PRF) for key schedule, specified in The Transport
 * Layer Security (TLS) Protocol Version 1.2 [RFC5246] §5. It is based on HMAC and can be used with
 * either SHA-256 or SHA-384.
 *
 * This key derivation algorithm uses the following inputs, which must be passed in the order given
 * here\:
 *
 * - PSA_KEY_DERIVATION_INPUT_SEED is the seed.
 *
 * - PSA_KEY_DERIVATION_INPUT_SECRET is the secret key.
 *
 * - PSA_KEY_DERIVATION_INPUT_LABEL is the label.
 *
 * Each input may only be passed once.
 *
 * For the application to TLS-1.2 key expansion\:
 *
 * - The seed is the concatenation of ServerHello.Random + ClientHello.Random.
 *
 * - The label is "key expansion".
 *
 * Return:
 * The corresponding TLS-1.2 PRF algorithm. For example, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256)
 * represents the TLS 1.2 PRF using HMAC-SHA-256.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_TLS12_PRF(hash_alg)                                            \
	((psa_algorithm_t)(PSA_ALG_TLS12_PRF_BASE |                            \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_TLS12_PSK_TO_MS() - Macro to build a TLS-1.2 PSK-to-MasterSecret algorithm.
 * @hash_alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *
 * In a pure-PSK handshake in TLS 1.2, the master secret (MS) is derived from the pre-shared key
 * (PSK) through the application of padding (Pre-Shared Key Ciphersuites for Transport Layer
 * Security (TLS) [RFC4279] §2) and the TLS-1.2 PRF (The Transport Layer Security (TLS) Protocol
 * Version 1.2 [RFC5246] §5). The latter is based on HMAC and can be used with either SHA-256 or
 * SHA-384.
 *
 * This key derivation algorithm uses the following inputs, which must be passed in the order given
 * here\:
 *
 * - PSA_KEY_DERIVATION_INPUT_SEED is the seed.
 *
 * - PSA_KEY_DERIVATION_INPUT_SECRET is the PSK. The PSK must not be larger than
 *   PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE.
 *
 * - PSA_KEY_DERIVATION_INPUT_LABEL is the label.
 *
 * Each input may only be passed once.
 *
 * For the application to TLS-1.2\:
 *
 * - The seed, which is forwarded to the TLS-1.2 PRF, is the concatenation of the ClientHello.Random
 *   + ServerHello.Random.
 *
 * - The label is "master secret" or "extended master secret".
 *
 * Return:
 * The corresponding TLS-1.2 PSK to MS algorithm. For example,
 * PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256) represents the TLS-1.2 PSK to MasterSecret derivation
 * PRF using HMAC-SHA-256.
 *
 * Unspecified if @hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_TLS12_PSK_TO_MS(hash_alg)                                      \
	((psa_algorithm_t)(PSA_ALG_TLS12_PSK_TO_MS_BASE |                      \
			   ((hash_alg) & (PSA_ALG_HASH_MASK))))

/**
 * PSA_ALG_TRUNCATED_MAC() - Macro to build a truncated MAC algorithm.
 * @mac_alg: A MAC algorithm identifier (value of &typedef psa_algorithm_t such that
 *           PSA_ALG_IS_MAC(mac_alg) is true). This can be a truncated or untruncated MAC algorithm.
 * @mac_length: Desired length of the truncated MAC in bytes. This must be at most the full length
 *              of the MAC and must be at least an implementation-specified minimum. The
 *              implementation-specified minimum must not be zero.
 *
 * A truncated MAC algorithm is identical to the corresponding MAC algorithm except that the MAC
 * value for the truncated algorithm consists of only the first @mac_length bytes of the MAC value
 * for the untruncated algorithm.
 *
 * **Note**:
 *	This macro might allow constructing algorithm identifiers that are not valid, either because
 *	the specified length is larger than the untruncated MAC or because the specified length is
 *	smaller than permitted by the implementation.
 *
 * **Note**:
 *	It is implementation-defined whether a truncated MAC that is truncated to the same length as
 *	the MAC of the untruncated algorithm is considered identical to the untruncated algorithm
 *	for policy comparison purposes.
 *
 * The full-length MAC algorithm can be recovered using PSA_ALG_FULL_LENGTH_MAC().
 *
 * Return:
 * The corresponding MAC algorithm with the specified length.
 *
 * Unspecified if alg is not a supported MAC algorithm or if @mac_length is too small or too large
 * for the specified MAC algorithm.
 */
#define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length)                             \
	((psa_algorithm_t)(((mac_alg) & ~PSA_ALG_MAC_TRUNCATION_MASK) |        \
			   (((mac_length) << PSA_MAC_TRUNCATION_OFFSET) &      \
			    PSA_ALG_MAC_TRUNCATION_MASK)))

/**
 * PSA_BLOCK_CIPHER_BLOCK_LENGTH() - The block size of a block cipher.
 * @type: A cipher key type (value of &typedef psa_key_type_t).
 *
 * **Note**:
 *	It is possible to build stream cipher algorithms on top of a block cipher, for example CTR
 *	mode (PSA_ALG_CTR). This macro only takes the key type into account, so it cannot be used to
 *	determine the size of the data that psa_cipher_update() might buffer for future processing
 *	in general.
 *
 * **Note**:
 *	This macro expression is a compile-time constant if @type is a compile-time constant.
 *
 * **Warning**:
 *	This macro is permitted to evaluate its argument multiple times.
 *
 * See also PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE.
 *
 * Return:
 * The block size for a block cipher, or 1 for a stream cipher. The return value is undefined if
 * @type is not a supported cipher key type.
 */
#define PSA_BLOCK_CIPHER_BLOCK_LENGTH(type) (1u << (((type) >> 8) & 7))

/**
 * DOC: PSA_DH_FAMILY_RFC7919
 * Finite-field Diffie-Hellman groups defined for TLS in RFC 7919.
 *
 * This family includes groups with the following key sizes (in bits): 2048, 3072, 4096, 6144, 8192.
 * An implementation can support all of these sizes or only a subset.
 *
 * Keys is this group can only be used with the PSA_ALG_FFDH key agreement algorithm.
 *
 * These groups are defined by Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for
 * Transport Layer Security (TLS) [RFC7919] Appendix A.
 */
#define PSA_DH_FAMILY_RFC7919 ((psa_dh_family_t)0x03)

/**
 * DOC: PSA_ECC_FAMILY_BRAINPOOL_P_R1
 * Brainpool P random curves.
 *
 * This family comprises the following curves\:
 *
 * - brainpoolP160r1 : key_bits = 160 (Deprecated)
 * - brainpoolP192r1 : key_bits = 192
 * - brainpoolP224r1 : key_bits = 224
 * - brainpoolP256r1 : key_bits = 256
 * - brainpoolP320r1 : key_bits = 320
 * - brainpoolP384r1 : key_bits = 384
 * - brainpoolP512r1 : key_bits = 512
 *
 * They are defined in Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve
 * Generation [RFC5639].
 *
 * **Warning**
 *	The 160-bit curve brainpoolP160r1 is weak and deprecated and is only recommended for use in
 *	legacy protocols.
 */
#define PSA_ECC_FAMILY_BRAINPOOL_P_R1 ((psa_ecc_family_t)0x30)

/**
 * DOC: PSA_ECC_FAMILY_FRP
 * Curve used primarily in France and elsewhere in Europe.
 *
 * This family comprises one 256-bit curve\:
 *
 * - FRP256v1 : key_bits = 256
 *
 * This is defined by Publication d'un paramétrage de courbe elliptique visant des applications de
 * passeport électronique et de l'administration électronique française [FRP].
 */
#define PSA_ECC_FAMILY_FRP ((psa_ecc_family_t)0x33)

/**
 * DOC: PSA_ECC_FAMILY_MONTGOMERY
 * Montgomery curves.
 *
 * This family comprises the following Montgomery curves\:
 *
 * - Curve25519 : key_bits = 255
 * - Curve448 : key_bits = 448
 *
 * Keys in this family can only be used with the PSA_ALG_ECDH key agreement algorithm.
 *
 * Curve25519 is defined in Curve25519: new Diffie-Hellman speed records [Curve25519]. Curve448 is
 * defined in Ed448-Goldilocks, a new elliptic curve [Curve448].
 */
#define PSA_ECC_FAMILY_MONTGOMERY ((psa_ecc_family_t)0x41)

/**
 * DOC: PSA_ECC_FAMILY_SECP_K1
 * SEC Koblitz curves over prime fields.
 *
 * This family comprises the following curves\:
 *
 * - secp192k1 : key_bits = 192
 * - secp224k1 : key_bits = 225
 * - secp256k1 : key_bits = 256
 *
 * They are defined in SEC 2: Recommended Elliptic Curve Domain Parameters [SEC2].
 */
#define PSA_ECC_FAMILY_SECP_K1 ((psa_ecc_family_t)0x17)

/**
 * DOC: PSA_ECC_FAMILY_SECP_R1
 * SEC random curves over prime fields.
 *
 * This family comprises the following curves\:
 *
 * - secp192r1 : key_bits = 192
 * - secp224r1 : key_bits = 224
 * - secp256r1 : key_bits = 256
 * - secp384r1 : key_bits = 384
 * - secp521r1 : key_bits = 521
 *
 * They are defined in [SEC2]
 */
#define PSA_ECC_FAMILY_SECP_R1 ((psa_ecc_family_t)0x12)

/**
 * DOC: PSA_ECC_FAMILY_SECP_R2
 * **Warning**:
 *	This family of curves is weak and deprecated.
 *
 * This family comprises the following curves\:
 *
 * - secp160r2 : key_bits = 160 (Deprecated)
 *
 * It is defined in the superseded SEC 2: Recommended Elliptic Curve Domain Parameters, Version 1.0
 * [SEC2v1].
 */
#define PSA_ECC_FAMILY_SECP_R2 ((psa_ecc_family_t)0x1b)

/**
 * DOC: PSA_ECC_FAMILY_SECT_K1
 * SEC Koblitz curves over binary fields.
 *
 * This family comprises the following curves\:
 *
 * - sect163k1 : key_bits = 163 (Deprecated)
 * - sect233k1 : key_bits = 233
 * - sect239k1 : key_bits = 239
 * - sect283k1 : key_bits = 283
 * - sect409k1 : key_bits = 409
 * - sect571k1 : key_bits = 571
 *
 * They are defined in [SEC2].
 *
 * **Warning**:
 *	The 163-bit curve sect163k1 is weak and deprecated and is only recommended for use in legacy
 *	protocols.
 */
#define PSA_ECC_FAMILY_SECT_K1 ((psa_ecc_family_t)0x27)

/**
 * DOC: PSA_ECC_FAMILY_SECT_R1
 * SEC random curves over binary fields.
 *
 * This family comprises the following curves:
 *
 * - sect163r1 : key_bits = 163 (Deprecated)
 * - sect233r1 : key_bits = 233
 * - sect283r1 : key_bits = 283
 * - sect409r1 : key_bits = 409
 * - sect571r1 : key_bits = 571
 *
 * They are defined in [SEC2].
 *
 * **Warning**:
 *	The 163-bit curve sect163r1 is weak and deprecated and is only recommended for use in legacy
 *	protocols.
 */
#define PSA_ECC_FAMILY_SECT_R1 ((psa_ecc_family_t)0x22)

/**
 * DOC: PSA_ECC_FAMILY_SECT_R2
 * SEC additional random curves over binary fields.
 *
 * This family comprises the following curves:
 *
 * - sect163r2 : key_bits = 163 (Deprecated)
 *
 * It is defined in [SEC2].
 *
 * **Warning**:
 *	The 163-bit curve sect163r2 is weak and deprecated and is only recommended for use in legacy
 *	protocols.
 */
#define PSA_ECC_FAMILY_SECT_R2 ((psa_ecc_family_t)0x2b)

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_CONTEXT
 * A context for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a direct input. It can also be a key of type PSA_KEY_TYPE_RAW_DATA.
 */
#define PSA_KEY_DERIVATION_INPUT_CONTEXT /* implementation-defined value */

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_INFO
 * An information string for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a direct input. It can also be a key of type PSA_KEY_TYPE_RAW_DATA.
 */
#define PSA_KEY_DERIVATION_INPUT_INFO /* implementation-defined value */

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_LABEL
 * A label for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a direct input. It can also be a key of type PSA_KEY_TYPE_RAW_DATA.
 */
#define PSA_KEY_DERIVATION_INPUT_LABEL /* implementation-defined value */

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_SALT
 * A salt for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a direct input. It can also be a key of type PSA_KEY_TYPE_RAW_DATA.
 */
#define PSA_KEY_DERIVATION_INPUT_SALT /* implementation-defined value */

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_SECRET
 * A secret input for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a key of type PSA_KEY_TYPE_DERIVE passed to psa_key_derivation_input_key(), or
 * the shared secret resulting from a key agreement obtained via psa_key_derivation_key_agreement().
 *
 * The secret can also be a direct input passed to psa_key_derivation_input_bytes(). In this case,
 * the derivation operation cannot be used to derive keys: the operation will only allow
 * psa_key_derivation_output_bytes(), not psa_key_derivation_output_key().
 */
#define PSA_KEY_DERIVATION_INPUT_SECRET /* implementation-defined value */

/**
 * DOC: PSA_KEY_DERIVATION_INPUT_SEED
 * A seed for key derivation.
 *
 * **Warning: Not supported**
 *
 * This is typically a direct input. It can also be a key of type PSA_KEY_TYPE_RAW_DATA.
 */
#define PSA_KEY_DERIVATION_INPUT_SEED /* implementation-defined value */

/**
 * DOC: PSA_KEY_ID_NULL
 * The null key identifier.
 *
 * The null key identifier is always invalid, except when used without in a call to
 * psa_destroy_key() which will return PSA_SUCCESS.
 */
#define PSA_KEY_ID_NULL ((psa_key_id_t)0)

/**
 * DOC: PSA_KEY_ID_USER_MAX
 * The maximum value for a key identifier chosen by the application.
 */
#define PSA_KEY_ID_USER_MAX ((psa_key_id_t)0x3fffffff)

/**
 * DOC: PSA_KEY_ID_USER_MIN
 * The minimum value for a key identifier chosen by the application.
 */
#define PSA_KEY_ID_USER_MIN ((psa_key_id_t)0x00000001)

/**
 * DOC: PSA_KEY_ID_VENDOR_MAX
 * The maximum value for a key identifier chosen by the implementation.
 */
#define PSA_KEY_ID_VENDOR_MAX ((psa_key_id_t)0x7fffffff)

/**
 * DOC: PSA_KEY_ID_VENDOR_MIN
 * The minimum value for a key identifier chosen by the implementation.
 */
#define PSA_KEY_ID_VENDOR_MIN ((psa_key_id_t)0x40000000)

/**
 * PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION() - Construct a lifetime from a persistence level
 * and a location.
 * @persistence: The persistence level (value of &typedef psa_key_persistence_t).
 * @location: The location indicator (value of &typedef psa_key_location_t).
 *
 * Return:
 * The constructed lifetime value.
 */
#define PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence, location)  \
	((location) << 8 | (persistence))

#define PSA_KEY_LIFETIME_GET_LIFETIME(persistence, location)                   \
	PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence, location)

/**
 * PSA_KEY_LIFETIME_GET_LOCATION() - Extract the location indicator from a key lifetime.
 * @lifetime: The lifetime value to query (value of &typedef psa_key_lifetime_t).
 */
#define PSA_KEY_LIFETIME_GET_LOCATION(lifetime)                                \
	((psa_key_location_t)((lifetime) >> 8))

/**
 * PSA_KEY_LIFETIME_GET_PERSISTENCE() - Extract the persistence level from a key lifetime.
 * @lifetime: The lifetime value to query (value of &typedef psa_key_lifetime_t).
 */
#define PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime)                             \
	((psa_key_persistence_t)(lifetime))

/**
 * PSA_KEY_LIFETIME_IS_VOLATILE() - Whether a key lifetime indicates that the key is volatile.
 * @lifetime: The lifetime value to query (value of &typedef psa_key_lifetime_t).
 *
 * A volatile key is automatically destroyed by the implementation when the application instance
 * terminates. In particular, a volatile key is automatically destroyed on a power reset of the
 * device.
 *
 * A key that is not volatile is persistent. Persistent keys are preserved until the application
 * explicitly destroys them or until an implementation-specific device management event occurs,for
 * example, a factory reset.
 *
 * Return:
 * 1 if the key is volatile, otherwise 0.
 */
#define PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)                                 \
	(PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) ==                         \
	 PSA_KEY_PERSISTENCE_VOLATILE)

/**
 * DOC: PSA_KEY_LIFETIME_PERSISTENT
 * The default lifetime for persistent keys.
 *
 * A persistent key remains in storage until it is explicitly destroyed or until the corresponding
 * storage area is wiped. This specification does not define any mechanism to wipe a storage area.
 * Implementations are permitted to provide their own mechanism, for example, to perform a factory
 * reset, to prepare for device refurbishment, or to uninstall an application.
 *
 * This lifetime value is the default storage area for the calling application. Implementations can
 * offer other storage areas designated by other lifetime values as implementation-specific
 * extensions.
 */
#define PSA_KEY_LIFETIME_PERSISTENT ((psa_key_lifetime_t)0x00000001)

/**
 * DOC: PSA_KEY_LIFETIME_VOLATILE
 * The default lifetime for volatile keys.
 *
 * A volatile key only exists as long as its identifier is not destroyed. The key material is
 * guaranteed to be erased on a power reset.
 *
 * A key with this lifetime is typically stored in the RAM area of the PSA Crypto subsystem.
 * However this is an implementation choice. If an implementation stores data about the key in a
 * non-volatile memory, it must release all the resources associated with the key and erase the key
 * material if the calling application terminates.
 */
#define PSA_KEY_LIFETIME_VOLATILE ((psa_key_lifetime_t)0x00000000)

/**
 * DOC: PSA_KEY_LOCATION_LOCAL_STORAGE
 * The local storage area for persistent keys.
 *
 * This storage area is available on all systems that can store persistent keys without delegating
 * the storage to a third-party cryptoprocessor.
 *
 * See &typedef psa_key_location_t for more information.
 */
#define PSA_KEY_LOCATION_LOCAL_STORAGE ((psa_key_location_t)0x000000)

/**
 * DOC: PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT
 * The default secure element storage area for persistent keys.
 *
 * This storage location is available on systems that have one or more secure elements that are able
 * to store keys.
 *
 * Vendor-defined locations must be provided by the system for storing keys in additional secure
 * elements.
 *
 * See &typedef psa_key_location_t for more information.
 */
#define PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT ((psa_key_location_t)0x000001)

/**
 * DOC: PSA_KEY_PERSISTENCE_DEFAULT
 * The default persistence level for persistent keys.
 *
 * See &typedef psa_key_persistence_t for more information.
 */
#define PSA_KEY_PERSISTENCE_DEFAULT ((psa_key_persistence_t)0x01)

/**
 * DOC: PSA_KEY_PERSISTENCE_READ_ONLY
 * A persistence level indicating that a key is never destroyed.
 *
 * See &typedef psa_key_persistence_t for more information.
 */
#define PSA_KEY_PERSISTENCE_READ_ONLY ((psa_key_persistence_t)0xff)

/**
 * DOC: PSA_KEY_PERSISTENCE_VOLATILE
 * The persistence level of volatile keys.
 *
 * See &typedef psa_key_persistence_t for more information.
 */
#define PSA_KEY_PERSISTENCE_VOLATILE ((psa_key_persistence_t)0x00)

/**
 * DOC: PSA_KEY_TYPE_AES
 * Key for a cipher, AEAD or MAC algorithm based on the AES block cipher.
 *
 * The size of the key is related to the AES algorithm variant. For algorithms except the XTS block
 * cipher mode, the following key sizes are used\:
 *
 * - AES-128 uses a 16-byte key : key_bits = 128
 * - AES-192 uses a 24-byte key : key_bits = 192
 * - AES-256 uses a 32-byte key : key_bits = 256
 *
 * For the XTS block cipher mode (PSA_ALG_XTS), the following key sizes are used\:
 *
 * - AES-128-XTS uses two 16-byte keys : key_bits = 256
 * - AES-192-XTS uses two 24-byte keys : key_bits = 384
 * - AES-256-XTS uses two 32-byte keys : key_bits = 512
 *
 * The AES block cipher is defined in FIPS Publication 197: Advanced Encryption Standard (AES)
 * [FIPS197].
 */
#define PSA_KEY_TYPE_AES ((psa_key_type_t)0x2400)

/**
 * DOC: PSA_KEY_TYPE_ARC4
 * Key for the ARC4 stream cipher.
 *
 * **Warning**:
 *	The ARC4 cipher is weak and deprecated and is only recommended for use in legacy protocols.
 *
 * The ARC4 cipher supports key sizes between 40 and 2048 bits, that are multiples of 8. (5 to 256
 * bytes)
 *
 * Use algorithm PSA_ALG_STREAM_CIPHER to use this key with the ARC4 cipher.
 */
#define PSA_KEY_TYPE_ARC4 ((psa_key_type_t)0x2002)

/**
 * DOC: PSA_KEY_TYPE_CAMELLIA
 * Key for a cipher, AEAD or MAC algorithm based on the Camellia block cipher.
 *
 * The size of the key is related to the Camellia algorithm variant. For algorithms except the XTS
 * block cipher mode, the following key sizes are used\:
 *
 * - Camellia-128 uses a 16-byte key : key_bits = 128
 * - Camellia-192 uses a 24-byte key : key_bits = 192
 * - Camellia-256 uses a 32-byte key : key_bits = 256
 *
 * For the XTS block cipher mode (PSA_ALG_XTS), the following key sizes are used\:
 *
 * - Camellia-128-XTS uses two 16-byte keys : key_bits = 256
 * - Camellia-192-XTS uses two 24-byte keys : key_bits = 384
 * - Camellia-256-XTS uses two 32-byte keys : key_bits = 512
 *
 * The Camellia block cipher is defined in Specification of Camellia — a 128-bit Block Cipher
 * [NTT-CAM] and also described in A Description of the Camellia Encryption Algorithm [RFC3713].
 */
#define PSA_KEY_TYPE_CAMELLIA ((psa_key_type_t)0x2403)

/**
 * DOC: PSA_KEY_TYPE_CHACHA20
 * Key for the ChaCha20 stream cipher or the ChaCha20-Poly1305 AEAD algorithm.
 *
 * The ChaCha20 key size is 256 bits (32 bytes).
 *
 * - Use algorithm PSA_ALG_STREAM_CIPHER to use this key with the ChaCha20 cipher for
 *   unauthenticated encryption. See PSA_ALG_STREAM_CIPHER for details of this algorithm.
 *
 * - Use algorithm PSA_ALG_CHACHA20_POLY1305 to use this key with the ChaCha20 cipher and Poly1305
 *   authenticator for AEAD. See PSA_ALG_CHACHA20_POLY1305 for details of this algorithm.
 */
#define PSA_KEY_TYPE_CHACHA20 ((psa_key_type_t)0x2004)

/**
 * DOC: PSA_KEY_TYPE_DERIVE
 * A secret for key derivation.
 *
 * The key policy determines which key derivation algorithm the key can be used for.
 *
 * The bit size of a secret for key derivation must be a non-zero multiple of 8. The maximum size of
 * a secret for key derivation is IMPLEMENTATION DEFINED.
 */
#define PSA_KEY_TYPE_DERIVE ((psa_key_type_t)0x1200)

/**
 * DOC: PSA_KEY_TYPE_DES
 * Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).
 *
 * The size of the key determines which DES algorithm is used\:
 *
 * - Single DES uses an 8-byte key : key_bits = 64
 * - 2-key 3DES uses a 16-byte key : key_bits = 128
 * - 3-key 3DES uses a 24-byte key : key_bits = 192
 *
 * **Warning**:
 *	Single DES and 2-key 3DES are weak and strongly deprecated and are only recommended for
 *	decrypting legacy data.
 *
 *	3-key 3DES is weak and deprecated and is only recommended for use in legacy protocols.
 *
 * The DES and 3DES block ciphers are defined in NIST Special Publication 800-67: Recommendation for
 * the Triple Data Encryption Algorithm (TDEA) Block Cipher [SP800-67].
 */
#define PSA_KEY_TYPE_DES ((psa_key_type_t)0x2301)

/**
 * PSA_KEY_TYPE_DH_GET_FAMILY() - Extract the group family from a Diffie-Hellman key type.
 * @type: A Diffie-Hellman key type (value of &typedef psa_key_type_t such that
 *        PSA_KEY_TYPE_IS_DH(type) is true).
 *
 * Return:
 * &typedef psa_dh_family_t
 *
 * The Diffie-Hellman group family id, if @type is a supported Diffie-Hellman key. Unspecified if
 * @type is not a supported Diffie-Hellman key.
 */
#define PSA_KEY_TYPE_DH_GET_FAMILY(type)                                       \
	((psa_dh_family_t)((type) & (PSA_KEY_TYPE_DH_GROUP_MASK)))

/**
 * PSA_KEY_TYPE_DH_KEY_PAIR() - Finite-field Diffie-Hellman key pair: both the private key and
 * public key.
 * @group: A value of &typedef psa_dh_family_t that identifies the Diffie-Hellman group family to
 *         be used.
 */
#define PSA_KEY_TYPE_DH_KEY_PAIR(group)                                        \
	((psa_key_type_t)(PSA_KEY_TYPE_DH_KEY_PAIR_BASE | (group)))

/**
 * PSA_KEY_TYPE_DH_PUBLIC_KEY() - Finite-field Diffie-Hellman public key.
 * @group: A value of &typedef psa_dh_family_t that identifies the Diffie-Hellman group family to
 *         be used.
 */
#define PSA_KEY_TYPE_DH_PUBLIC_KEY(group)                                      \
	((psa_key_type_t)(PSA_KEY_TYPE_DH_PUBLIC_KEY_BASE | (group)))

/**
 * PSA_KEY_TYPE_ECC_GET_FAMILY() - Extract the curve family from an elliptic curve key type.
 * @type: An elliptic curve key type (value of &typedef psa_key_type_t such that
 *        PSA_KEY_TYPE_IS_ECC(type) is true).
 *
 * Return:
 * &typedef psa_ecc_family_t
 *
 * The elliptic curve family id, if @type is a supported elliptic curve key. Unspecified if @type is
 * not a supported elliptic curve key.
 */
#define PSA_KEY_TYPE_ECC_GET_FAMILY(type)                                      \
	((psa_ecc_family_t)((type) & (PSA_KEY_TYPE_ECC_CURVE_MASK)))

/**
 * PSA_KEY_TYPE_ECC_KEY_PAIR() - Elliptic curve key pair: both the private and public key.
 * @curve: A value of &typedef psa_ecc_family_t that identifies the ECC curve family to be used.
 */
#define PSA_KEY_TYPE_ECC_KEY_PAIR(curve)                                       \
	((psa_key_type_t)(PSA_KEY_TYPE_ECC_KEY_PAIR_BASE | (curve)))

/**
 * PSA_KEY_TYPE_ECC_PUBLIC_KEY() - Elliptic curve public key.
 * @curve: A value of &typedef psa_ecc_family_t that identifies the ECC curve family to be used.
 */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)                                     \
	((psa_key_type_t)(PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve)))

/**
 * DOC: PSA_KEY_TYPE_HMAC
 * HMAC key.
 *
 * The key policy determines which underlying hash algorithm the key can be used for.
 *
 * The bit size of an HMAC key must be a non-zero multiple of 8. An HMAC key is typically the same
 * size as the output of the underlying hash algorithm. An HMAC key that is longer than the block
 * size of the underlying hash algorithm will be hashed before use.
 *
 * When an HMAC key is created that is longer than the block size, it is implementation defined
 * whether the implementation stores the original HMAC key, or the hash of the HMAC key. If the hash
 * of the key is stored, the key size reported by psa_get_key_attributes() will be the size of the
 * hashed key.
 *
 * **Note**:
 *	PSA_HASH_LENGTH(alg) provides the output size of hash algorithm alg, in bytes.
 *
 *	PSA_HASH_BLOCK_LENGTH(alg) provides the block size of hash algorithm alg, in bytes.
 */
#define PSA_KEY_TYPE_HMAC ((psa_key_type_t)0x1100)

/**
 * PSA_KEY_TYPE_IS_ASYMMETRIC() - Whether a key type is asymmetric: either a key pair or a public
 * key.
 * @type: A key type (value of &typedef psa_key_type_t).
 *
 * See RSA keys for a list of asymmetric key types.
 */
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)                                       \
	(((type) & (PSA_KEY_TYPE_CATEGORY_MASK) &                              \
	  ~PSA_KEY_TYPE_CATEGORY_FLAG_PAIR) ==                                 \
	 PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY)

/**
 * PSA_KEY_TYPE_IS_DH() - Whether a key type is a Diffie-Hellman key, either a key pair or a public
 * key.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_DH(type)                                               \
	((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) &                          \
	  ~PSA_KEY_TYPE_DH_GROUP_MASK) == PSA_KEY_TYPE_DH_PUBLIC_KEY_BASE)

/**
 * PSA_KEY_TYPE_IS_DH_KEY_PAIR() - Whether a key type is a Diffie-Hellman key pair.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_DH_KEY_PAIR(type)                                      \
	(((type) & ~PSA_KEY_TYPE_DH_GROUP_MASK) ==                             \
	 PSA_KEY_TYPE_DH_KEY_PAIR_BASE)

/**
 * PSA_KEY_TYPE_IS_DH_PUBLIC_KEY() - Whether a key type is a Diffie-Hellman public key.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(type)                                    \
	(((type) & ~PSA_KEY_TYPE_DH_GROUP_MASK) ==                             \
	 PSA_KEY_TYPE_DH_PUBLIC_KEY_BASE)

/**
 * PSA_KEY_TYPE_IS_ECC() - Whether a key type is an elliptic curve key, either a key pair or a
 * public key.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_ECC(type)                                              \
	((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) &                          \
	  ~PSA_KEY_TYPE_ECC_CURVE_MASK) == PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/**
 * PSA_KEY_TYPE_IS_ECC_KEY_PAIR() - Whether a key type is an elliptic curve key pair.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)                                     \
	(((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                            \
	 PSA_KEY_TYPE_ECC_KEY_PAIR_BASE)

/**
 * PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY() - Whether a key type is an elliptic curve key pair.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)                                   \
	(((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                            \
	 PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/**
 * PSA_KEY_TYPE_IS_KEY_PAIR() - Whether a key type is a key pair containing a private part and a
 * public part.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_KEY_PAIR(type)                                         \
	(((type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==                            \
	 PSA_KEY_TYPE_CATEGORY_KEY_PAIR)

/**
 * PSA_KEY_TYPE_IS_PUBLIC_KEY() - Whether a key type is the public part of a key pair.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)                                       \
	(((type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==                            \
	 PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY)

/**
 * PSA_KEY_TYPE_IS_RSA() - Whether a key type is an RSA key. This includes both key pairs and public
 * keys.
 * @type: A key type (value of &typedef psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_RSA(type)                                              \
	(PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) ==                          \
	 PSA_KEY_TYPE_RSA_PUBLIC_KEY)

/**
 * PSA_KEY_TYPE_IS_UNSTRUCTURED() - Whether a key type is an unstructured array of bytes.
 * @type: A key type (value of &typedef psa_key_type_t).
 *
 * This encompasses both symmetric keys and non-key data.
 *
 * See Symmetric keys for a list of symmetric key types.
 */
#define PSA_KEY_TYPE_IS_UNSTRUCTURED(type)                                     \
	(((type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==                            \
		 PSA_KEY_TYPE_CATEGORY_RAW ||                                  \
	 ((type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==                            \
		 PSA_KEY_TYPE_CATEGORY_SYMMETRIC)
/**
 * PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY() - The key pair type corresponding to a public key type.
 * @type: A public key type or key pair type.
 *
 * If type is a key pair type, it will be left unchanged.
 *
 * Return:
 * The corresponding key pair type. If @type is not a public key or a key pair, the return value is
 * undefined.
 */
#define PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(type)                              \
	((psa_key_type_t)((type) | PSA_KEY_TYPE_CATEGORY_FLAG_PAIR))

/**
 * DOC: PSA_KEY_TYPE_NONE
 * An invalid key type value.
 *
 * Zero is not the encoding of any key type.
 */
#define PSA_KEY_TYPE_NONE ((psa_key_type_t)0x0000)

/**
 * PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR() - The public key type corresponding to a key pair type.
 * @type: A public key type or key pair type.
 *
 * If type is a public key type, it will be left unchanged.
 *
 * Return:
 * The corresponding public key type. If @type is not a public key or a key pair, the return value
 * is undefined.
 */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type)                              \
	((psa_key_type_t)((type) & ~PSA_KEY_TYPE_CATEGORY_FLAG_PAIR))

/**
 * DOC: PSA_KEY_TYPE_RAW_DATA
 * Raw data.
 *
 * A “key” of this type cannot be used for any cryptographic operation. Applications can use
 * this type to store arbitrary data in the keystore.
 *
 * The bit size of a raw key must be a non-zero multiple of 8. The maximum size of a raw key is
 * IMPLEMENTATION DEFINED.
 */
#define PSA_KEY_TYPE_RAW_DATA ((psa_key_type_t)0x1001)

/**
 * DOC: PSA_KEY_TYPE_RSA_KEY_PAIR
 * RSA key pair: both the private and public key.
 */
#define PSA_KEY_TYPE_RSA_KEY_PAIR ((psa_key_type_t)0x7001)

/**
 * DOC: PSA_KEY_TYPE_RSA_PUBLIC_KEY
 * RSA public key.
 */
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY ((psa_key_type_t)0x4001)

/**
 * DOC: PSA_KEY_TYPE_SM4
 * Key for a cipher, AEAD or MAC algorithm based on the SM4 block cipher.
 *
 * For algorithms except the XTS block cipher mode, the SM4 key size is 128 bits (16 bytes).
 *
 * For the XTS block cipher mode (PSA_ALG_XTS), the SM4 key size is 256 bits (two 16-byte keys).
 *
 * The SM4 block cipher is defined in GB/T 32907-2016: Information security technology — SM4 block
 * cipher algorithm [PRC-SM4] and also described in The SM4 Blockcipher Algorithm And Its Modes Of
 * Operations [IETF-SM4].
 */
#define PSA_KEY_TYPE_SM4 ((psa_key_type_t)0x2405)

/**
 * DOC: PSA_KEY_USAGE_CACHE
 * Permission for the implementation to cache the key.
 *
 * This flag allows the implementation to make additional copies of the key material that are not in
 * storage and not for the purpose of an ongoing operation. Applications can use it as a hint to
 * keep the key around for repeated access.
 *
 * An application can request that cached key material is removed from memory by calling
 * psa_purge_key().
 *
 * The presence of this usage flag when creating a key is a hint:
 *
 * - An implementation is not required to cache keys that have this usage flag.
 *
 * - An implementation must not report an error if it does not cache keys.
 *
 * If this usage flag is not present, the implementation must ensure key material is removed from
 * memory as soon as it is not required for an operation or for maintenance of a volatile key.
 *
 * This flag must be preserved when reading back the attributes for all keys, regardless of key type
 * or implementation behavior.
 */
#define PSA_KEY_USAGE_CACHE ((psa_key_usage_t)0x00000004)

/**
 * DOC: PSA_KEY_USAGE_COPY
 * Permission to copy the key.
 *
 * This flag allows the use of psa_copy_key() to make a copy of the key with the same policy or a
 * more restrictive policy.
 *
 * For lifetimes for which the key is located in a secure element which enforce the
 * non-exportability of keys, copying a key outside the secure element also requires the usage flag
 * PSA_KEY_USAGE_EXPORT. Copying the key inside the secure element is permitted with just
 * PSA_KEY_USAGE_COPY if the secure element supports it. For keys with the lifetime
 * PSA_KEY_LIFETIME_VOLATILE or PSA_KEY_LIFETIME_PERSISTENT, the usage flag PSA_KEY_USAGE_COPY is
 * sufficient to permit the copy.
 */
#define PSA_KEY_USAGE_COPY ((psa_key_usage_t)0x00000002)

/**
 * DOC: PSA_KEY_USAGE_DECRYPT
 * Permission to decrypt a message with the key.
 * This flag allows the key to be used for a symmetric decryption operation, for an AEAD
 * decryption-and-verification operation, or for an asymmetric decryption operation, if otherwise
 * permitted by the key’s type and policy. The flag must be present on keys used with the
 * following APIs\:
 *
 * - psa_cipher_decrypt()
 * - psa_cipher_decrypt_setup()
 * - psa_aead_decrypt()
 * - psa_aead_decrypt_setup()
 * - psa_asymmetric_decrypt()
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_DECRYPT ((psa_key_usage_t)0x00000200)

/**
 * DOC: PSA_KEY_USAGE_DERIVE
 * Permission to derive other keys from this key.
 *
 * This flag allows the key to be used for a key derivation operation or for a key agreement
 * operation, if otherwise permitted by the key’s type and policy. The flag must be present on
 * keys used with the following APIs\:
 *
 * - psa_key_derivation_input_key()
 * - psa_key_derivation_key_agreement()
 * - psa_raw_key_agreement()
 */
#define PSA_KEY_USAGE_DERIVE ((psa_key_usage_t)0x00004000)

/**
 * DOC: PSA_KEY_USAGE_ENCRYPT
 * Permission to encrypt a message with the key.
 *
 * This flag allows the key to be used for a symmetric encryption operation, for an AEAD
 * encryption-and-authentication operation, or for an asymmetric encryption operation, if
 * otherwise permitted by the key’s type and policy. The flag must be present on keys used with
 * the following APIs\:
 *
 * - psa_cipher_encrypt()
 * - psa_cipher_encrypt_setup()
 * - psa_aead_encrypt()
 * - psa_aead_encrypt_setup()
 * - psa_asymmetric_encrypt()
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_ENCRYPT ((psa_key_usage_t)0x00000100)

/**
 * DOC: PSA_KEY_USAGE_EXPORT
 * Permission to export the key.
 *
 * This flag allows the use of psa_export_key() to export a key from the cryptoprocessor. A public
 * ey or the public part of a key pair can always be exported regardless of the value of this
 * permission flag.
 *
 * This flag can also be required to copy a key using psa_copy_key() outside of a secure element.
 * See also PSA_KEY_USAGE_COPY.
 *
 * If a key does not have export permission, implementations must not allow the key to be exported
 * in plain form from the cryptoprocessor, whether through psa_export_key() or through a proprietary
 * interface. The key might still be exportable in a wrapped form, i.e. in a form where it is
 * encrypted by another key.
 */
#define PSA_KEY_USAGE_EXPORT ((psa_key_usage_t)0x00000001)

/**
 * DOC: PSA_KEY_USAGE_SIGN_HASH
 * Permission to sign a message hash with the key.
 *
 * This flag allows the key to be used to sign a message hash as part of an asymmetric signature
 * operation, if otherwise permitted by the key’s type and policy. The flag must be present on
 * keys used when calling psa_sign_hash().
 *
 * This flag automatically sets PSA_KEY_USAGE_SIGN_MESSAGE: if an application sets the flag
 * PSA_KEY_USAGE_SIGN_HASH when creating a key, then the key always has the permissions conveyed by
 * PSA_KEY_USAGE_SIGN_MESSAGE, and the flag PSA_KEY_USAGE_SIGN_MESSAGE will also be present when the
 * application queries the usage flags of the key.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_SIGN_HASH ((psa_key_usage_t)0x00001000)

/**
 * DOC: PSA_KEY_USAGE_SIGN_MESSAGE
 * Permission to sign a message with the key.
 *
 * This flag allows the key to be used for a MAC calculation operation or for an asymmetric message
 * signature operation, if otherwise permitted by the key’s type and policy. The flag must be
 * present on keys used with the following APIs:
 *
 * - psa_mac_compute()
 * - psa_mac_sign_setup()
 * - psa_sign_message()
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_SIGN_MESSAGE ((psa_key_usage_t)0x00000400)

/**
 * DOC: PSA_KEY_USAGE_VERIFY_HASH
 * Permission to verify a message hash with the key.
 *
 * This flag allows the key to be used to verify a message hash as part of an asymmetric signature
 * verification operation, if otherwise permitted by the key’s type and policy. The flag must be
 * present on keys used when calling psa_verify_hash().
 *
 * This flag automatically sets PSA_KEY_USAGE_VERIFY_MESSAGE: if an application sets the flag
 * PSA_KEY_USAGE_VERIFY_HASH when creating a key, then the key always has the permissions conveyed
 * by PSA_KEY_USAGE_VERIFY_MESSAGE, and the flag PSA_KEY_USAGE_VERIFY_MESSAGE will also be present
 * when the application queries the usage flags of the key.
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_VERIFY_HASH ((psa_key_usage_t)0x00002000)

/**
 * DOC: PSA_KEY_USAGE_VERIFY_MESSAGE
 * Permission to verify a message signature with the key.
 *
 * This flag allows the key to be used for a MAC verification operation or for an asymmetric message
 * signature verification operation, if otherwise permitted by the key’s type and policy. The flag
 * must be present on keys used with the following APIs:
 *
 * - psa_mac_verify()
 * - psa_mac_verify_setup()
 * - psa_verify_message()
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_VERIFY_MESSAGE ((psa_key_usage_t)0x00000800)

#endif /* __PSA_CRYPTO_VALUES_H__ */
