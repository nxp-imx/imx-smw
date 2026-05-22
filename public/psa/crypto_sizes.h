/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_SIZES_H__
#define __PSA_CRYPTO_SIZES_H__

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7) / 8)

#define PSA_ROUND_UP_TO_MULTIPLE(block_size, length)                           \
	((((length) + (block_size) - (1)) / (block_size)) * (block_size))

#define PSA_MAX(a, b) ((a) < (b) ? (b) : (a))

/*
 * Define the maximum capabilities supported by the SMW's subsystems
 */
#define PSA_VENDOR_MAX_RSA_KEY_BITS   4096
#define PSA_VENDOR_MAX_ECC_CURVE_BITS 521

/*
 * This file contains the definitions of macros that are useful to compute
 * buffer sizes. The signatures and semantics of these macros are standardized,
 * but the definitions are not, because they depend on the available algorithms
 * and, in some cases, on permitted tolerances on buffer sizes.
 */

/*
 * Reference
 * Documentation:
 *   PSA Cryptography API v1.3.2
 * Link:
 *   https://arm-software.github.io/psa-api/crypto/1.3/
 */

/**
 * PSA_AEAD_ENCRYPT_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                  psa_aead_encrypt(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 * @plaintext_length: [in] Size of the plaintext in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed
 * that psa_aead_encrypt() will not fail due to an insufficient buffer size.
 * Depending on the algorithm, the actual size of the ciphertext might be
 * smaller.
 *
 * See also :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * The AEAD ciphertext size for the specified key type and algorithm. If the key
 * type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length)          \
	(PSA_ALG_IS_AEAD(alg) ?                                                \
		 ((plaintext_length) + PSA_ALG_AEAD_TAG_LENGTH(alg)) :         \
		 (0u))

/**
 * PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE() - The maximum size of the output of
 *                                      psa_aead_encrypt(), for any of the
 *                                      supported key types and AEAD algorithms.
 * @plaintext_length: [in] Size of the plaintext in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed
 * that psa_aead_encrypt() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_SIZE`.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length)                     \
	((plaintext_length) + PSA_AEAD_TAG_MAX_SIZE)

/**
 * PSA_AEAD_DECRYPT_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                  psa_aead_decrypt(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 * @ciphertext_length: [in] Size of the ciphertext in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed
 * that psa_aead_decrypt() will not fail due to an insufficient buffer size.
 * Depending on the algorithm, the actual size of the plaintext might be
 * smaller.
 *
 * See also :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * The AEAD plaintext size for the specified key type and algorithm. If the key
 * type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length)         \
	((PSA_ALG_IS_AEAD(alg) != 0 &&                                         \
	  (ciphertext_length) > PSA_ALG_AEAD_TAG_LENGTH(alg)) ?                \
		 (ciphertext_length) - (PSA_ALG_AEAD_TAG_LENGTH(alg)) :        \
		 (0u))

/**
 * PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE() - The maximum size of the output of
 *                                      psa_aead_decrypt(), for any of the
 *                                      supported key types and AEAD algorithms.
 * @ciphertext_length: [in] Size of the ciphertext in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed
 * that psa_aead_decrypt() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_SIZE`.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length) (ciphertext_length)

/**
 * PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE() - A sufficient output buffer size for
 *                                     psa_aead_update(), for any of the
 *                                     supported key types and AEAD algorithms.
 * @input_length: [in] Size of the input in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_aead_update() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_AEAD_UPDATE_OUTPUT_SIZE`.
 */
#define PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length)                          \
/* implementation-defined value */

/**
 * PSA_AEAD_UPDATE_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                 psa_aead_update(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 * @input_length: [in] Size of the input in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_aead_update() will not fail due to an insufficient buffer size.
 * The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output buffer size for the specified key type and algorithm. If
 * the key type or AEAD algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)               \
/* implementation-defined value */

/**
 * PSA_AEAD_FINISH_OUTPUT_SIZE() - A sufficient ciphertext buffer size for
 *                                 psa_aead_finish(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed
 * that psa_aead_finish() will not fail due to an insufficient ciphertext buffer
 * size. The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_AEAD_FINISH_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient ciphertext buffer size for the specified key type and algorithm.
 * If the key type or AEAD algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg)                             \
/* implementation-defined value */

/**
 * PSA_AEAD_FINISH_OUTPUT_MAX_SIZE - The maximum the ciphertext buffer size
 *                                   of psa_aead_finish(), for any of the
 *                                   supported key types and AEAD algorithms.
 *
 * .. warning::
 *    Not supported.
 *
 * See also :c:macro:`PSA_AEAD_FINISH_OUTPUT_SIZE`.
 */
#define PSA_AEAD_FINISH_OUTPUT_MAX_SIZE 0 /* implementation-defined value */

/**
 * PSA_AEAD_VERIFY_OUTPUT_SIZE() - A sufficient plaintext buffer size for
 *                                 psa_aead_verify(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed
 * that psa_aead_verify() will not fail due to an insufficient plaintext buffer
 * size. The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient plaintext buffer size for the specified key type and algorithm.
 * If the key type or AEAD algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg)                             \
	/* implementation-defined value */

/**
 * PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE - The maximum plaintext buffer size of
 *                                   psa_aead_verify(), for any of the supported
 *                                   key types and AEAD algorithms.
 *
 * .. warning::
 *    Not supported.
 *
 * See also :c:macro:`PSA_AEAD_VERIFY_OUTPUT_SIZE`.
 */
#define PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE 0 /* implementation-defined value */

/**
 * PSA_AEAD_NONCE_LENGTH() - The default nonce size for an AEAD algorithm, in
 *                           bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 *
 * This macro can be used to allocate a buffer of sufficient size to store the
 * nonce output from psa_aead_generate_nonce().
 *
 * See also :c:macro:`PSA_AEAD_NONCE_MAX_SIZE`.
 *
 * Return:
 * The default nonce size for the specified key type and algorithm. If the key
 * type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0.
 */
#define PSA_AEAD_NONCE_LENGTH(key_type, alg)                                   \
	(PSA_ALG_IS_AEAD(alg) &&                                               \
	 ((PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) == PSA_ALG_CCM) ||        \
	  (PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) == PSA_ALG_GCM) ||        \
	  (PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) ==                        \
	   PSA_ALG_CHACHA20_POLY1305))) ?                                      \
		(12u) :                                                        \
		(0u)

/**
 * PSA_AEAD_NONCE_MAX_SIZE - The maximum nonce size for all supported AEAD
 *                           algorithms, in bytes.
 *
 * See also :c:macro:`PSA_AEAD_NONCE_LENGTH`.
 */
#define PSA_AEAD_NONCE_MAX_SIZE (12u)

/**
 * PSA_AEAD_TAG_LENGTH() - The length of a tag for an AEAD algorithm, in bytes.
 * @key_type: [in] The type of the AEAD key.
 * @key_bits: [in] The size of the AEAD key in bits.
 * @alg: [in] An AEAD algorithm such that :c:macro:`PSA_ALG_IS_AEAD` is true.
 *
 * This is the size of the tag output from psa_aead_finish().
 *
 * If the size of the tag buffer is at least this large, it is guaranteed that
 * psa_aead_finish() will not fail due to an insufficient tag buffer size.
 *
 * See also :c:macro:`PSA_AEAD_TAG_MAX_SIZE`.
 *
 * Return:
 * The tag length for the specified algorithm and key. If the AEAD algorithm
 * does not have an identified tag that can be distinguished from the rest of
 * the ciphertext, return 0. If the AEAD algorithm is not recognized, return 0.
 */
#define PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg)                           \
	PSA_ALG_AEAD_TAG_LENGTH(alg)

/**
 * PSA_AEAD_TAG_MAX_SIZE - The maximum tag size for all supported AEAD
 *                         algorithms, in bytes.
 *
 * See also :c:macro:`PSA_AEAD_TAG_LENGTH`.
 */
#define PSA_AEAD_TAG_MAX_SIZE (16u)

/**
 * PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE() - Sufficient output buffer size for
 *                                        psa_asymmetric_decrypt().
 * @key_type: [in] An asymmetric key type, either a key pair or a public key.
 * @key_bits: [in] The size of the key in bits.
 * @alg: [in] The asymmetric encryption algorithm such that
 *            :c:macro:`PSA_ALG_IS_ASYMMETRIC_ENCRYPTION` is true.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_asymmetric_decrypt() will not fail due to an insufficient buffer
 * size. The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output buffer size for the specified asymmetric encryption
 * algorithm and key parameters. If algorithm or key is not recognizes,
 * return 0.
 */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)            \
	(PSA_KEY_TYPE_IS_RSA(key_type) ?                                       \
		 (((alg) == PSA_ALG_RSA_PKCS1V15_CRYPT) ?                      \
			  (PSA_BITS_TO_BYTES(key_bits) - 11) :                 \
		  PSA_ALG_IS_RSA_OAEP(alg) ?                                   \
			  (PSA_BITS_TO_BYTES(key_bits) -                       \
			   (2 *                                                \
			    PSA_HASH_LENGTH(PSA_ALG_RSA_OAEP_GET_HASH(alg))) - \
			   2) :                                                \
			  0) :                                                 \
		 0)

/**
 * PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE - A sufficient output buffer size for
 *                                          psa_asymmetric_decrypt(), for any
 *                                          supported asymmetric decryption.
 *
 * See also :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE`.
 */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE                                 \
	(PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))

/**
 * PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE() - Sufficient output buffer size for
 *                                        psa_asymmetric_encrypt().
 * @key_type: [in] An asymmetric key type, either a key pair or a public key.
 * @key_bits: [in] The size of the key in bits.
 * @alg: [in] The asymmetric encryption algorithm such that
 *            :c:macro:`PSA_ALG_IS_ASYMMETRIC_ENCRYPTION` is true.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_asymmetric_encrypt() will not fail due to an insufficient buffer
 * size. The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output buffer size for the specified asymmetric encryption
 * algorithm and key parameters. If algorithm or key is not recognizes,
 * return 0.
 */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)            \
	(PSA_KEY_TYPE_IS_RSA(key_type) ?                                       \
		 (((alg) == PSA_ALG_RSA_PKCS1V15_CRYPT) ||                     \
				  PSA_ALG_IS_RSA_OAEP(alg) ?                   \
			  PSA_BITS_TO_BYTES(key_bits) :                        \
			  0) :                                                 \
		 0)

/**
 * PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE - A sufficient output buffer size for
 *                                          psa_asymmetric_encrypt(), for any
 *                                          supported asymmetric encryption.
 *
 * See also :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE`.
 */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE                                 \
	(PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))

/**
 * PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE - The maximum size of a block cipher
 *                                   supported.
 *
 * See also :c:macro:`PSA_BLOCK_CIPHER_BLOCK_LENGTH`.
 */
#define PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE 16

/**
 * PSA_CIPHER_DECRYPT_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                    psa_cipher_decrypt(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] A cipher algorithm such that :c:macro:`PSA_ALG_IS_CIPHER` is true.
 * @input_length: [in] Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_decrypt() will not fail due to an insufficient buffer size.
 * Depending on the algorithm, the actual size of the output might be smaller.
 *
 * See also :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key
 * type or cipher algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length)            \
	(PSA_ALG_IS_CIPHER(alg) &&                                             \
			 ((key_type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==        \
				 PSA_KEY_TYPE_CATEGORY_SYMMETRIC ?             \
		 (input_length) :                                              \
		 0)

/**
 * PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE() - The maximum size of the output of
 *                                        psa_cipher_decrypt(), for any of the
 *                                        supported key types and cipher
 *                                        algorithms.
 * @input_length: [in] Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_decrypt() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_SIZE`.
 */
#define PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_length) (input_length)

size_t psa_cipher_encrypt_output_size(psa_key_type_t key_type,
				      psa_algorithm_t alg, size_t input_length);

/**
 * PSA_CIPHER_ENCRYPT_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                    psa_cipher_encrypt(), for any of the
 *                                    supported key types and cipher algorithms.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] A cipher algorithm such that :c:macro:`PSA_ALG_IS_CIPHER` is true.
 * @input_length: [in] Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_encrypt() will not fail due to an insufficient buffer size.
 * Depending on the algorithm, the actual size of the output might be smaller.
 *
 * See also :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the
 * key type or cipher algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_length)            \
	psa_cipher_encrypt_output_size(key_type, alg, input_length)

/**
 * PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE() - The maximum size of the output of
 *                                        psa_cipher_encrypt(), for any of the
 *                                        supported key types and cipher
 *                                        algorithms.
 * @input_length: [in] Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_encrypt() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_SIZE`.
 *
 */
#define PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length)                       \
	(PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE,             \
				  (input_length) + 1) +                        \
	 PSA_CIPHER_IV_MAX_SIZE)

/**
 * PSA_CIPHER_UPDATE_OUTPUT_SIZE() - A sufficient output buffer size for
 *                                   psa_cipher_update(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] A cipher algorithm such that :c:macro:`PSA_ALG_IS_CIPHER` is true.
 * @input_length: [in] Size of the input in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_update() will not fail due to an insufficient buffer size.
 * The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the
 * key type or cipher algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)             \
	/* implementation-defined value */

/**
 * PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE() - The maximum output buffer size for
 *                                       psa_cipher_update(), for any of the
 *                                       supported key types and cipher
 *                                       algorithms.
 * @input_length: [in] Size of the input in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_update() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_SIZE`.
 */
#define PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input_length)                        \
	/* implementation-defined value */

/**
 * PSA_CIPHER_FINISH_OUTPUT_SIZE() - A sufficient ciphertext buffer size for
 *                                   psa_cipher_finish(), in bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] A cipher algorithm such that :c:macro:`PSA_ALG_IS_CIPHER` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_cipher_finish() will not fail due to an insufficient buffer size.
 * The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key
 * type or cipher algorithm is not recognized, or the parameters are
 * incompatible, return 0.
 */
#define PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg)                           \
	/* implementation-defined value */

/**
 * PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE - The maximum output buffer size for
 *                                     psa_cipher_finish(), for any of the
 *                                     supported key types and cipher
 *                                     algorithms.
 *
 * .. warning::
 *    Not supported.
 *
 * See also :c:macro:`PSA_CIPHER_FINISH_OUTPUT_SIZE`.
 */
#define PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE 0 /* implementation-defined value */

size_t psa_cipher_iv_length(psa_key_type_t key_type, psa_algorithm_t alg);

/**
 * PSA_CIPHER_IV_LENGTH() - The default IV size for a cipher algorithm, in
 *                          bytes.
 * @key_type: [in] A symmetric key type that is compatible with algorithm @alg.
 * @alg: [in] A cipher algorithm such that :c:macro:`PSA_ALG_IS_CIPHER` is true.
 *
 * The IV that is generated as part of a call to psa_cipher_encrypt() is always
 * the default IV length for the algorithm.
 *
 * This macro can be used to allocate a buffer of sufficient size to store the
 * IV output from psa_cipher_generate_iv() when using a multi-part cipher
 * operation.
 *
 * See also :c:macro:`PSA_CIPHER_IV_MAX_SIZE`.
 *
 * Return:
 * The default IV size for the specified key type and algorithm. If the
 * algorithm does not use an IV, return 0. If the key type or cipher algorithm
 * is not recognized, or the parameters are incompatible, return 0.
 */
#define PSA_CIPHER_IV_LENGTH(key_type, alg) psa_cipher_iv_length(key_type, alg)

/**
 * PSA_CIPHER_IV_MAX_SIZE - The maximum IV size for all supported cipher
 *                          algorithms, in bytes.
 *
 * See also :c:macro:`PSA_CIPHER_IV_LENGTH`.
 */
#define PSA_CIPHER_IV_MAX_SIZE 16

#define PSA_VENDOR_RSA_MAX_KEY_BITS   4096
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 521

/* Maximum size in bytes of the ASN.1 encoding of an INTEGER with the specified
 * number of bits.
 *
 * This definition assumes that bits <= 2^19 - 9 so that the length field
 * is at most 3 bytes. The length of the encoding is the length of the
 * bit string padded to a whole number of bytes plus:
 * - 1 type byte;
 * - 1 to 3 length bytes;
 * - 0 to 1 bytes of leading 0 due to the sign bit.
 */
#define PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(bits) (PSA_BITS_TO_BYTES(bits) + 5)

/* Maximum size of the export encoding of an RSA public key.
 * Assumes that the public exponent is less than 2^32.
 *
 * RSAPublicKey  ::=  SEQUENCE  {
 *    modulus            INTEGER,    -- n
 *    publicExponent     INTEGER  }  -- e
 *
 * - 4 bytes of SEQUENCE overhead;
 * - n : INTEGER;
 * - 7 bytes for the public exponent.
 */
#define PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits)                       \
	(PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) + 11)

/* Maximum size of the export encoding of an RSA key pair.
 * Assumes that the public exponent is less than 2^32 and that the size
 * difference between the two primes is at most 1 bit.
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,  -- 0
 *     modulus           INTEGER,  -- N-bit
 *     publicExponent    INTEGER,  -- 32-bit
 *     privateExponent   INTEGER,  -- N-bit
 *     prime1            INTEGER,  -- N/2-bit
 *     prime2            INTEGER,  -- N/2-bit
 *     exponent1         INTEGER,  -- N/2-bit
 *     exponent2         INTEGER,  -- N/2-bit
 *     coefficient       INTEGER,  -- N/2-bit
 * }
 *
 * - 4 bytes of SEQUENCE overhead;
 * - 3 bytes of version;
 * - 7 half-size INTEGERs plus 2 full-size INTEGERs,
 *   overapproximated as 9 half-size INTEGERS;
 * - 7 bytes for the public exponent.
 */
#define PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits)                         \
	(9 * PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE((key_bits) / 2 + 1) + 14)

/* Maximum size of the export encoding of an ECC public key.
 *
 * The representation of an ECC public key is:
 *      - The byte 0x04;
 *      - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - `y_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - where m is the bit size associated with the curve.
 *
 * - 1 byte + 2 * point size.
 */
#define PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)                       \
	(2 * PSA_BITS_TO_BYTES(key_bits) + 1)

/* Maximum size of the export encoding of an ECC key pair.
 *
 * An ECC key pair is represented by the secret value.
 */
#define PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits)                         \
	(PSA_BITS_TO_BYTES(key_bits))

/**
 * PSA_EXPORT_KEY_OUTPUT_SIZE() - Sufficient output buffer size for
 *                                psa_export_key().
 * @key_type: [in] A supported key type.
 * @key_bits: [in] The size of the key in bits.
 *
 * The following code illustrates how to allocate enough memory to export a
 * key by querying the key type and size at runtime.
 *
 * .. code-block:: c
 *
 *    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *    psa_status_t status;
 *
 *    status = psa_get_key_attributes(key, &attributes);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 *    psa_key_type_t key_type = psa_get_key_type(&attributes);
 *    size_t key_bits = psa_get_key_bits(&attributes);
 *    size_t buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
 *
 *    psa_reset_key_attributes(&attributes);
 *
 *    uint8_t *buffer = malloc(buffer_size);
 *    if (buffer == NULL)
 *        handle_error(...);
 *
 *    size_t buffer_length;
 *    status = psa_export_key(key, buffer, buffer_size, &buffer_length);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 * See also :c:macro:`PSA_EXPORT_KEY_PAIR_MAX_SIZE`,
 * :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE`, and
 * :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE`.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that
 * guarantees that psa_export_key() or psa_export_public_key() will not fail
 * with PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are a valid combination
 * that is not supported by the implementation, this macro must return either a
 * sensible size or 0. If the parameters are not valid, the return value is
 * unspecified.
 */
#define PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits)                         \
	(PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ?                              \
		 PSA_BITS_TO_BYTES(key_bits) :                                 \
		 PSA_KEY_TYPE_IS_RSA_KEY_PAIR(key_type) ?                      \
		 PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits) :              \
		 PSA_KEY_TYPE_IS_RSA_PUBLIC_KEY(key_type) ?                    \
		 PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits) :            \
		 PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ?                      \
		 PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits) :              \
		 PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) ?                    \
		 PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) :            \
		 0)

/**
 * PSA_EXPORT_KEY_PAIR_MAX_SIZE - Sufficient buffer size for exporting any
 *                                asymmetric key pair.
 *
 * This value must be a sufficient buffer size when calling psa_export_key()
 * to export any asymmetric key pair that is supported by the implementation,
 * regardless of the exact key type and key size.
 *
 * See also PSA_EXPORT_KEY_OUTPUT_SIZE(),
 * :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE`, and
 * :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE`.
 */
#define PSA_EXPORT_KEY_PAIR_MAX_SIZE                                           \
	PSA_MAX(PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(                          \
			PSA_VENDOR_RSA_MAX_KEY_BITS),                          \
		PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(                          \
			PSA_VENDOR_ECC_MAX_CURVE_BITS))

/**
 * PSA_EXPORT_PUBLIC_KEY_MAX_SIZE - Sufficient buffer size for exporting any
 *                                  asymmetric public key.
 *
 * This value must be a sufficient buffer size when calling psa_export_key() or
 * psa_export_public_key() to export any asymmetric public key that is supported by the
 * implementation, regardless of the exact key type and key size.
 *
 * See also PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(), PSA_EXPORT_KEY_OUTPUT_SIZE(),
 * :c:macro:`PSA_EXPORT_KEY_PAIR_MAX_SIZE`, and
 * :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE`.
 */
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE                                         \
	PSA_MAX(PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(                        \
			PSA_VENDOR_RSA_MAX_KEY_BITS),                          \
		PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(                        \
			PSA_VENDOR_ECC_MAX_CURVE_BITS))

/**
 * PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE - Sufficient buffer size for exporting
 *                                      any asymmetric key pair or public key.
 *
 * This value must be a sufficient buffer size when calling psa_export_key() or
 * psa_export_public_key() to export any asymmetric key pair or public key that
 * is supported by the implementation, regardless of the exact key type and
 * key size.
 *
 * See also :c:macro:`PSA_EXPORT_KEY_PAIR_MAX_SIZE`,
 * :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE`, and PSA_EXPORT_KEY_OUTPUT_SIZE().
 */
#define PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE                                     \
	PSA_MAX(PSA_EXPORT_KEY_PAIR_MAX_SIZE, PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)

/**
 * PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE() - Sufficient output buffer size for
 *                                       psa_export_public_key().
 * @key_type: [in] A public key or key pair key type.
 * @key_bits: [in] The size of the key in bits.
 *
 * The following code illustrates how to allocate enough memory to export a
 * public key by querying the key type and size at runtime.
 *
 * .. code-block:: c
 *
 *    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *    psa_status_t status;
 *
 *    status = psa_get_key_attributes(key, &attributes);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 *    psa_key_type_t key_type = psa_get_key_type(&attributes);
 *    size_t key_bits = psa_get_key_bits(&attributes);
 *    size_t buffer_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits);
 *
 *    psa_reset_key_attributes(&attributes);
 *
 *    uint8_t *buffer = malloc(buffer_size);
 *    if (buffer == NULL)
 *        handle_error(...);
 *
 *    size_t buffer_length;
 *    status = psa_export_public_key(key, buffer, buffer_size, &buffer_length);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 * See also :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE` and
 * :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE`.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that
 * guarantees that psa_export_public_key() will not fail with
 * PSA_ERROR_BUFFER_TOO_SMALL. Otherwises return 0.
 */
#define PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits)                  \
	(PSA_KEY_TYPE_IS_RSA(key_type) ?                                       \
		 PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits) :            \
		 PSA_KEY_TYPE_IS_ECC(key_type) ?                               \
		 PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) :            \
		 0)

size_t psa_hash_block_length(psa_algorithm_t alg);

/**
 * PSA_HASH_BLOCK_LENGTH() - The input block size of a hash algorithm, in bytes.
 * @alg: [in] A hash algorithm such that :c:macro:`PSA_ALG_IS_HASH` is true.
 *
 * Hash algorithms process their input data in blocks. Hash operations will
 * retain any partial blocks until they have enough input to fill the block or
 * until the operation is finished.
 *
 * This affects the output from psa_hash_suspend().
 *
 * Return:
 * The block size in bytes for the specified hash algorithm. If the hash
 * algorithm is not recognized, return 0.
 */
#define PSA_HASH_BLOCK_LENGTH(alg)                                             \
	(alg == PSA_ALG_MD5	     ? 64u :                                   \
	 alg == PSA_ALG_RIPEMD160    ? 64u :                                   \
	 alg == PSA_ALG_SHA_1	     ? 64u :                                   \
	 alg == PSA_ALG_SHA_224	     ? 64u :                                   \
	 alg == PSA_ALG_SHA_256	     ? 64u :                                   \
	 alg == PSA_ALG_SHA_384	     ? 128u :                                  \
	 alg == PSA_ALG_SHA_512	     ? 128u :                                  \
	 alg == PSA_ALG_SHA3_224     ? 144u :                                  \
	 alg == PSA_ALG_SHA3_256     ? 136u :                                  \
	 alg == PSA_ALG_SHA3_384     ? 104u :                                  \
	 alg == PSA_ALG_SHA3_512     ? 72u :                                   \
	 alg == PSA_ALG_SM3	     ? 64u :                                   \
	 alg == PSA_ALG_SHAKE256_512 ? 136u :                                  \
				       0u)

size_t psa_hash_length(psa_algorithm_t alg);

/**
 * PSA_HASH_LENGTH() - The size of the output of psa_hash_compute() and
 *                     psa_hash_finish(), in bytes.
 * @alg: [in] A hash algorithm such that :c:macro:`PSA_ALG_IS_HASH` is true, or
 *            an HMAC algorithm such that :c:macro:`PSA_ALG_IS_HMAC` is true.
 *
 * This is also the hash length that psa_hash_compare() and psa_hash_verify()
 * expect.
 *
 * See also :c:macro:`PSA_HASH_MAX_SIZE`.
 *
 * Return:
 * The hash length for the specified hash algorithm. If the hash algorithm is
 * not recognized, return 0.
 */
#define PSA_HASH_LENGTH(alg)                                                   \
	(alg == PSA_ALG_MD5	     ? 16u :                                   \
	 alg == PSA_ALG_SHA_1	     ? 20u :                                   \
	 alg == PSA_ALG_SHA_224	     ? 28u :                                   \
	 alg == PSA_ALG_SHA_256	     ? 32u :                                   \
	 alg == PSA_ALG_SHA_384	     ? 48u :                                   \
	 alg == PSA_ALG_SHA_512	     ? 64u :                                   \
	 alg == PSA_ALG_SHA3_224     ? 28u :                                   \
	 alg == PSA_ALG_SHA3_256     ? 32u :                                   \
	 alg == PSA_ALG_SHA3_384     ? 48u :                                   \
	 alg == PSA_ALG_SHA3_512     ? 64u :                                   \
	 alg == PSA_ALG_SM3	     ? 32u :                                   \
	 alg == PSA_ALG_SHAKE256_512 ? 64u :                                   \
				       0u)

/**
 * PSA_HASH_MAX_SIZE -  Maximum size of a hash.
 *
 * This macro must expand to a compile-time constant integer.
 *
 * See also :c:macro:`PSA_HASH_LENGTH`.
 */
#define PSA_HASH_MAX_SIZE 64

/**
 * PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH - The size of the algorithm field
 *                                           that is part of the output of
 *                                           psa_hash_suspend(), in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * Applications can use this value to unpack the hash suspend state that is
 * output by psa_hash_suspend().
 */
#define PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH ((size_t)4)

/**
 * PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH() - The size of the hash-state field
 *                                              that is part of the
 *                                              output of psa_hash_suspend(), in
 *                                              bytes.
 * @alg: [in] A hash algorithm such that :c:macro:`PSA_ALG_IS_HASH` is true.
 *
 * Applications can use this value to unpack the hash suspend state that is
 * output by psa_hash_suspend().
 *
 * Return:
 * The size, in bytes, of the hash-state field of the hash suspend state for the
 * specified hash algorithm. If the hash algorithm is not recognized, return 0.
 */
#define PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg)                                           \
	({                                                                                      \
		typeof(alg) _alg = (alg);                                                       \
		((_alg == PSA_ALG_MD2) ?                                                        \
			 64 :                                                                   \
			 _alg == PSA_ALG_MD4 || _alg == PSA_ALG_MD5 ?                           \
			 16 :                                                                   \
			 _alg == PSA_ALG_RIPEMD160 || _alg == PSA_ALG_SHA_1 ?                   \
			 20 :                                                                   \
			 _alg == PSA_ALG_SHA_224 || _alg == PSA_ALG_SHA_256 ?                   \
			 32 :                                                                   \
			 _alg == PSA_ALG_SHA_512 || _alg == PSA_ALG_SHA_384 ||                  \
								 _alg == PSA_ALG_SHA_512_224 || \
								 _alg == PSA_ALG_SHA_512_256 ?  \
			 64 :                                                                   \
			 0);                                                                    \
	})

/**
 * PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH() - The size of the input-length
 *                                                field that is part of
 *                                                the output of
 *                                                psa_hash_suspend(), in bytes.
 * @alg: [in] A hash algorithm such that :c:macro:`PSA_ALG_IS_HASH` is true.
 *
 * Applications can use this value to unpack the hash suspend state that is
 * output by psa_hash_suspend().
 *
 * Return:
 * The size, in bytes, of the input-length field of the hash suspend state for
 * the specified hash algorithm. If the hash algorithm is not recognized,
 * return 0.
 */
#define PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg)                         \
	({                                                                      \
		typeof(alg) _alg = (alg);                                       \
		(_alg == PSA_ALG_MD2 ?                                          \
			 1 :                                                    \
			 _alg == PSA_ALG_MD4 || _alg == PSA_ALG_MD5 ||          \
					 _alg == PSA_ALG_RIPEMD160 ||           \
					 _alg == PSA_ALG_SHA_1 ||               \
					 _alg == PSA_ALG_SHA_224 ||             \
					 _alg == PSA_ALG_SHA_256 ?              \
			 8 :                                                    \
			 _alg == PSA_ALG_SHA_512 || _alg == PSA_ALG_SHA_384 ||  \
						 _alg == PSA_ALG_SHA_512_224 || \
						 _alg == PSA_ALG_SHA_512_256 ?  \
			 16 :                                                   \
			 0);                                                    \
	})

/**
 * PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE - A sufficient hash suspend state buffer
 *                                    size for psa_hash_suspend(), for any
 *                                    supported hash algorithms.
 *
 * .. warning::
 *    Not supported.
 *
 * See also :c:macro:`PSA_HASH_SUSPEND_OUTPUT_SIZE`.
 */
#define PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE 0

/**
 * PSA_HASH_SUSPEND_OUTPUT_SIZE() - A sufficient hash suspend state buffer size
 *                                  for psa_hash_suspend().
 * @alg: [in] A hash algorithm such that :c:macro:`PSA_ALG_IS_HASH` is true.
 *
 * If the size of the hash state buffer is at least this large, it is guaranteed
 * that psa_hash_suspend() will not fail due to an insufficient buffer size.
 * The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * A sufficient output size for the algorithm. If the hash algorithm is not
 * recognized, or is not supported by psa_hash_suspend(), return 0.
 */
#define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg)                                      \
	({                                                                     \
		typeof(alg) _algo = (alg);                                     \
		(PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH +                     \
		 PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(_algo) +           \
		 PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(_algo) +             \
		 PSA_HASH_BLOCK_LENGTH(_algo) - 1);                            \
	})

/**
 * PSA_MAC_TRUNCATED_LENGTH() - Size of the truncated MAC algorithm
 *                              in bytes.
 * @alg: [in] A MAC algorithm such that :c:macro:`PSA_ALG_IS_MAC_TRUNCATED` is
 *            true.
 *
 * Return:
 * The MAC truncated length for the specified algorithm.
 * 0 if the algorithm is not a MAC or a truncated MAC algorithm.
 */
#define PSA_MAC_TRUNCATED_LENGTH(alg)                                          \
	({                                                                     \
		typeof(alg) _algo = (alg);                                     \
		PSA_ALG_IS_MAC_TRUNCATED(_algo) ?                              \
			(_algo & PSA_ALG_MAC_TRUNCATION_MASK) >>               \
				PSA_MAC_TRUNCATION_OFFSET :                    \
			0;                                                     \
	})

/**
 * PSA_HMAC_LENGTH() - Size of the HMAC output length in bytes.
 * @alg: [in] A MAC algorithm such that :c:macro:`PSA_ALG_IS_HMAC` is true.
 *
 * Return:
 * The MAC length for the specified algorithm.
 * 0 if the MAC algorithm is not HMAC.
 */
#define PSA_HMAC_LENGTH(alg)                                                   \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		PSA_ALG_IS_HMAC(_alg) ?                                        \
			(PSA_MAC_TRUNCATED_LENGTH(_alg) ?                      \
				 PSA_MAC_TRUNCATED_LENGTH(_alg) :              \
				 PSA_MAC_MAX_SIZE) :                           \
			0;                                                     \
	})

/*
 * PSA_BLOCK_CIPHER_MAC_LENGTH() - Size of the block cipher MAC output length
 *                                 in bytes.
 * @alg: [in] A MAC algorithm such that :c:macro:`PSA_ALG_IS_BLOCK_CIPHER_MAC`
 *            is true.
 *
 * Return:
 * The MAC length for the specified algorithm.
 * 0 if the MAC algorithm is not a block cipher MAC.
 */
#define PSA_BLOCK_CIPHER_MAC_LENGTH(alg)                                       \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		PSA_ALG_IS_BLOCK_CIPHER_MAC(_alg) ?                            \
			(PSA_MAC_TRUNCATED_LENGTH(_alg) ?                      \
				 PSA_MAC_TRUNCATED_LENGTH(_alg) :              \
				 PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE) :            \
			0;                                                     \
	})

/**
 * PSA_MAC_LENGTH() - The size of the output of psa_mac_compute() and
 *                    psa_mac_sign_finish(), in bytes.
 * @key_type: [in] The type of the MAC key.
 * @key_bits: [in] The size of the MAC key in bits.
 * @alg: [in] A MAC algorithm such that :c:macro:`PSA_ALG_IS_MAC` is true.
 *
 * This is also the MAC length that psa_mac_verify() and
 * psa_mac_verify_finish() expect.
 *
 * See also :c:macro:`PSA_MAC_MAX_SIZE`.
 *
 * Return:
 * The MAC length for the specified algorithm with the specified key parameters.
 * 0 if the MAC algorithm is not recognized.
 */
#define PSA_MAC_LENGTH(key_type, key_bits, alg)                                \
	(PSA_ALG_IS_HMAC(alg) ? PSA_HMAC_LENGTH(alg) :                         \
				PSA_BLOCK_CIPHER_MAC_LENGTH(alg))

/**
 * PSA_MAC_MAX_SIZE - Maximum size of a MAC.
 *
 * This macro must expand to a compile-time constant integer.
 * The maximum MAC size is the maximum size supported by HMAC and by CMAC.
 *
 * See also :c:macro:`PSA_MAC_LENGTH`.
 */
#define PSA_MAC_MAX_SIZE                                                       \
	PSA_MAX(PSA_HASH_MAX_SIZE, PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)

/**
 * PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE - Maximum size of the output from
 *                                         psa_raw_key_agreement().
 *
 * .. warning::
 *    Not supported.
 *
 * This macro must expand to a compile-time constant integer.
 *
 * See also :c:macro:`PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE`.
 */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE                                  \
	0 /* implementation-defined value */

/**
 * PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() - Sufficient output buffer size for
 *                                       psa_raw_key_agreement().
 * @key_type: [in] A supported key type.
 * @key_bits: [in] The size of the key in bits.
 *
 * .. warning::
 *    Not supported.
 *
 * This macro returns a compile-time constant if its arguments are
 * compile-time constants.
 *
 * See also :c:macro:`PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE`.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes
 * that guarantees that psa_raw_key_agreement() will not fail with
 * PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are not valid, the return value
 * is unspecified.
 */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits)                  \
	/* implementation-defined value */

/**
 * PSA_ECC_SIGNATURE_SIZE - Size of an elliptic curve signature.
 *
 * @key_bits: [in] The size of the key in bits.
 */
#define PSA_ECC_SIGNATURE_SIZE(key_bits) (PSA_BITS_TO_BYTES(key_bits) * 2)

#define PSA_ECC_SIGNATURE_MAX_SIZE                                             \
	PSA_ECC_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#define PSA_RSA_SIGNATURE_MAX_SIZE                                             \
	PSA_BITS_TO_BYTES(PSA_VENDOR_MAX_RSA_KEY_BITS)

/**
 * PSA_SIGNATURE_MAX_SIZE - Maximum size of an asymmetric signature.
 *
 * This macro must expand to a compile-time constant integer.
 *
 * Returns a ufficient signature buffer size for psa_sign_message() and
 * psa_sign_hash(), for any of the supported key types and asymmetric signature
 * algorithms.
 *
 * See also :c:macro:`PSA_SIGN_OUTPUT_SIZE`
 */
#define PSA_SIGNATURE_MAX_SIZE                                                 \
	PSA_MAX(PSA_ECC_SIGNATURE_MAX_SIZE, PSA_RSA_SIGNATURE_MAX_SIZE)

/**
 * PSA_SIGN_OUTPUT_SIZE() - Sufficient signature buffer size for
 *                          psa_sign_message() and psa_sign_hash().
 * @key_type: [in] An asymmetric key type. This can be a key pair type or a
 *                 public key type.
 * @key_bits: [in] The size of the key in bits.
 * @alg: [in] The signature algorithm.
 *
 * If the size of the signature buffer is at least this large, it is guaranteed
 * that psa_sign_message() and psa_sign_hash() will not fail due to an
 * insufficient buffer size. The actual size of the output might be smaller in
 * any given call.
 *
 * See also :c:macro:`PSA_SIGNATURE_MAX_SIZE`.
 *
 * Return:
 * A sufficient signature buffer size for the specified asymmetric signature
 * algorithm and key parameters. 0 if asymmetric signature algorithm and key
 * parameters are not recognized.
 */
#define PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)                          \
	(PSA_KEY_TYPE_IS_RSA(key_type) ?                                       \
		 ((void)alg, PSA_BITS_TO_BYTES(key_bits)) :                    \
		 PSA_KEY_TYPE_IS_ECC(key_type) ?                               \
		 PSA_ECC_SIGNATURE_SIZE(key_bits) :                            \
		 ((void)alg, 0))

/**
 * PSA_TLS12_ECJPAKE_TO_PMS_OUTPUT_SIZE - The size of the output from the
 *                                        TLS 1.2 ECJPAKE-to-PMS key-derivation
 *                                        algorithm, in bytes.
 *
 * This value can be used when extracting the result of a key-derivation
 * operation that was set up with the PSA_ALG_TLS12_ECJPAKE_TO_PMS algorithm.
 */
#define PSA_TLS12_ECJPAKE_TO_PMS_OUTPUT_SIZE 32

/**
 * PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE - Maximum supported length of the PSK for
 *                                    the TLS-1.2 PSK-to-MS key derivation.
 *
 * .. warning::
 *    Not supported.
 *
 * Quoting Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
 * [:rfc:`4279`] §5.3\:
 *
 *  TLS implementations supporting these cipher suites MUST support arbitrary
 *  PSK identities up to 128 octets in length, and arbitrary PSKs up to 64
 *  octets in length. Supporting longer identities and keys is RECOMMENDED.
 */
#define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE 0 /* implementation-defined value */

/**
 * PSA_PAKE_OUTPUT_SIZE - Sufficient output buffer size for psa_pake_output(),
 *                        in bytes.
 * @alg: [in] A PAKE algorithm such that :c:macro:`PSA_ALG_IS_PAKE` is true.
 * @primitive: [in] A primitive of &typedef psa_pake_primitive_t that is
 *                  compatible with algorithm @alg.
 * @output_step: [in] A value of &typedef psa_pake_step_t that is valid for the
 *                    algorithm @alg.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_pake_output() will not fail due to an insufficient buffer size.
 * The actual size of the output might be smaller in any given call.
 *
 * See also :c:macro:`PSA_PAKE_OUTPUT_MAX_SIZE`
 *
 * Returns:
 * A sufficient output buffer size for the specified PAKE algorithm, primitive,
 * and output step. If algorithm, primitive, and output step is not recognized,
 * return 0.
 */
#define PSA_PAKE_OUTPUT_SIZE(alg, primitive, output_step)                      \
	/* implementation-defined value */

/**
 * PSA_PAKE_OUTPUT_MAX_SIZE - The maximum output buffer size for
 *                            psa_pake_output() for any of the supported PAKE
 *                            algorithms, primitives and output steps.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_pake_output() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_PAKE_OUTPUT_SIZE`.
 */
#define PSA_PAKE_OUTPUT_MAX_SIZE 0 /* implementation-defined value */

/**
 * PSA_PAKE_INPUT_SIZE - Sufficient buffer size for inputs to psa_pake_input().
 * @alg: [in] A PAKE algorithm such that :c:macro:`PSA_ALG_IS_PAKE` is true.
 * @primitive: [in] A primitive of &typedef psa_pake_primitive_t that is
 *                  compatible with algorithm @alg.
 * @input_step: [in] A value of &typedef psa_pake_step_t that is valid for the
 *                   algorithm @alg.
 *
 * .. warning::
 *    Not supported.
 *
 * The value returned by this macro is guaranteed to be large enough for any
 * valid input to psa_pake_input() in an operation with the specified
 * parameters.
 *
 * This macro can be useful when transferring inputs from the peer into the
 * PAKE operation.
 *
 * See also :c:macro:`PSA_PAKE_INPUT_MAX_SIZE`
 *
 * Returns:
 * A sufficient buffer size for the specified PAKE algorithm, primitive, and
 * input step. If algorithm, primitive, and output step is not recognized,
 * return 0.
 */
#define PSA_PAKE_INPUT_SIZE(alg, primitive, input_step)                        \
	/* implementation-defined value */

/**
 * PSA_PAKE_INPUT_MAX_SIZE - The maximum buffer size for inputs to
 *                           psa_pake_input() for any of the supported PAKE
 *                           algorithms, primitives and input steps.
 *
 * .. warning::
 *    Not supported.
 *
 * This macro can be useful when transferring inputs from the peer into the
 * PAKE operation.
 *
 * See also :c:macro:`PSA_PAKE_INPUT_SIZE`.
 */
#define PSA_PAKE_INPUT_MAX_SIZE 0 /* implementation-defined value */

/**
 * PSA_ENCAPSULATE_CIPHERTEXT_SIZE - Sufficient ciphertext buffer size for
 *                                   psa_encapsulate(), in bytes.
 * @key_type: [in] A key type that is compatible with algorithm @alg.
 * @key_bits: [in] The size of the key in bits.
 * @alg: [in] A key-encapsulation algorithm such that
 *            :c:macro:`PSA_ALG_IS_KEY_ENCAPSULATION` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed
 * that psa_encapsulate() will not fail due to an insufficient buffer size. The
 * actual size of the ciphertext might be smaller in any given call.
 *
 * See also :c:macro:`PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE`.
 *
 * Return:
 * A sufficient ciphertext buffer size for the specified algorithm, key type,
 * and size. If algorithm, key type and size is not recognize, return 0.
 */
#define PSA_ENCAPSULATE_CIPHERTEXT_SIZE(key_type, key_bits, alg)               \
	/* implementation-defined value */

/**
 * PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE - The maximum ciphertext buffer size for
 *                                       psa_encapsulate(), for any of the
 *                                       supported key types and key
 *                                       encapsulation algorithms.
 *
 * .. warning::
 *    Not supported.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed
 * that psa_encapsulate() will not fail due to an insufficient buffer size.
 *
 * See also :c:macro:`PSA_ENCAPSULATE_CIPHERTEXT_SIZE`.
 */
#define PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE 0 /* implementation-defined value */

#endif /* __PSA_CRYPTO_SIZES_H__ */
