/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
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

/**
 * DOC:
 * This file contains the definitions of macros that are useful to compute buffer sizes. The
 * signatures and semantics of these macros are standardized, but the definitions are not, because
 * they depend on the available algorithms and, in some cases, on permitted tolerances on buffer
 * sizes.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.1.0
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/b
 */

/**
 * PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_aead_decrypt(), for
 * any of the supported key types and AEAD algorithms.
 * @ciphertext_length: Size of the ciphertext in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed that
 * psa_aead_decrypt() will not fail due to an insufficient buffer size.
 *
 * See also PSA_AEAD_DECRYPT_OUTPUT_SIZE().
 */
#define PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length)                    \
/* implementation-defined value */

/**
 * PSA_AEAD_DECRYPT_OUTPUT_SIZE() - The maximum size of the output of psa_aead_decrypt(), in
 * bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 * @ciphertext_length: Size of the ciphertext in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed that
 * psa_aead_decrypt() will not fail due to an insufficient buffer size. Depending on the algorithm,
 * the actual size of the plaintext might be smaller.
 *
 * See also PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE().
 *
 * Return:
 * The AEAD plaintext size for the specified key type and algorithm. If the key type or AEAD
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and AEAD algorithm that it recognizes, but does
 * not support.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length)         \
/* implementation-defined value */

/**
 * PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_aead_encrypt(), for
 * any of the supported key types and AEAD algorithms.
 * @plaintext_length: Size of the plaintext in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * psa_aead_encrypt() will not fail due to an insufficient buffer size.
 *
 * See also PSA_AEAD_ENCRYPT_OUTPUT_SIZE().
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length)                     \
/* implementation-defined value */

/**
 * PSA_AEAD_ENCRYPT_OUTPUT_SIZE() - The maximum size of the output of psa_aead_encrypt(), in bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 * @plaintext_length: Size of the plaintext in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * psa_aead_encrypt() will not fail due to an insufficient buffer size. Depending on the algorithm,
 * the actual size of the ciphertext might be smaller.
 *
 * See also PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE().
 *
 * Return:
 * The AEAD ciphertext size for the specified key type and algorithm. If the key type or AEAD
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and AEAD algorithm that it recognizes, but does
 * not support.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length)          \
/* implementation-defined value */

/**
 * DOC: PSA_AEAD_FINISH_OUTPUT_MAX_SIZE
 * A sufficient ciphertext buffer size for psa_aead_finish(), for any of the supported key types
 * and AEAD algorithms.
 *
 * **Warning: Not supported**
 *
 * See also PSA_AEAD_FINISH_OUTPUT_SIZE().
 */
#define PSA_AEAD_FINISH_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * PSA_AEAD_FINISH_OUTPUT_SIZE() - A sufficient ciphertext buffer size for psa_aead_finish().
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * psa_aead_finish() will not fail due to an insufficient ciphertext buffer size. The actual size
 * of the output might be smaller in any given call.
 *
 * See also PSA_AEAD_FINISH_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient ciphertext buffer size for the specified key type and algorithm. If the key type or
 * AEAD algorithm is not recognized, or the parameters are incompatible, return 0. An
 * implementation can return either 0 or a correct size for a key type and AEAD algorithm that it
 * recognizes, but does not support.
 */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg)                             \
/* implementation-defined value */

/**
 * PSA_AEAD_NONCE_LENGTH() - The default nonce size for an AEAD algorithm, in bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * This macro can be used to allocate a buffer of sufficient size to store the nonce output from
 * psa_aead_generate_nonce().
 *
 * See also PSA_AEAD_NONCE_MAX_SIZE.
 *
 * Return:
 * The default nonce size for the specified key type and algorithm. If the key type or AEAD
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and AEAD algorithm that it recognizes, but does
 * not support.
 */
#define PSA_AEAD_NONCE_LENGTH(key_type, alg) /* implementation-defined value */

/**
 * DOC: PSA_AEAD_NONCE_MAX_SIZE
 * The maximum nonce size for all supported AEAD algorithms, in bytes.
 *
 * **Warning: Not supported**
 *
 * See also PSA_AEAD_NONCE_LENGTH().
 */
#define PSA_AEAD_NONCE_MAX_SIZE /* implementation-defined value */

/**
 * PSA_AEAD_TAG_LENGTH() - The length of a tag for an AEAD algorithm, in bytes.
 * @key_type: The type of the AEAD key.
 * @key_bits: The size of the AEAD key in bits.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * This macro can be used to allocate a buffer of sufficient size to store the tag output from
 * psa_aead_finish().
 *
 * See also PSA_AEAD_TAG_MAX_SIZE.
 *
 * Return:
 * The tag length for the specified algorithm and key. If the AEAD algorithm does not have an
 * identified tag that can be distinguished from the rest of the ciphertext, return 0. If the AEAD
 * algorithm is not recognized, return 0. An implementation can return either 0 or a correct size
 * for an AEAD algorithm that it recognizes, but does not support.
 */
#define PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg)                           \
/* implementation-defined value */

/**
 * DOC: PSA_AEAD_TAG_MAX_SIZE
 * The maximum tag size for all supported AEAD algorithms, in bytes.
 *
 * **Warning: Not supported**
 *
 * See also PSA_AEAD_TAG_LENGTH().
 */
#define PSA_AEAD_TAG_MAX_SIZE /* implementation-defined value */

/**
 * PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_aead_update(), for
 * any of the supported key types and AEAD algorithms.
 * @input_length: Size of the input in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the output buffer is at least this large, it is guaranteed that psa_aead_update()
 * will not fail due to an insufficient buffer size.
 *
 * See also PSA_AEAD_UPDATE_OUTPUT_SIZE().
 */
#define PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length)                          \
/* implementation-defined value */

/**
 * PSA_AEAD_UPDATE_OUTPUT_SIZE() - A sufficient output buffer size for psa_aead_update().
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 * @input_length: Size of the input in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the output buffer is at least this large, it is guaranteed that psa_aead_update()
 * will not fail due to an insufficient buffer size. The actual size of the output might be smaller
 * in any given call.
 *
 * See also PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output buffer size for the specified key type and algorithm. If the key type or
 * AEAD algorithm is not recognized, or the parameters are incompatible, return 0. An
 * implementation can return either 0 or a correct size for a key type and AEAD algorithm that it
 * recognizes, but does not support.
 */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)               \
/* implementation-defined value */

/**
 * DOC: PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE
 * A sufficient plaintext buffer size for psa_aead_verify(), for any of the supported key types and
 * AEAD algorithms.
 *
 * **Warning: Not supported**
 *
 * See also PSA_AEAD_VERIFY_OUTPUT_SIZE().
 */
#define PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * PSA_AEAD_VERIFY_OUTPUT_SIZE() - A sufficient plaintext buffer size for psa_aead_verify().
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: An AEAD algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed that
 * psa_aead_verify() will not fail due to an insufficient plaintext buffer size. The actual size of
 * the output might be smaller in any given call.
 *
 * See also PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient plaintext buffer size for the specified key type and algorithm. If the key type or
 * AEAD algorithm is not recognized, or the parameters are incompatible, return 0. An
 * implementation can return either 0 or a correct size for a key type and AEAD algorithm that it
 * recognizes, but does not support.
 */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg)                             \
	/* implementation-defined value */

/**
 * DOC: PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE
 * A sufficient output buffer size for psa_asymmetric_decrypt(), for any supported asymmetric
 * decryption.
 *
 * **Warning: Not supported**
 *
 * See also PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE().
 */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE                                 \
/* implementation-defined value */

/**
 * PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE() - Sufficient output buffer size for
 * psa_asymmetric_decrypt().
 * @key_type: An asymmetric key type, either a key pair or a public key.
 * @key_bits: The size of the key in bits.
 * @alg: The asymmetric encryption algorithm.
 *
 * **Warning: Not supported**
 *
 * This macro returns a sufficient buffer size for a plaintext produced using a key of the specified
 * type and size, with the specified algorithm. Note that the actual size of the plaintext might be
 * smaller, depending on the algorithm.
 *
 * **Warning**:
 *	This function might evaluate its arguments multiple times or zero times. Providing arguments
 *	that have side effects will result in implementation-specific behavior, and is non-portable.
 *
 * See also PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_asymmetric_decrypt() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are a
 * valid combination that is not supported by the implementation, this macro must return either a
 * sensible size or 0. If the parameters are not valid, the return value is unspecified.
 *
 */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)            \
/* implementation-defined value */

/**
 * DOC: PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE
 * A sufficient output buffer size for psa_asymmetric_encrypt(), for any supported asymmetric
 * encryption.
 *
 * **Warning: Not supported**
 *
 * See also PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE().
 */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE                                 \
/* implementation-defined value */

/**
 * PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE() - Sufficient output buffer size for
 * psa_asymmetric_encrypt().
 * @key_type: An asymmetric key type, either a key pair or a public key.
 * @key_bits: The size of the key in bits.
 * @alg: The asymmetric encryption algorithm.
 *
 * **Warning: Not supported**
 *
 * This macro returns a sufficient buffer size for a ciphertext produced using a key of the
 * specified type and size, with the specified algorithm. Note that the actual size of the
 * ciphertext might be smaller, depending on the algorithm.
 *
 * **Warning**:
 *	This function might evaluate its arguments multiple times or zero times. Providing arguments
 *	that have side effects will result in implementation-specific behavior, and is non-portable.
 *
 * See also PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_asymmetric_encrypt() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are a
 * valid combination that is not supported by the implementation, this macro must return either a
 * sensible size or 0. If the parameters are not valid, the return value is unspecified.
 *
 */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)            \
	/* implementation-defined value */

/**
 * DOC: PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE
 * The maximum size of a block cipher supported by the implementation.
 *
 * See also PSA_BLOCK_CIPHER_BLOCK_LENGTH().
 */
#define PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE 16

/**
 * PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_cipher_decrypt(),
 * for any of the supported key types and cipher algorithms.
 * @input_length: Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_decrypt() will not fail due to an insufficient buffer size.
 *
 * See also PSA_CIPHER_DECRYPT_OUTPUT_SIZE().
 */
#define PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_length) (input_length)

/**
 * PSA_CIPHER_DECRYPT_OUTPUT_SIZE() - The maximum size of the output of psa_cipher_decrypt(), in
 * bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: A cipher algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is true).
 * @input_length: Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_decrypt() will not fail due to an insufficient buffer size. Depending on the
 * algorithm, the actual size of the output might be smaller.
 *
 * See also PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key type or cipher
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and cipher algorithm that it recognizes, but
 * does not support.
 */
#define PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length)            \
	(PSA_ALG_IS_CIPHER(alg) &&                                             \
			 ((key_type) & (PSA_KEY_TYPE_CATEGORY_MASK)) ==        \
				 PSA_KEY_TYPE_CATEGORY_SYMMETRIC ?             \
		 (input_length) :                                              \
		 0)

/**
 * PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_cipher_encrypt(),
 * for any of the supported key types and cipher algorithms.
 * @input_length: Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_encrypt() will not fail due to an insufficient buffer size.
 *
 * See also PSA_CIPHER_ENCRYPT_OUTPUT_SIZE().
 *
 */
#define PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length)                       \
	(PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE,             \
				  (input_length) + 1) +                        \
	 PSA_CIPHER_IV_MAX_SIZE)

size_t psa_cipher_encrypt_output_size(psa_key_type_t key_type,
				      psa_algorithm_t alg, size_t input_length);

/**
 * PSA_CIPHER_ENCRYPT_OUTPUT_SIZE() - The maximum size of the output of psa_cipher_encrypt(), in
 * bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: A cipher algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is true).
 * @input_length: Size of the input in bytes.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_encrypt() will not fail due to an insufficient buffer size. Depending on the
 * algorithm, the actual size of the output might be smaller.
 *
 * See also PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key type or cipher
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and cipher algorithm that it recognizes, but
 * does not support.
 */
#define PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_length)            \
	psa_cipher_encrypt_output_size(key_type, alg, input_length)

/**
 * DOC: PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE
 * A sufficient ciphertext buffer size for psa_cipher_finish(), for any of the supported key types
 * and cipher algorithms.
 *
 * **Warning: Not supported**
 *
 * See also PSA_CIPHER_FINISH_OUTPUT_SIZE().
 */
#define PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * PSA_CIPHER_FINISH_OUTPUT_SIZE() - A sufficient ciphertext buffer size for psa_cipher_finish().
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: A cipher algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is true).
 *
 * **Warning: Not supported**
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * psa_cipher_finish() will not fail due to an insufficient ciphertext buffer size. The actual size
 * of the output might be smaller in any given call.
 *
 * See also PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key type or cipher
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and cipher algorithm that it recognizes, but
 * does not support.
 */
#define PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg)                           \
	/* implementation-defined value */

size_t psa_cipher_iv_length(psa_key_type_t key_type, psa_algorithm_t alg);

/**
 * PSA_CIPHER_IV_LENGTH() - The default IV size for a cipher algorithm, in bytes.
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: A cipher algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is true).
 *
 * The IV that is generated as part of a call to psa_cipher_encrypt() is always the default IV
 * length for the algorithm.
 *
 * This macro can be used to allocate a buffer of sufficient size to store the IV output from
 * psa_cipher_generate_iv() when using a multi-part cipher operation.
 *
 * See also PSA_CIPHER_IV_MAX_SIZE.
 *
 * Return:
 * The default IV size for the specified key type and algorithm. If the algorithm does not use an
 * IV, return 0. If the key type or cipher algorithm is not recognized, or the parameters are
 * incompatible, return 0. An implementation can return either 0 or a correct size for a key type
 * and cipher algorithm that it recognizes, but does not support.
 */
#define PSA_CIPHER_IV_LENGTH(key_type, alg) psa_cipher_iv_length(key_type, alg)

/**
 * DOC: PSA_CIPHER_IV_MAX_SIZE
 * The maximum IV size for all supported cipher algorithms, in bytes.
 *
 * See also PSA_CIPHER_IV_LENGTH().
 */
#define PSA_CIPHER_IV_MAX_SIZE 16

/**
 * PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE() - A sufficient output buffer size for psa_cipher_update(),
 * for any of the supported key types and cipher algorithms.
 * @input_length: Size of the input in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_update() will not fail due to an insufficient buffer size.
 *
 * See also PSA_CIPHER_UPDATE_OUTPUT_SIZE().
 */
#define PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input_length)                        \
/* implementation-defined value */

/**
 * PSA_CIPHER_UPDATE_OUTPUT_SIZE() - A sufficient output buffer size for psa_cipher_update().
 * @key_type: A symmetric key type that is compatible with algorithm @alg.
 * @alg: A cipher algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is true).
 * @input_length: Size of the input in bytes.
 *
 * **Warning: Not supported**
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * psa_cipher_update() will not fail due to an insufficient buffer size. The actual size of the
 * output might be smaller in any given call.
 *
 * See also PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output size for the specified key type and algorithm. If the key type or cipher
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and cipher algorithm that it recognizes, but
 * does not support.
 */
#define PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)             \
	/* implementation-defined value */

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
 * PSA_EXPORT_KEY_OUTPUT_SIZE() - Sufficient output buffer size for psa_export_key().
 * @key_type: A supported key type.
 * @key_bits: The size of the key in bits.
 *
 * The following code illustrates how to allocate enough memory to export a key by querying the key
 * type and size at runtime.
 *
 * .. code-block:: c
 *
 *    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *    psa_status_t status;
 *    status = psa_get_key_attributes(key, &attributes);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *    psa_key_type_t key_type = psa_get_key_type(&attributes);
 *    size_t key_bits = psa_get_key_bits(&attributes);
 *    size_t buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
 *    psa_reset_key_attributes(&attributes);
 *    uint8_t *buffer = malloc(buffer_size);
 *    if (buffer == NULL)
 *        handle_error(...);
 *    size_t buffer_length;
 *    status = psa_export_key(key, buffer, buffer_size, &buffer_length);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 * See also PSA_EXPORT_KEY_PAIR_MAX_SIZE and PSA_EXPORT_PUBLIC_KEY_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_export_key() or psa_export_public_key() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the
 * parameters are a valid combination that is not supported by the implementation, this macro must
 * return either a sensible size or 0. If the parameters are not valid, the return value is
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
 * DOC: PSA_EXPORT_KEY_PAIR_MAX_SIZE
 * Sufficient buffer size for exporting any asymmetric key pair.
 *
 * This value must be a sufficient buffer size when calling psa_export_key() to export any
 * asymmetric key pair that is supported by the implementation, regardless of the exact key type and
 * key size.
 *
 * See also PSA_EXPORT_KEY_OUTPUT_SIZE().
 */
#define PSA_EXPORT_KEY_PAIR_MAX_SIZE                                           \
	PSA_MAX(PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(                          \
			PSA_VENDOR_RSA_MAX_KEY_BITS),                          \
		PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(                          \
			PSA_VENDOR_ECC_MAX_CURVE_BITS))

/**
 * DOC: PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
 * Sufficient buffer size for exporting any asymmetric public key.
 *
 * This value must be a sufficient buffer size when calling psa_export_key() or
 * psa_export_public_key() to export any asymmetric public key that is supported by the
 * implementation, regardless of the exact key type and key size.
 *
 * See also PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE().
 */
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE                                         \
	PSA_MAX(PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(                        \
			PSA_VENDOR_RSA_MAX_KEY_BITS),                          \
		PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(                        \
			PSA_VENDOR_ECC_MAX_CURVE_BITS))

/**
 * PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE() - Sufficient output buffer size for psa_export_public_key().
 * @key_type: A public key or key pair key type.
 * @key_bits: The size of the key in bits.
 *
 * The following code illustrates how to allocate enough memory to export a public key by querying
 * the key type and size at runtime.
 *
 * .. code-block:: c
 *
 *    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *    psa_status_t status;
 *    status = psa_get_key_attributes(key, &attributes);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *    psa_key_type_t key_type = psa_get_key_type(&attributes);
 *    size_t key_bits = psa_get_key_bits(&attributes);
 *    size_t buffer_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits);
 *    psa_reset_key_attributes(&attributes);
 *    uint8_t *buffer = malloc(buffer_size);
 *    if (buffer == NULL)
 *        handle_error(...);
 *    size_t buffer_length;
 *    status = psa_export_public_key(key, buffer, buffer_size, &buffer_length);
 *    if (status != PSA_SUCCESS)
 *        handle_error(...);
 *
 * See also PSA_EXPORT_PUBLIC_KEY_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_export_public_key() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are a
 * valid combination that is not supported by the implementation, this macro must return either a
 * sensible size or 0. If the parameters are not valid, the return value is unspecified.
 *
 * If the parameters are valid and supported, it is recommended that this macro returns the same
 * result as PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(key_type), key_bits).
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
 * @alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 *
 * Hash algorithms process their input data in blocks. Hash operations will retain any partial
 * blocks until they have enough input to fill the block or until the operation is finished.
 *
 * This affects the output from psa_hash_suspend().
 *
 * Return:
 * The block size in bytes for the specified hash algorithm. If the hash algorithm is not
 * recognized, return 0. An implementation can return either 0 or the correct size for a hash
 * algorithm that it recognizes, but does not support.
 */
#define PSA_HASH_BLOCK_LENGTH(alg) psa_hash_block_length(alg)

size_t psa_hash_length(psa_algorithm_t alg);

/**
 * PSA_HASH_LENGTH() - The size of the output of psa_hash_compute() and psa_hash_finish(), in bytes.
 * @alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true), or an HMAC
 * algorithm (PSA_ALG_HMAC(hash_alg) where hash_alg is a hash algorithm).
 *
 * This is also the hash length that psa_hash_compare() and psa_hash_verify() expect.
 *
 * See also PSA_HASH_MAX_SIZE.
 *
 * Return:
 * The hash length for the specified hash algorithm. If the hash algorithm is not recognized, return
 * 0. An implementation can return either 0 or the correct size for a hash algorithm that it
 * recognizes, but does not support.
 */
#define PSA_HASH_LENGTH(alg) psa_hash_length(alg)

/**
 * DOC: PSA_HASH_MAX_SIZE
 * Maximum size of a hash.
 *
 * This macro must expand to a compile-time constant integer. It is recommended that this value is
 * the maximum size of a hash supported by the implementation, in bytes. The value must not be
 * smaller than this maximum.
 *
 * See also PSA_HASH_LENGTH().
 */
#define PSA_HASH_MAX_SIZE 64

/**
 * DOC: PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH
 * The size of the algorithm field that is part of the output of psa_hash_suspend(), in bytes.
 *
 * **Warning: Not supported**
 *
 * Applications can use this value to unpack the hash suspend state that is output by
 * psa_hash_suspend().
 */
#define PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH ((size_t)4)

/**
 * PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH() - The size of the hash-state field that is part of the
 * output of psa_hash_suspend(), in bytes.
 * @alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 *
 * Applications can use this value to unpack the hash suspend state that is output by
 * psa_hash_suspend().
 *
 * Return:
 * The size, in bytes, of the hash-state field of the hash suspend state for the specified hash
 * algorithm. If the hash algorithm is not recognized, return 0. An implementation can return either
 * 0 or the correct size for a hash algorithm that it recognizes, but does not support.
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
 * PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH() - The size of the input-length field that is part of
 * the output of psa_hash_suspend(), in bytes.
 * @alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 *
 * Applications can use this value to unpack the hash suspend state that is output by
 * psa_hash_suspend().
 *
 * Return:
 * The size, in bytes, of the input-length field of the hash suspend state for the specified hash
 * algorithm. If the hash algorithm is not recognized, return 0. An implementation can return either
 * 0 or the correct size for a hash algorithm that it recognizes, but does not support.
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
 * DOC: PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE
 * A sufficient hash suspend state buffer size for psa_hash_suspend(), for any supported hash
 * algorithms.
 *
 * **Warning: Not supported**
 *
 * See also PSA_HASH_SUSPEND_OUTPUT_SIZE().
 */
#define PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * PSA_HASH_SUSPEND_OUTPUT_SIZE() - A sufficient hash suspend state buffer size for
 * psa_hash_suspend().
 * @alg: A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 *
 * If the size of the hash state buffer is at least this large, it is guaranteed that
 * psa_hash_suspend() will not fail due to an insufficient buffer size. The actual size of the
 * output might be smaller in any given call.
 *
 * See also PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE.
 *
 * Return:
 * A sufficient output size for the algorithm. If the hash algorithm is not recognized, or is not
 * supported by psa_hash_suspend(), return 0. An implementation can return either 0 or a correct
 * size for a hash algorithm that it recognizes, but does not support.
 *
 * For a supported hash algorithm alg, the following expression is true\:
 *
 * .. code-block:: c
 *
 *    PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) == PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH +
 *                                         PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) +
 *                                         PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) +
 *                                         PSA_HASH_BLOCK_LENGTH(alg) - 1
 */
#define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg)                                      \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		(PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH +                     \
		 PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(_alg) +            \
		 PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(_alg) +              \
		 PSA_HASH_BLOCK_LENGTH(_alg) - 1);                             \
	})

/**
 * PSA_MAC_TRUNCATED_LENGTH() - Size of the truncated MAC algorithm
 * in bytes.
 * @alg: A MAC algorithm (such that PSA_ALG_IS_MAC_TRUNCATED(alg) is true).
 *
 * Return:
 * The MAC truncated length for the specified algorithm.
 * 0 if the algorithm is not a MAC or a truncated MAC algorithm.
 */
#define PSA_MAC_TRUNCATED_LENGTH(alg)                                          \
	({                                                                     \
		typeof(alg) _alg = (alg);                                      \
		PSA_ALG_IS_MAC_TRUNCATED(_alg) ?                               \
			(_alg & PSA_ALG_MAC_TRUNCATION_MASK) >>                \
				PSA_MAC_TRUNCATION_OFFSET :                    \
			0;                                                     \
	})

/**
 * PSA_HMAC_LENGTH() - Size of the HMAC output length in bytes.
 * @alg: A MAC algorithm (such that PSA_ALG_IS_HMAC(alg) is true).
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
 * in bytes.
 * @alg: A MAC algorithm (such that PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) is true).
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
 * psa_mac_sign_finish(), in bytes.
 * @key_type: The type of the MAC key.
 * @key_bits: The size of the MAC key in bits.
 * @alg: A MAC algorithm (such that PSA_ALG_IS_MAC(alg) is true).
 *
 * This is also the MAC length that psa_mac_verify() and
 * psa_mac_verify_finish() expect.
 *
 * See also PSA_MAC_MAX_SIZE.
 *
 * Return:
 * The MAC length for the specified algorithm with the specified key parameters.
 *
 * 0 if the MAC algorithm is not recognized.
 *
 * Either 0 or the correct length for a MAC algorithm that the implementation
 * recognizes, but does not support.
 */
#define PSA_MAC_LENGTH(key_type, key_bits, alg)                                \
	(PSA_ALG_IS_HMAC(alg) ? PSA_HMAC_LENGTH(alg) :                         \
				PSA_BLOCK_CIPHER_MAC_LENGTH(alg))

/**
 * DOC: PSA_MAC_MAX_SIZE
 * Maximum size of a MAC.
 *
 * This macro must expand to a compile-time constant integer.
 * The maximum MAC size is based on the maximum hash size supported by HMAC
 *
 * See also PSA_MAC_LENGTH().
 */
#define PSA_MAC_MAX_SIZE                                                       \
	PSA_MAX(PSA_HASH_MAX_SIZE, PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)

/**
 * DOC: PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE
 * Maximum size of the output from psa_raw_key_agreement().
 *
 * **Warning: Not supported**
 *
 * This macro must expand to a compile-time constant integer. It is recommended that this value is
 * the maximum size of the output any raw key agreement algorithm supported by the implementation,
 * in bytes. The value must not be smaller than this maximum.
 *
 * See also PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE().
 */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() - Sufficient output buffer size for psa_raw_key_agreement().
 * @key_type: A supported key type.
 * @key_bits: The size of the key in bits.
 *
 * **Warning: Not supported**
 *
 * This macro returns a compile-time constant if its arguments are compile-time constants.
 *
 * **Warning**:
 *	This function might evaluate its arguments multiple times or zero times. Providing arguments
 *	that have side effects will result in implementation-specific behavior, and is non-portable.
 *
 * See also PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_raw_key_agreement() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the parameters are a
 * valid combination that is not supported by the implementation, this macro must return either a
 * sensible size or 0. If the parameters are not valid, the return value is unspecified.
 */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits)                  \
	/* implementation-defined value */

/**
 * DOC: PSA_ECC_SIGNATURE_SIZE
 * Size of an elliptic curve signature.
 *
 * @key_bits: The size of the key in bits.
 */
#define PSA_ECC_SIGNATURE_SIZE(key_bits) (PSA_BITS_TO_BYTES(key_bits) * 2)

#define PSA_ECC_SIGNATURE_MAX_SIZE                                             \
	PSA_ECC_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#define PSA_RSA_SIGNATURE_MAX_SIZE                                             \
	PSA_BITS_TO_BYTES(PSA_VENDOR_MAX_RSA_KEY_BITS)

/**
 * DOC: PSA_SIGNATURE_MAX_SIZE
 * Maximum size of an asymmetric signature.
 *
 * This macro must expand to a compile-time constant integer. It is recommended that this value is
 * the maximum size of an asymmetric signature supported by the implementation, in bytes. The value
 * must not be smaller than this maximum.
 */
#define PSA_SIGNATURE_MAX_SIZE                                                 \
	PSA_MAX(PSA_ECC_SIGNATURE_MAX_SIZE, PSA_RSA_SIGNATURE_MAX_SIZE)

/**
 * PSA_SIGN_OUTPUT_SIZE() - Sufficient signature buffer size for psa_sign_message() and
 * psa_sign_hash().
 * @key_type: An asymmetric key type. This can be a key pair type or a public key type.
 * @key_bits: The size of the key in bits.
 * @alg: The signature algorithm.
 *
 * This macro returns a sufficient buffer size for a signature using a key of the specified type and
 * size, with the specified algorithm. Note that the actual size of the signature might be smaller,
 * as some algorithms produce a variable-size signature.
 *
 * See also PSA_SIGNATURE_MAX_SIZE.
 *
 * Return:
 * If the parameters are valid and supported, return a buffer size in bytes that guarantees that
 * psa_sign_message() and psa_sign_hash() will not fail with PSA_ERROR_BUFFER_TOO_SMALL. If the
 * parameters are a valid combination that is not supported by the implementation, this macro must
 * return either a sensible size or 0. If the parameters are not valid, the return value is
 * unspecified.
 */
#define PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)                          \
	(PSA_KEY_TYPE_IS_RSA(key_type) ?                                       \
		 ((void)alg, PSA_BITS_TO_BYTES(key_bits)) :                    \
		 PSA_KEY_TYPE_IS_ECC(key_type) ?                               \
		 PSA_ECC_SIGNATURE_SIZE(key_bits) :                            \
		 ((void)alg, 0))

/**
 * DOC: PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE
 * This macro returns the maximum supported length of the PSK for the TLS-1.2 PSK-to-MS key
 * derivation.
 *
 * **Warning: Not supported**
 *
 * This implementation-defined value specifies the maximum length for the PSK input used with a
 * PSA_ALG_TLS12_PSK_TO_MS() key agreement algorithm.
 *
 * Quoting Pre-Shared Key Ciphersuites for Transport Layer Security (TLS) [RFC4279] §5.3\:
 *
 *	TLS implementations supporting these cipher suites MUST support arbitrary PSK identities up
 *	to 128 octets in length, and arbitrary PSKs up to 64 octets in length. Supporting longer
 *	identities and keys is RECOMMENDED.
 *
 * Therefore, it is recommended that implementations define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE with a
 * value greater than or equal to 64.
 */
#define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE /* implementation-defined value */

#endif /* __PSA_CRYPTO_SIZES_H__ */
