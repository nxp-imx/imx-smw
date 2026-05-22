/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_TYPES_H__
#define __PSA_CRYPTO_TYPES_H__

#include <stdint.h>

/*
 * This file declares types that encode errors, algorithms, key types, policies, etc.
 */

/*
* Reference
 * Documentation:
 *   PSA Cryptography API v1.3.2
 * Link:
 *   https://arm-software.github.io/psa-api/crypto/1.3/
 */

/**
 * typedef psa_algorithm_t - Encoding of a cryptographic algorithm.
 */
typedef uint32_t psa_algorithm_t;

/**
 * typedef psa_dh_family_t - The type of PSA finite-field Diffie-Hellman group
 *                           family identifiers.
 *
 * The group family identifier is required to create an Diffie-Hellman key using
 * the PSA_KEY_TYPE_DH_KEY_PAIR() or PSA_KEY_TYPE_DH_PUBLIC_KEY() macros.
 *
 * The specific Diffie-Hellman group within a family is identified by the
 * `key_bits` attribute of the key.
 *
 * The range of Diffie-Hellman group family identifier values is divided as
 * follows\:
 *
 *  - 0x00
 *      Reserved. Not allocated to a DH group family
 *
 *  - 0x01 - 0x7f
 *      DH group family identifiers defined by this standard. Unallocated
 *      values in this range are reserved for future use.
 *
 *  - 0x80 - 0xff
 *      Implementation defines additional DH family.
 */
typedef uint8_t psa_dh_family_t;

/**
 * typedef psa_ecc_family_t - The type of PSA elliptic curve family identifiers.
 *
 * The curve identifier is required to create an ECC key using the
 * PSA_KEY_TYPE_ECC_KEY_PAIR() or PSA_KEY_TYPE_ECC_PUBLIC_KEY() macros.
 *
 * The specific ECC curve within a family is identified by the key_bits
 * attribute of the key.
 *
 * The range of Elliptic curve family identifier values is divided as follows\:
 *
 *  - 0x00
 *      Reserved. Not allocated to an ECC family.
 *
 *  - 0w01 - 0x7f
 *      ECC family identifiers defined by this standard. Unallocated values in
 *      this range are reserved for future use.
 *
 *  - 0x80 - 0xff
 *      Implementation defines additional ECC family.
 */
typedef uint8_t psa_ecc_family_t;

/**
 * typedef psa_key_derivation_step_t - Encoding of the step of a key derivation.
 */
typedef uint16_t psa_key_derivation_step_t;

/**
 * typedef psa_key_id_t - Key identifier.
 *
 * A key identifiers can be a permanent name for a persistent key, or a
 * transient reference to volatile key.
 */
typedef uint32_t psa_key_id_t;

/**
 * typedef psa_key_lifetime_t - Encoding of key lifetimes.
 */
typedef uint32_t psa_key_lifetime_t;

/**
 * typedef psa_key_location_t - Encoding of key location indicators.
 */
typedef uint32_t psa_key_location_t;

/**
 * typedef psa_key_persistence_t - Encoding of key persistence levels.
 */
typedef uint8_t psa_key_persistence_t;

/**
 * typedef psa_key_type_t - Encoding of a key type.
 */
typedef uint16_t psa_key_type_t;

/**
 * typedef psa_key_usage_t - Encoding of permitted usage on a key.
 */
typedef uint32_t psa_key_usage_t;

/**
 * typedef psa_pake_primitive_t - Encoding of the primitive associated with the
 *                                PAKE.
 */
typedef uint32_t psa_pake_primitive_t;

/**
 * typedef psa_pake_primitive_type_t - Encoding of the primitive associated with
 *                                     the PAKE.
 */
typedef uint8_t psa_pake_primitive_type_t;

/**
 * typedef psa_pake_family_t - Encoding of the family of the primitive
 *                             associated with the PAKE.
 */
typedef uint8_t psa_pake_family_t;

/**
 * typedef psa_pake_role_t - Encoding of the application role in a PAKE
 *                           algorithm.
 *
 * This type is used to encode the application’s role in the algorithm being
 * executed. For more information see the documentation of individual PAKE role
 * constants
 */
typedef uint8_t psa_pake_role_t;

/**
 * typedef psa_pake_step_t - Encoding of input and output steps for a PAKE
 *                           algorithm.
 *
 * Some PAKE algorithms need to exchange more data than a single key share.
 * This type encodes additional input and output steps for such algorithms.
 */
typedef uint8_t psa_pake_step_t;

#endif /* __PSA_CRYPTO_TYPES_H__ */
