/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_H__
#define __PSA_CRYPTO_H__

#include <stdint.h>
#include <stddef.h>

/*
 * This file contains the delarations of the crypto functions supported by the
 * PSA Cryptography API.
 */

/*
 * Reference
 * Documentation:
 *   PSA Cryptography API v1.3.2
 * Link:
 *   https://arm-software.github.io/psa-api/crypto/1.3/about
 */

#include "psa/error.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/keymgr.h"
#include "psa/crypto/rng.h"
#include "psa/crypto/hash.h"
#include "psa/crypto/mac.h"
#include "psa/crypto/cipher.h"
#include "psa/crypto/sign.h"
#include "psa/crypto/aead.h"
#include "psa/crypto/asymmetric_encryption.h"
#include "psa/crypto/pake.h"

/**
 * PSA_CRYPTO_API_VERSION_MAJOR - The major version of this implementation of
 *                                the PSA Crypto API.
 */
#define PSA_CRYPTO_API_VERSION_MAJOR 1

/**
 * PSA_CRYPTO_API_VERSION_MINOR - The minor version of this implementation of
 *                                the PSA Crypto API.
 */
#define PSA_CRYPTO_API_VERSION_MINOR 3

/**
 * PSA_KEY_DERIVATION_UNLIMITED_CAPACITY - Use the maximum possible capacity
 *                                         for a key derivation operation.
 *
 * .. warning::
 *    Not supported.
 *
 * Use this value as the capacity argument when setting up a key derivation to
 * specify that the operation will use the maximum possible capacity. The value
 * of the maximum possible capacity depends on the key derivation algorithm.
 */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY                                  \
	0 /* implementation-defined value */

/**
 * psa_crypto_init() - Library initialization.
 *
 * Applications must call this function before calling any other function in
 * this module.
 *
 * Applications are permitted to call this function more than once. Once a call
 * succeeds, subsequent calls are guaranteed to succeed.
 *
 * If the application calls any functions before calling psa_crypto_init(),
 * the function returns PSA_ERROR_BAD_STATE.
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"

#endif /* __PSA_CRYPTO_H__ */
