/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#include <tss2/tss2_mu.h>
#include "smw_crypto.h"

/**
 * map_hash_info() - Map hash algorithm information for TPM to SMW mapping.
 * @hash_alg:     TPM2 hash algorithm identifier.
 * @digest_size:  Pointer to store the digest size in bytes (can be NULL).
 * @smw_name:     Pointer to store the SMW hash algorithm name (can be NULL).
 *
 * This function maps a TPM2 hash algorithm identifier to its corresponding
 * digest size and SMW hash algorithm name. It supports SHA1, SHA256, SHA384,
 * and SHA512 algorithms. If an unknown algorithm is provided, it defaults
 * to SHA256 and returns an error code.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful mapping, TSS2_TCTI_RC_BAD_VALUE for unknown algorithm.
 */
uint32_t map_hash_info(TPMI_ALG_HASH hash_alg, uint16_t *digest_size,
		       smw_hash_algo_t *smw_name);
#endif /* __CRYPTO_H__ */
