/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_HASH_H__
#define __ELE_CRYPTO_HASH_H__

#include "ele_common.h"

/*******************************************************************************
 * HASH Definitions
 ******************************************************************************/
/**
 * hash_algo_t - Supported cryptographic hash algorithms identifiers.
 * ELE_MD5: MD5 hash algorithm
 * ELE_SHA_1: SHA-1 hash algorithm
 * ELE_SHA_224: SHA-224 hash algorithm
 * ELE_SHA_256: SHA-256 hash algorithm
 * ELE_SHA_384: SHA-384 hash algorithm
 * ELE_SHA_512: SHA-512 hash algorithm
 * ELE_SHA3_224: SHA3-224 hash algorithm
 * ELE_SHA3_256: SHA3-256 hash algorithm
 * ELE_SHA3_384: SHA3-384 hash algorithm
 * ELE_SHA3_512: SHA3-512 hash algorithm
 * ELE_SM3_256: SM3_256 hash algorithm
 * ELE_SHAKE_256: SHAKE-256 hash algorithm
 */
typedef enum {
	ELE_MD5 = 0x02000003,
	ELE_SHA_1 = 0x02000005,
	ELE_SHA_224 = 0x02000008,
	ELE_SHA_256 = 0x02000009,
	ELE_SHA_384 = 0x0200000A,
	ELE_SHA_512 = 0x0200000B,
	ELE_SHA3_224 = 0x02000010,
	ELE_SHA3_256 = 0x02000011,
	ELE_SHA3_384 = 0x02000012,
	ELE_SHA3_512 = 0x02000013,
	ELE_SM3_256 = 0x02000014,
	ELE_SHAKE_256 = 0x02000015,
} hash_algo_t;

#endif /* __ELE_CRYPTO_HASH_H__ */
