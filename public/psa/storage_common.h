/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022, 2026 NXP
 */

#ifndef __PSA_STORAGE_COMMON_H__
#define __PSA_STORAGE_COMMON_H__

#include <stdint.h>
#include <stddef.h>

#include "psa/error.h"

/*
 * This file defines common definitions for PSA storage.
 */

/*
 * Reference
 * Documentation:
 *   PSA Storage API v1.0.4 section 5.1 General Definitions
 * Link:
 *   https://arm-software.github.io/psa-api/storage/1.0
 */

/**
 * typedef psa_storage_create_flags_t - Storage create flags
 *
 * Flags used when creating a data entry.
 */
typedef uint32_t psa_storage_create_flags_t;

/**
 * typedef psa_storage_uid_t - Storage uid
 *
 * A type for uid used for identifying data.
 */
typedef uint64_t psa_storage_uid_t;

/**
 * struct psa_storage_info_t - Storage info
 * @capacity: The allocated capacity of the storage associated with a uid.
 * @size: The size of the data associated with a uid.
 * @flags: The flags set when the uid was created.
 */
struct psa_storage_info_t {
	size_t capacity;
	size_t size;
	psa_storage_create_flags_t flags;
};

#ifndef BIT
#define BIT(n) (1u << (n))
#endif /* BIT */

#define PSA_STORAGE_FLAG_NONE		      0u
#define PSA_STORAGE_FLAG_WRITE_ONCE	      BIT(0)
#define PSA_STORAGE_FLAG_NO_CONFIDENTIALITY   BIT(1)
#define PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION BIT(2)

#define PSA_STORAGE_SUPPORT_SET_EXTENDED BIT(0)

#endif /* __PSA_STORAGE_COMMON_H__ */
