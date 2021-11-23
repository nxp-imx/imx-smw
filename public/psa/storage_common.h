/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_STORAGE_COMMON_H__
#define __PSA_STORAGE_COMMON_H__

#include <stdint.h>
#include <stddef.h>

#include <psa/status.h>

/**
 * DOC: Reference
 * Documentation:
 *	PSA Storage API v1.0.0 section 5.1 General Definitions
 * Link:
 *	https://armkeil.blob.core.windows.net/developer/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0087-PSA_Storage_API-1.0.0.pdf
 */

/**
 * typedef psa_storage_create_flags_t - Storage create flags
 *
 * Flags used when creating a data entry.
 *
 * Values:
 * * PSA_STORAGE_FLAG_NONE:
 *	No flags to pass.
 * * PSA_STORAGE_FLAG_WRITE_ONCE:
 *	The data associated with the uid will not be able to be modified or deleted. Intended to be
 *	used to set bits in &typedef psa_storage_create_flags_t.
 * * PSA_STORAGE_FLAG_NO_CONFIDENTIALITY:
 *	The data associated with the uid is public and therefore does not require confidentiality.
 *	It therefore only needs to be integrity protected.
 * * PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION:
 *	The data associated with the uid does not require replay protection. This may permit faster
 *	storage - but it permits an attacker with physical access to revert to an earlier version
 *	of the data.
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
