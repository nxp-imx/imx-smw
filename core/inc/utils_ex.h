/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __UTILS_EX_H__
#define __UTILS_EX_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "builtin_macros.h"

#include "global.h"
#include "osal.h"
#include "debug.h"

static inline int smw_utils_file_initialise(void)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->file_initialize)
		return ops->file_initialize();

	return -1;
}

static inline int smw_utils_file_write(uint32_t blob_id_msb,
				       uint32_t blob_id_lsb, uint32_t blob_ext,
				       uint32_t *chunk, size_t chunk_sz)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->file_write)
		return ops->file_write(blob_id_msb, blob_id_lsb, blob_ext,
				       chunk, chunk_sz);

	return -1;
}

static inline int smw_utils_file_read(uint32_t blob_id_msb,
				      uint32_t blob_id_lsb, uint32_t blob_ext,
				      uint32_t *chunk, size_t *sz)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->file_read)
		return ops->file_read(blob_id_msb, blob_id_lsb, blob_ext, chunk,
				      sz);

	return -1;
}

static inline void smw_utils_dcache_invalidate(void *addr, size_t size)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->dcache_invalidate)
		ops->dcache_invalidate(addr, size);
}

static inline void smw_utils_dcache_clean(void *addr, size_t size)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->dcache_clean)
		ops->dcache_clean(addr, size);
}

static inline void smw_utils_shared_memory_init(void)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->shared_memory_init)
		ops->shared_memory_init();
}

static inline void smw_utils_shared_memory_deinit(void)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->shared_memory_deinit)
		ops->shared_memory_deinit();
}

static inline void *smw_utils_shared_memory_alloc(void *buf, size_t size,
						  uintptr_t *aligned_phys)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->shared_memory_alloc)
		return ops->shared_memory_alloc(buf, size, aligned_phys);

	return NULL;
}

static inline void smw_utils_shared_memory_free(void *buf, size_t size,
						void *original_buf)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->shared_memory_free)
		ops->shared_memory_free(buf, size, original_buf);
}

static inline void *smw_utils_get_mu_base(void)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->get_mu_base)
		return ops->get_mu_base();

	return NULL;
}

#endif /* __UTILS_EX_H__ */
