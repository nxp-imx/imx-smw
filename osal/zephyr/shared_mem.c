// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/devicetree.h>
#include <zephyr/kernel/mm.h>

#include "internal.h"

/* ELE reserved memory defined in DTS */
#define ELE_BUF_NODE DT_NODELABEL(ele_buf)
#if !DT_NODE_HAS_STATUS(ELE_BUF_NODE, okay)
#error "ELE buffer node not enabled"
#endif

#define ELE_BUF_PA   DT_REG_ADDR(ELE_BUF_NODE)
#define ELE_BUF_SIZE DT_REG_SIZE(ELE_BUF_NODE)

/*******************************************************************************
 * Code
 ******************************************************************************/

void osal_shared_memory_init(void)
{
	void *heap_buf = NULL;
	struct osal_ctx *ctx = get_osal_ctx();

	/* In MMU-enabled systems, shared memory is allocated with osal_shared_memory_alloc() */
	heap_buf = k_mem_map_phys_guard(ELE_BUF_PA, ELE_BUF_SIZE, K_MEM_PERM_RW,
					false);
	if (heap_buf)
		k_heap_init(&ctx->heap, heap_buf, ELE_BUF_SIZE);

	ctx->heap_buf = heap_buf;
	ctx->heap_size = ELE_BUF_SIZE;
}

void osal_shared_memory_deinit(void)
{
	struct osal_ctx *ctx = get_osal_ctx();

	k_mem_unmap_phys_guard(ctx->heap_buf, ctx->heap_size, false);
}

void *osal_shared_memory_alloc(void *buf, size_t size, uintptr_t *aligned_phys)
{
	void *aligned_buf = NULL;
	size_t aligned_size = size;
	struct osal_ctx *ctx = get_osal_ctx();

	k_mem_region_align(aligned_phys, &aligned_size, 0, size,
			   CONFIG_MMU_PAGE_SIZE);

	aligned_buf = k_heap_alloc(&ctx->heap, aligned_size, K_NO_WAIT);
	if (!aligned_buf)
		return NULL;

	if (buf)
		memcpy(aligned_buf, buf, size);

	DCACHE_INVALIDATE(aligned_buf, size);

	*aligned_phys = ELE_BUF_PA +
			((uintptr_t)aligned_buf - (uintptr_t)ctx->heap_buf);

	return aligned_buf;
}

void osal_shared_memory_free(void *buf, size_t size, void *original_buf)
{
	struct osal_ctx *ctx = get_osal_ctx();

	if (original_buf)
		memcpy(original_buf, buf, size);

	k_heap_free(&ctx->heap, buf);
}
