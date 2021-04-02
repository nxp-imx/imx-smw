/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __LIB_OPCTX_H__
#define __LIB_OPCTX_H__

#include "types.h"

/**
 * libopctx_add() - Add an operation context to the list
 * @list: List of operations contexts
 * @opctx: Operation context
 *
 * Return:
 * CKR_ARGUMENTS_BAD - @opctx is not valid
 * CKR_HOST_MEMORY   - Memory allocation error
 * CKR_OK            - Success
 */
CK_RV libopctx_add(struct libopctx_list *list, struct libopctx *opctx);

/**
 * libopctx_find() - Find an operation context in the list
 * @list: List of operations contexts
 * @op_flag: Operation flag
 * @opctx: Pointer to operation context structure
 *
 * Return:
 * CKR_OK                             - Success
 */
CK_RV libopctx_find(struct libopctx_list *list, CK_FLAGS op_flag,
		    struct libopctx **opctx);

/**
 * libopctx_destroy() - Destroy an operation context
 * @list: List of operations contexts
 * @opctx: Pointer to operation context structure
 *
 * The operation specific context field @opctx->ctx is freed.
 *
 * Return:
 * CKR_OK                             - Success
 */
CK_RV libopctx_destroy(struct libopctx_list *list, struct libopctx *opctx);

/**
 * libopctx_list_destroy() - Destroy all operations contexts of the @list
 * @list: List of operations contexts
 *
 * Destroy all operations contexts of the @list and destroy the @list's mutex
 * protection.
 *
 * return:
 * CKR_MUTEX_BAD                 - Mutex not correct
 * CKR_HOST_MEMORY               - Memory error
 * CKR_GENERAL_ERROR             - No context available
 * CKR_OK                        - Success
 */
CK_RV libopctx_list_destroy(struct libopctx_list *list);

#endif /* __LIB_OPCTX_H__ */
