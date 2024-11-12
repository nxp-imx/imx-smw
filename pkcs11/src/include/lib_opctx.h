/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2024 NXP
 */

#ifndef __LIB_OPCTX_H__
#define __LIB_OPCTX_H__

#include "types.h"

/**
 * enum op_state - Operation state
 *
 * Set when calling encryption or sign/verify functions
 *
 * @NOT_INIT: State not initialized.
 * @OP_INIT: C_(Encrypt|Decrypt|Sign|Verify)Init
 * or C_Message(Encrypt|Decrypt|Sign|Verify)Init.
 * @OP_ONE_SHOT: C_(Encrypt|Decrypt|Sign|Verify)
 * or C_(Encrypt|Decrypt|Sign|Verify)cryptMessage.
 * @OP_UPDATE: C_(Encrypt|Decrypt|Sign|Verify)Update.
 * @OP_BEGIN: C_(Encrypt|Decrypt|Sign|Verify)MessageBegin.
 * @OP_NEXT: C_(Encrypt|Decrypt|Sign|Verify)MessageNext, more input.
 * @OP_END: C_(Encrypt|Decrypt|Sign|Verify)MessageNext, no more input.
 * @OP_FINAL: C_(Encrypt|Decrypt|Sign|Verify)Final.
 */
enum op_state {
	NOT_INIT = 0,
	OP_INIT,
	OP_ONE_SHOT,
	OP_UPDATE,
	OP_BEGIN,
	OP_NEXT,
	OP_END,
	OP_FINAL
};

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

/**
 * libopctx_cancel() - Cancel the ongoing multi-part crypto operation.
 * @list: List of operations contexts
 * @opctx: Pointer to operation context structure
 * @context: Double pointer to multi-part operation context
 *
 * The operation specific context field @opctx->ctx is freed.
 *
 * Return:
 * CKR_MUTEX_BAD                 - Mutex not correct
 * CKR_HOST_MEMORY               - Memory error
 * CKR_GENERAL_ERROR             - No context available
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libopctx_cancel(struct libopctx_list *list, struct libopctx *opctx,
		      void **context);

/**
 * libopctx_check_next_state() - Check the next state of the ongoing multi-part
 * crypto operation.
 * @current_state: Current operation state
 * @next_state: Next operation state
 * @terminate: Whether or not the operation must be terminated
 *
 * The next state of the multi-part crypto operation is checked against its
 * current state.
 * @terminate is set to CK_TRUE if the ongoing multi-part crypto operation must
 * be terminated.
 *
 * Return:
 * CKR_OPERATION_NOT_INITIALIZED - Operation not initialized
 * CKR_ARGUMENTS_BAD             - Next state is not valid
 * CKR_OK                        - Success
 */
CK_RV libopctx_check_next_state(enum op_state current_state,
				enum op_state next_state, CK_BBOOL *terminate);

/**
 * libopctx_copy() - Copy the ongoing multi-part crypto operation.
 * @src: Source multi-part operation context
 * @dst: Destination multi-part operation context
 *
 * The operation specific context field @src->ctx is copied.
 *
 * Return:
 * CKR_STATE_UNSAVEABLE               - State cannot be saved
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_FUNCTION_FAILED                - Operation failed
 * CKR_OBJECT_HANDLE_INVALID          - Object not found
 * CKR_DEVICE_ERROR                   - Device failure
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OK                             - Success
 */
CK_RV libopctx_copy(struct libopctx *src, struct libopctx *dst);

#endif /* __LIB_OPCTX_H__ */
