/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __OP_CONTEXT_H__
#define __OP_CONTEXT_H__

/* SMW operation context arguments structure */
struct smw_op_context;

/**
 * struct smw_context_args - SMW cryptographic operation context arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @context: Pointer to an opaque operation context structure
 *
 * The @context parameter allocated by SMW should not be modified by the
 * application.
 *
 * This opaque structure is dynamically allocated by the SMW library upon
 * invoking the function smw_allocate_context(). It is deallocated when any of
 * the following conditions are met:\
 *
 *  - Upon successful completion of the associated multi-part final operation.
 *  - In the event of critical failure during the associated operation.
 *  - When smw_cancel_operation() function is invoked.
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 *
 */
struct smw_context_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_op_context *context;
};

/**
 * struct smw_copy_context_args - SMW cryptographic copy operation context args
 * @version: Version of this structure
 * @src_context: Pointer to source opaque operation context structure
 * @dst_context: Pointer to destination opaque operation context structure
 */
struct smw_copy_context_args {
	unsigned char version;
	struct smw_op_context *src_context;
	struct smw_op_context *dst_context;
};

/**
 * smw_allocate_context() - Allocate SMW operation context
 * @args: Pointer to operation context arguments structure.
 *
 * This function allocates an operation context for a new cryptographic
 * operation.
 *
 * This function is intended for use in the multi-part cryptographic operation
 * and it serves as the first step in such operations.
 * This function does not need to be called for one-shot cryptographic
 * operation.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_allocate_context(struct smw_context_args *args);

/**
 * smw_cancel_operation() - Cancel on-going cryptographic multi-part operation
 * @args: Pointer to an operation context arguments structure.
 *
 * This function cancels the on-going cryptographic multi-part operation and
 * releases all the memory allocated to SMW operation context.
 * Additionally, this function can be used to release the SMW operation context
 * even if there are no on-going multi-part operations associated with it.
 *
 * Upon successful completion, @args->context field is set to NULL.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_cancel_operation(struct smw_context_args *args);

/**
 * smw_copy_context() - Copy an operation context
 * @args: Pointer to copy operation context arguments structure.
 *
 * This function copies the last state of the source operation context to the
 * destination operation context.
 * Destination context must be allocated using smw_allocate_context() function
 * prior to invoking this function.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_copy_context(struct smw_copy_context_args *args);

#endif /* __OP_CONTEXT_H__ */
