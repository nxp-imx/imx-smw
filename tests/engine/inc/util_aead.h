/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTIL_AEAD_H__
#define __UTIL_AEAD_H__

#include "util_list.h"

/**
 * struct aead_output_data - AEAD output data
 * @output: Pointer to output data.
 * @output_len: @output length in bytes.
 */
struct aead_output_data {
	unsigned char *output;
	unsigned int output_len;
};

/**
 * util_aead_init() - Initialize the AEAD list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_aead_init(struct llist **list);

/**
 * util_aead_add_output_data() - Add data in a AEAD output linked list
 * @list: Pointer to AEAD output data linked list.
 * @ctx_id: Local context ID.
 * @out_data: Data to add.
 * @data_len: @out_data length in bytes.
 *
 * If parameter @list is NULL it's allocated in this function.
 * If it's the first call for parameter @ctx_id, the node is allocated.
 * Else, parameter @out_data is added to existing node data.
 * All the memory allocated by this function is freed when
 * util_list_clear() is called.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_aead_add_output_data(struct llist *list, unsigned int ctx_id,
			      unsigned char *out_data, unsigned int data_len);

/**
 * util_aead_cmp_output_data() - Compare AEAD output data
 * @list: Pointer to AEAD output data linked list.
 * @ctx_id: Local context ID.
 * @data: Data to compare.
 * @data_len: @data length in bytes.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - @ctx_id node is not found.
 * -SUBSYSTEM              - Comparison failed.
 */
int util_aead_cmp_output_data(struct llist *list, unsigned int ctx_id,
			      unsigned char *data, unsigned int data_len);

#endif /* __UTIL_AEAD_H__ */
