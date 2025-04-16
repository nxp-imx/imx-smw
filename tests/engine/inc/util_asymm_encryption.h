/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */
#ifndef __UTIL_ASYMM_ENCRYPTION_H__
#define __UTIL_ASYMM_ENCRYPTION_H__

#include "util_list.h"

/**
 * util_asymm_enc_init() - Initialize the encryption linked list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_asymm_enc_init(struct llist **list);

/**
 * util_asymm_enc_add_node() - Add a new node to a linked list.
 * @list: Pointer to linked list.
 * @id: Local ID of the encryption. Comes from test definition file.
 * @output: Output buffer.
 * @output_length: Output buffer length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_asymm_enc_add_node(struct llist *list, unsigned int id,
			    unsigned char *output, unsigned int output_length);

/**
 * util_asymm_enc_find_node() - Search a node.
 * @signatures: Encryption linked list where the research is done.
 * @id: Id of the encryption.
 * @output: Pointer to the output buffer.
 * @output_length: Output buffer length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -FAILED                 - @signatures is NULL or @id is not found.
 */
int util_asymm_enc_find_node(struct llist *list, unsigned int id,
			     unsigned char **output,
			     unsigned int *output_length);

#endif /* __UTIL_ASYMM_ENCRYPTION_H__ */
