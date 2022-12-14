/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */
#ifndef __UTIL_SIGN_H__
#define __UTIL_SIGN_H__

#include "util_list.h"

/**
 * util_sign_init() - Initialize the signature list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_sign_init(struct llist **list);

/**
 * util_sign_add_node() - Add a new node in a signature linked list.
 * @signatures: Pointer to linked list.
 * @id: Local ID of the signature. Comes from test definition file.
 * @signature: Signature buffer.
 * @signature_length: Signature length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_sign_add_node(struct llist *signatures, unsigned int id,
		       unsigned char *signature, unsigned int signature_length);

/**
 * util_sign_find_node() - Search a signature.
 * @signatures: Signature linked list where the research is done.
 * @id: Id of the signature.
 * @signature: Pointer to the signature buffer.
 * @signature_length: Pointer to the signature length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -FAILED                 - @signatures is NULL or @id is not found.
 */
int util_sign_find_node(struct llist *signatures, unsigned int id,
			unsigned char **signature,
			unsigned int *signature_length);

#endif /* __UTIL_SIGN_H__ */
