/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTIL_CERTIFICATE_H__
#define __UTIL_CERTIFICATE_H__

#include "util_list.h"

/**
 * util_certificate_init() - Initialize the certificate list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_certificate_init(struct llist **list);

/**
 * util_certificate_add_node() - Add a new node in a certificate linked list.
 * @certificates: Pointer to linked list.
 * @id: Local ID of the certificate. Comes from test definition file.
 * @certificate: certificate buffer.
 * @certificate_length: certificate length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_certificate_add_node(struct llist *certificates, unsigned int id,
			      unsigned char *certificate,
			      unsigned int certificate_length);

/**
 * util_certificate_find_node() - Search a certificate.
 * @certificates: certificate linked list where the research is done.
 * @id: Id of the certificate.
 * @certificate: Pointer to the certificate buffer.
 * @certificate_length: Pointer to the certificate length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -FAILED                 - @certificates is NULL or @id is not found.
 */
int util_certificate_find_node(struct llist *certificates, unsigned int id,
			       unsigned char **certificate,
			       unsigned int *certificate_length);

#endif /* __UTIL_CERTIFICATE_H__ */
