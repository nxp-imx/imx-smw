/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __DATA_H__
#define __DATA_H__

#include <stddef.h>
#include <stdint.h>

#include <psa/internal_trusted_storage.h>

#include "util_data.h"

struct data_descriptor {
	psa_storage_uid_t uid;
	void *data;
	size_t length;
	psa_storage_create_flags_t create_flags;
};

/**
 * data_read_descriptor_psa() - Set the PSA data buffer and attributes
 * @data_list: Data list.
 * @data_descriptor: Data descriptor.
 * @data_name: Data name.
 *
 * Read the test definition to extract PSA data buffer and attributes.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int data_read_descriptor_psa(struct llist *data_list,
			     struct data_descriptor *data_descriptor,
			     const char *data_name);

#endif /* __DATA_H__ */
