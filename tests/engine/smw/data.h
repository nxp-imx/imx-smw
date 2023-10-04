/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __DATA_H__
#define __DATA_H__

#include <assert.h>
#include <limits.h>

#include <smw_storage.h>

#include "util_data.h"

/**
 * data_read_descriptor() - Read the data descriptor definition
 * @data_list: Data list.
 * @data_descriptor: Data descriptor.
 * @data_name: Data name.
 *
 * Read the test definition to extract SMW data descriptor fields.
 * Caller is in charge of checking if mandatory fields are set or not.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int data_read_descriptor(struct llist *data_list,
			 struct smw_data_descriptor *data_descriptor,
			 const char *data_name);

#endif /* __DATA_H__ */
