/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTIL_DATA_H__
#define __UTIL_DATA_H__

#include "types.h"

#include "util_list.h"

/**
 * struct data_info - Info of data linked list node.
 * @identifier: Data identifier assigned by SMW.
 * @odata_params: Pointer to the JSON-C object of data info.
 */
struct data_info {
	unsigned int identifier;
	struct json_object *odata_params;
};

/**
 * util_data_init() - Initialize the data list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_data_init(struct llist **list);

/**
 * util_data_build_data_list() - Build the data list.
 * @dir_def_file: Folder of the test definition file.
 * @definition: JSON-C object to be parsed.
 * @data_list: Data list.
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 */
int util_data_build_data_list(char *dir_def_file,
			      struct json_object *definition,
			      struct llist *data_list);

#endif /* __UTIL_DATA_H__ */
