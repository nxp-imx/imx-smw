// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "util_attr.h"

#define UTIL_ATTR_ARRAY_SIZE (10)

int util_attr_read_attributes(struct json_object *params, const char *key,
			      attribute_callback callback, void *user_data)
{
	struct json_object *obj = NULL;
	struct json_object *value = NULL;
	size_t nb_params = 0;
	size_t idx = 0;
	const char *array[UTIL_ATTR_ARRAY_SIZE] = { 0 };

	if (!json_object_object_get_ex(params, key, &obj))
		return ERR_CODE(VALUE_NOTFOUND);

	nb_params = json_object_array_length(obj);
	if (nb_params > UTIL_ATTR_ARRAY_SIZE) {
		DBG_PRINT("Too many values in simple array!");
		return ERR_CODE(INTERNAL);
	}

	for (; idx < nb_params; idx++) {
		value = json_object_array_get_idx(obj, idx);
		array[idx] = json_object_get_string(value);
	}

	callback(user_data, array, nb_params);

	return ERR_CODE(PASSED);
}
