// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "data.h"

#include "lib_device.h"
#include "libobj_types.h"
#include "util.h"

#include "trace.h"

enum attr_data_list {
	DATA_APPLICATION = 0,
	DATA_ID,
	DATA_VALUE,
};

const struct template_attr attr_data[] = {
	[DATA_APPLICATION] =
		TATTR(data, application, APPLICATION, 0, OPTIONAL, rfc2279),
	[DATA_ID] = TATTR(data, id, OBJECT_ID, 0, OPTIONAL, byte_array),
	[DATA_VALUE] = TATTR(data, value, VALUE, 0, OPTIONAL, byte_array),
};

/**
 * data_allocate() - Allocate and initialize data object
 * @obj: Data object
 *
 * return:
 * Reference to allocated common key if success
 * NULL otherwise
 */
static struct libobj_data *data_allocate(struct libobj_obj *obj)
{
	struct libobj_data *data = NULL;

	data = calloc(1, sizeof(*data));
	if (data)
		set_subobj_to(obj, storage, data);

	DBG_TRACE("Allocated a new data object (%p)", data);
	return data;
}

void data_free(struct libobj_obj *obj)
{
	struct libobj_data *data = get_subobj_from(obj, storage);

	if (!data)
		return;

	DBG_TRACE("Free data object (%p)", data);

	if (data->application.string)
		free(data->application.string);

	if (data->id.array)
		free(data->id.array);

	if (data->value.array)
		free(data->value.array);

	free(data);
}

CK_RV data_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		  struct libattr_list *attrs)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libobj_data *new_data = NULL;

	DBG_TRACE("Create a new data type object");

	if (!obj)
		return ret;

	new_data = data_allocate(obj);
	if (!new_data)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Create a new data (%p)", new_data);

	ret = attr_get_value(new_data, &attr_data[DATA_APPLICATION], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_data, &attr_data[DATA_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_data, &attr_data[DATA_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (is_token_obj(obj, storage))
		ret = libdev_create_data(hsession, obj);

	DBG_TRACE("Data type object (%p) creation return %ld", obj, ret);
	return ret;
}

CK_RV data_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the data attribute */
	ret = attr_get_obj_value(attr, attr_data, ARRAY_SIZE(attr_data),
				 get_subobj_from(obj, storage));

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV data_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Get attribute from the common key attribute */
	ret = attr_modify_obj_value(attr, attr_data, ARRAY_SIZE(attr_data),
				    get_subobj_from(obj, storage));

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}
