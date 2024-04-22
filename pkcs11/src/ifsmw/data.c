// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "smw_osal.h"
#include "smw_status.h"
#include "smw_storage.h"

#include "util.h"

#include "lib_session.h"
#include "lib_device.h"
#include "libobj_types.h"

#include "args_attr.h"

#define DATA_LABEL(name)                                                       \
	{                                                                      \
		.string = (CK_UTF8CHAR *)name, .length = sizeof(name) - 1,     \
	}

static int set_tee_info(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("TEE", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_seco_info(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("SECO", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_ele_info(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("ELE", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_obj_db(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_open_obj_db((const char *)data->value.array,
				      data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_data_identifier(unsigned int *identifier,
			       const struct libobj_obj *obj)
{
	int ret = CKR_OK;

	struct librfc2279 *unique_id = get_unique_id_obj(obj, storage);
	struct libbytes data_id = { 0 };

	data_id.number =
		util_rfc2279_to_byte_len(unique_id->string, unique_id->length);
	if (!data_id.number)
		return CKR_FUNCTION_FAILED;

	data_id.array = malloc(data_id.number);
	if (!data_id.array)
		return CKR_HOST_MEMORY;

	if (util_rfc2279_to_byte(data_id.array, data_id.number,
				 unique_id->string,
				 unique_id->length) != unique_id->length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (TO_INT(*identifier, &data_id.array[sizeof(obj->class)],
		   sizeof(*identifier)))
		ret = CKR_ATTRIBUTE_VALUE_INVALID;

end:
	free(data_id.array);

	return ret;
}

static int store_data(CK_SESSION_HANDLE hsession, struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct smw_store_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct libobj_data *data = get_subobj_from(obj, storage);
	struct smw_data_attributes data_attr = { 0 };

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		return ret;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	ret = set_data_identifier(&data_descriptor.identifier, obj);
	if (ret != CKR_OK)
		return ret;

	data_descriptor.data = data->value.array;

	if (SET_OVERFLOW(data->value.number, data_descriptor.length))
		return CKR_FUNCTION_FAILED;

	args_attr_data_storage(&data_attr.attributes, obj);
	data_descriptor.data_attributes = &data_attr;

	args.subsystem_name = devinfo->name;
	args.data_descriptor = &data_descriptor;

	status = smw_store_data(&args);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int retrieve_data(const struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_retrieve_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct libobj_data *data = get_subobj_from(obj, storage);
	unsigned char *buffer = NULL;

	ret = set_data_identifier(&data_descriptor.identifier, obj);
	if (ret != CKR_OK)
		return ret;

	args.data_descriptor = &data_descriptor;

	status = smw_retrieve_data(&args);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && data_descriptor.length) {
		if (data->value.number < data_descriptor.length) {
			buffer = malloc(data_descriptor.length);
			if (!buffer)
				return CKR_HOST_MEMORY;

			data_descriptor.data = buffer;
		} else {
			data_descriptor.data = data->value.array;
		}

		status = smw_retrieve_data(&args);
	}

	if (status != SMW_STATUS_OK) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (buffer) {
		if (data->value.array)
			free(data->value.array);

		data->value.array = buffer;
	}

	data->value.number = data_descriptor.length;

end:
	if (ret != CKR_OK && buffer)
		free(buffer);

	return ret;
}

static int delete_data(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_delete_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };

	ret = set_data_identifier(&data_descriptor.identifier, obj);
	if (ret != CKR_OK)
		return ret;

	args.data_descriptor = &data_descriptor;

	status = smw_delete_data(&args);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static const struct data_op {
	struct librfc2279 label;
	int (*set)(struct libobj_obj *obj);
} data_op[] = {
	{ DATA_LABEL("TEE Info"), .set = &set_tee_info },
	{ DATA_LABEL("SECO Info"), .set = &set_seco_info },
	{ DATA_LABEL("ELE Info"), .set = &set_ele_info },
	{ DATA_LABEL("Object DB"), .set = &set_obj_db },
};

struct librfc2279 data_label = DATA_LABEL("Data");

CK_RV libdev_create_data(CK_SESSION_HANDLE hsession, struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;
	const struct data_op *op = data_op;
	size_t index = 0;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	if (objstorage->label.length == data_label.length &&
	    !memcmp(objstorage->label.string, data_label.string,
		    data_label.length))
		return store_data(hsession, obj);

	for (; index < ARRAY_SIZE(data_op); index++, op++) {
		if (objstorage->label.length == op->label.length &&
		    !memcmp(objstorage->label.string, op->label.string,
			    op->label.length)) {
			return op->set(obj);
		}
	}

	return CKR_FUNCTION_FAILED;
}

CK_RV libdev_retrieve_data(const struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	if (objstorage->label.length == data_label.length &&
	    !memcmp(objstorage->label.string, data_label.string,
		    data_label.length))
		return retrieve_data(obj);

	return CKR_FUNCTION_FAILED;
}

CK_RV libdev_delete_data(struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	if (objstorage->label.length == data_label.length &&
	    !memcmp(objstorage->label.string, data_label.string,
		    data_label.length))
		return delete_data(obj);

	return CKR_FUNCTION_FAILED;
}
