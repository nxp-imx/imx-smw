// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "smw_osal.h"
#include "smw_storage.h"
#include "smw/names.h"

#include "util.h"
#include "trace.h"

#include "lib_session.h"
#include "lib_device.h"
#include "libobj_types.h"

#include "args_attr.h"
#include "ifsmw_utils.h"

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

	data_descriptor.data = data->value.array;

	if (SET_OVERFLOW(data->value.number, data_descriptor.length))
		return CKR_FUNCTION_FAILED;

	args_attr_data_storage(&data_attr.attributes, obj);
	data_descriptor.data_attributes = &data_attr;

	args.subsystem_name = devinfo->name;
	args.data_descriptor = &data_descriptor;

	status = smw_store_data(&args);
	ret = smw_status_to_ck_rv(status);

	if (status == SMW_STATUS_OK)
		data->data_id = data_descriptor.identifier;

	return ret;
}

static int retrieve_data(const struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_retrieve_data_args args = { 0 };
	struct smw_data_info_args data_info = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct libobj_data *data = get_subobj_from(obj, storage);
	unsigned char *buffer = NULL;

	ret = set_data_identifier(&data_descriptor.identifier, obj);
	if (ret != CKR_OK)
		return ret;

	args.data_descriptor = &data_descriptor;
	data_info.data_descriptor = &data_descriptor;

	status = smw_get_data_info(&data_info);

	if (status == SMW_STATUS_OK) {
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

	ret = smw_status_to_ck_rv(status);

	if (buffer) {
		if (data->value.array)
			free(data->value.array);

		data->value.array = buffer;
	}

	data->value.number = data_descriptor.length;

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
	return smw_status_to_ck_rv(status);
}

CK_RV libdev_create_data(CK_SESSION_HANDLE hsession, struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return store_data(hsession, obj);
}

CK_RV libdev_retrieve_data(const struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return retrieve_data(obj);
}

CK_RV libdev_delete_data(struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return delete_data(obj);
}
