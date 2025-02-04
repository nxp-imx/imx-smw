// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
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
#include "lib_object.h"
#include "libobj_types.h"

#include "args_attr.h"
#include "ifsmw_utils.h"

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

	args_attr_obj_storage(&data_attr.attributes, obj);
	data_descriptor.data_attributes = &data_attr;

	args.subsystem_name = devinfo->name;
	args.data_descriptor = &data_descriptor;

	status = smw_store_data(&args);
	ret = smw_status_to_ck_rv(status);

	if (status == SMW_STATUS_OK)
		set_data_token_id(obj, data_descriptor.identifier);

	return ret;
}

static int get_data_attributes(struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_data_info_args data_info = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct smw_data_attributes data_attributes = { 0 };
	struct libobj_data *data = get_subobj_from(obj, storage);

	data_descriptor.identifier = get_data_token_id(obj);
	data_descriptor.data_attributes = &data_attributes;
	data_info.data_descriptor = &data_descriptor;

	status = smw_get_data_info(&data_info);
	ret = smw_status_to_ck_rv(status);

	if (ret == CKR_OK) {
		args_attr_get_obj_storage(obj, data_attributes.attributes);

		data->value.number = data_descriptor.length;
	}

	return ret;
}

static int get_data_value(const struct libobj_obj *obj)
{
	int ret = CKR_OK;

	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_retrieve_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct smw_data_attributes data_attributes = { 0 };
	struct libobj_data *data = get_subobj_from(obj, storage);

	data_descriptor.identifier = get_data_token_id(obj);
	args.data_descriptor = &data_descriptor;
	data_descriptor.data_attributes = &data_attributes;

	if (!data->value.array && data->value.number) {
		data->value.array = malloc(data->value.number);
		if (!data->value.array) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}
	}

	if (SET_OVERFLOW(data->value.number, data_descriptor.length)) {
		ret = CKR_ATTRIBUTE_VALUE_INVALID;
		goto end;
	}

	data_descriptor.data = data->value.array;

	status = smw_retrieve_data(&args);
	ret = smw_status_to_ck_rv(status);

	/*
	 * If the data buffer was NULL or length too small retry to get
	 * the data value with the new buffer size.
	 */
	if (ret == CKR_OK) {
		data->value.number = data_descriptor.length;
		if (data->value.array)
			goto end;
	} else if (ret == CKR_BUFFER_TOO_SMALL) {
		data->value.number = data_descriptor.length;
	} else {
		goto end;
	}

	if (data->value.array)
		free(data->value.array);

	if (!data->value.number) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	data->value.array = malloc(data->value.number);
	if (!data->value.array) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	data_descriptor.data = data->value.array;

	status = smw_retrieve_data(&args);
	ret = smw_status_to_ck_rv(status);

end:
	return ret;
}

static int delete_data(struct libobj_obj *obj)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_delete_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };

	data_descriptor.identifier = get_data_token_id(obj);
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

CK_RV libdev_get_data_attributes(struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return get_data_attributes(obj);
}

CK_RV libdev_get_data_value(const struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return get_data_value(obj);
}

CK_RV libdev_delete_data(struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	return delete_data(obj);
}
