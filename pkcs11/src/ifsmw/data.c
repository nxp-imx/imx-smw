// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */
#include <string.h>

#include "smw_osal.h"
#include "smw_status.h"

#include "lib_device.h"
#include "libobj_types.h"
#include "util.h"

#define DATA_LABEL(name)                                                       \
	{                                                                      \
		.string = (CK_UTF8CHAR *)name, .length = sizeof(name) - 1,     \
	}

static int set_tee_info(struct libobj_obj *obj)
{
	int ret = CKR_DEVICE_ERROR;

	enum smw_status_code status;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("TEE", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_hsm_info(struct libobj_obj *obj)
{
	int ret = CKR_DEVICE_ERROR;

	enum smw_status_code status;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("HSM", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_ele_info(struct libobj_obj *obj)
{
	int ret = CKR_DEVICE_ERROR;

	enum smw_status_code status;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_set_subsystem_info("ELE", data->value.array,
					     data->value.number);
	if (status == SMW_STATUS_OK)
		ret = CKR_OK;
	else if (status == SMW_STATUS_SUBSYSTEM_LOADED)
		ret = CKR_FUNCTION_FAILED;

	return ret;
}

static int set_key_db(struct libobj_obj *obj)
{
	int ret = CKR_DEVICE_ERROR;

	enum smw_status_code status;
	struct libobj_data *data = get_subobj_from(obj, storage);

	status = smw_osal_open_key_db((const char *)data->value.array,
				      data->value.number);
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
	{ DATA_LABEL("HSM Info"), .set = &set_hsm_info },
	{ DATA_LABEL("ELE Info"), .set = &set_ele_info },
	{ DATA_LABEL("Key DB"), .set = &set_key_db },
};

CK_RV libdev_create_data(CK_SESSION_HANDLE hsession, struct libobj_obj *obj)
{
	(void)hsession;

	struct libobj_storage *objstorage;
	const struct data_op *op = data_op;
	size_t index;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return CKR_ARGUMENTS_BAD;

	for (index = 0; index < ARRAY_SIZE(data_op); index++, op++) {
		if (objstorage->label.length == op->label.length &&
		    !memcmp(objstorage->label.string, op->label.string,
			    op->label.length)) {
			return op->set(obj);
		}
	}

	return CKR_FUNCTION_FAILED;
}
