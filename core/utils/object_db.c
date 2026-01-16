// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "global.h"
#include "object_db.h"
#include "utils.h"

static int object_id_to_user_id(char **dst, unsigned int id)
{
	int ret = SMW_STATUS_ALLOC_FAILURE;

	unsigned int len = sizeof(id);
	unsigned int len_b64 = 0;
	unsigned int idx = 0;
	uint8_t *tmp = NULL;
	uint8_t *tmp_b64 = NULL;
	uint8_t byte = 0;

	/*
	 * Count the number of bytes removing the MSB equal 0
	 */
	for (idx = sizeof(id) - 1; idx > 0; idx--) {
		byte = (id >> (idx * 8)) & 0xFF;
		if (byte)
			break;

		if (DEC_OVERFLOW(len, 1)) {
			len = 1;
			break;
		}
	}

	tmp = SMW_UTILS_MALLOC(len);
	if (!tmp)
		goto end;

	len_b64 = smw_utils_get_base64_len(len);
	if (!len_b64)
		goto end;

	tmp_b64 = SMW_UTILS_CALLOC(1, len_b64 + 1);
	if (!tmp_b64)
		goto end;

	/*
	 * Copy the id significant bytes in big endian format to
	 * have pkcs11 object identifier print like unsigned int.
	 */
	for (idx = 0; idx < len; idx++) {
		byte = (id >> ((len - idx - 1) * 8)) & 0xFF;
		tmp[idx] = byte;
	}

	ret = smw_utils_base64_encode(tmp, len, tmp_b64, &len_b64);

end:
	if (ret == SMW_STATUS_OK)
		*dst = (char *)tmp_b64;
	else if (tmp_b64)
		SMW_UTILS_FREE(tmp_b64);

	if (tmp)
		SMW_UTILS_FREE(tmp);

	return ret;
}

void smw_object_db_prepare(unsigned int s_id,
			   struct smw_object_descriptor *obj_desc,
			   struct smw_osal_object *obj)
{
	smw_attr_attributes_t persistence = 0;

	obj->obj_id_subsystem = s_id;
	obj->obj_desc = obj_desc;

	switch (obj_desc->type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		persistence = obj_desc->data.attributes.attributes;
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		persistence = obj_desc->key.attributes.attributes;
		break;

	default:
		persistence = obj_desc->persistency;
		break;
	}

	persistence = SMW_ATTR_GET_PERSISTENCE(persistence);
	obj_desc->persistency = SMW_ATTR_SET_PERSISTENCE(0, persistence);
}

int smw_object_db_create(unsigned int s_id,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_CREATE;
	struct smw_ops *ops = get_smw_ops();
	struct smw_osal_object obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->add_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prepare(s_id, descriptor, &obj);

	if (!ops->add_obj_info(&obj) && descriptor->id != INVALID_OBJ_ID)
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_update(unsigned int s_id,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_UPDATE;
	struct smw_ops *ops = get_smw_ops();
	bool free_user_id = false;
	struct smw_osal_object obj = { 0 };
	struct smw_object_descriptor desc_copy = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->update_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prepare(s_id, descriptor, &obj);

	/* Only update R/W attributes */
	if (s_id == INVALID_OBJ_ID) {
		desc_copy.id = descriptor->id;
		desc_copy.label = descriptor->label;
		desc_copy.user_id = descriptor->user_id;
		desc_copy.persistency = descriptor->persistency;

		obj.obj_desc = &desc_copy;
	}

	/*
	 * If the descriptor User ID is not defined, assign the user id to
	 * be the given input id.
	 */
	if (!descriptor->user_id) {
		free_user_id = true;

		ret = object_id_to_user_id(&descriptor->user_id,
					   descriptor->id);
		if (ret != SMW_STATUS_OK)
			return ret;
	}

	if (!ops->update_obj_info(&obj))
		ret = SMW_STATUS_OK;

	if (free_user_id) {
		SMW_UTILS_FREE(descriptor->user_id);
		descriptor->user_id = NULL;
	}

	return ret;
}

int smw_object_db_delete(struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_DELETE;
	struct smw_ops *ops = get_smw_ops();
	struct smw_osal_object obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ops || !ops->delete_obj_info || !descriptor)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prepare(INVALID_OBJ_ID, descriptor, &obj);

	if (!ops->delete_obj_info(&obj))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_get_info(unsigned int *s_id,
			   struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_GET_INFO;
	struct smw_ops *ops = get_smw_ops();
	struct smw_osal_object obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->get_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prepare(*s_id, descriptor, &obj);

	if (!ops->get_obj_info(&obj)) {
		ret = SMW_STATUS_OK;
		*s_id = obj.obj_id_subsystem;
	} else if (descriptor->id == INVALID_OBJ_ID) {
		ret = SMW_STATUS_UNKNOWN_ID;
	}

	return ret;
}

void smw_object_db_clean_descriptor(struct smw_object_descriptor *obj)
{
	if (!obj)
		return;

	if (obj->label)
		SMW_UTILS_FREE(obj->label);

	if (obj->user_id)
		SMW_UTILS_FREE(obj->user_id);

	obj->label = NULL;
	obj->user_id = NULL;
}
