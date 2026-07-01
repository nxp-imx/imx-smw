// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "constants.h"
#include "internal.h"

#include "object_query.h"

/* Simple in-memory database implementation */
/* For production, consider using NVS or other persistent storage */

static void key_identifier_to_object(struct smw_keymgr_identifier *identifier,
				     struct smw_object_descriptor *obj)
{
	int status = SMW_STATUS_OK;
	enum smw_keymgr_privacy_id privacy = identifier->privacy_id;
	enum smw_keymgr_privacy_id default_privacy =
		SMW_KEYMGR_PRIVACY_ID_INVALID;

	if (identifier->type_id != SMW_CONFIG_KEY_TYPE_ID_INVALID) {
		status = smw_keymgr_get_privacy_id(identifier->type_id,
						   &default_privacy);
		if (status != SMW_STATUS_OK)
			return;
	}

	if (privacy == SMW_KEYMGR_PRIVACY_ID_INVALID)
		privacy = default_privacy;

	switch (privacy) {
	case SMW_KEYMGR_PRIVACY_ID_PAIR:
		obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		break;

	case SMW_KEYMGR_PRIVACY_ID_PUBLIC:
		obj->type = SMW_OBJECT_TYPE_NAME_PUBLIC_KEY;
		break;

	case SMW_KEYMGR_PRIVACY_ID_PRIVATE:
		if (default_privacy == SMW_KEYMGR_PRIVACY_ID_PAIR)
			obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		else
			obj->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	case SMW_KEYMGR_PRIVACY_ID_SHARED_SECRET:
		obj->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	default:
		break;
	}

	if (identifier->subsystem_id == SUBSYSTEM_ID_INVALID)
		obj->subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	else
		obj->subsystem_name =
			smw_config_get_subsystem_name(identifier->subsystem_id);

	obj->key.type_name = smw_config_get_key_type_name(identifier->type_id);
	obj->key.security_size = identifier->security_size;
	obj->key.attributes = identifier->key_attributes;
	obj->group = identifier->group;
}

int osal_zephyr_get_obj_info(struct smw_osal_object *descriptor)
{
	int status = -1;

	struct smw_object_query obj_query = { 0 };
	struct smw_object_descriptor *obj_desc = NULL;
	struct smw_storage_data_descriptor data_desc = { 0 };
	struct smw_keymgr_descriptor key_desc = { 0 };

	if (!descriptor || !descriptor->obj_desc)
		goto end;

	obj_desc = descriptor->obj_desc;
	obj_query.subsystem_id = SUBSYSTEM_ID_INVALID;

	switch (obj_desc->type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		obj_query.type = SMW_QUERY_TYPE_DATA;
		obj_query.data = &data_desc;
		data_desc.data_attributes = obj_desc->data.attributes;
		data_desc.pub = &obj_desc->data;
		break;
	default:
		obj_query.type = SMW_QUERY_TYPE_KEY;
		obj_query.key = &key_desc;
		key_desc.identifier = INIT_SMW_KEYMGR_IDENTIFIER;
		key_desc.identifier.s_id = obj_desc->key.id;
		key_desc.identifier.security_size = obj_desc->key.security_size;
		key_desc.identifier.key_attributes = obj_desc->key.attributes;
		key_desc.pub = &obj_desc->key;
		break;
	}

	if (util_object_query_subsystem(&obj_query, NULL, 0) != SMW_STATUS_OK)
		goto end;

	if (obj_query.type == SMW_QUERY_TYPE_KEY)
		key_identifier_to_object(&key_desc.identifier, obj_desc);

	status = 0;

end:
	return status;
}

int osal_zephyr_add_obj_info(struct smw_osal_object *descriptor)
{
	if (!descriptor || !descriptor->obj_desc)
		return -1;

	return 0;
}

int osal_zephyr_update_obj_info(struct smw_osal_object *descriptor)
{
	(void)descriptor;
	return 0;
}

int osal_zephyr_delete_obj_info(struct smw_osal_object *descriptor)
{
	(void)descriptor;
	return 0;
}

int osal_zephyr_find_obj_init(void **find_ctx,
			      struct smw_osal_object *descriptor)
{
	(void)find_ctx;
	(void)descriptor;
	return -1;
}

int osal_zephyr_find_obj_next(void *find_ctx,
			      struct smw_osal_object *descriptor)
{
	(void)find_ctx;
	(void)descriptor;
	return -1;
}

int osal_zephyr_find_obj_final(void *find_ctx)
{
	(void)find_ctx;
	return 0;
}

int osal_zephyr_db_has_capability(smw_osal_db_capability_t flag)
{
	(void)flag;
	return -1;
}
