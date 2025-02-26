// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "utils.h"
#include "keymgr.h"
#include "object_db.h"

static int object_to_key_identifier(struct smw_object_descriptor *obj,
				    struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	status = smw_config_get_subsystem_id(obj->subsystem_name,
					     &identifier->subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(obj->key.type_name,
					    &identifier->type_id);
	if (status != SMW_STATUS_OK)
		return status;

	identifier->security_size = obj->key.security_size;
	identifier->id = obj->key.id;
	identifier->attributes = obj->attributes;
	if (SET_OVERFLOW(obj->group, identifier->group))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

static void key_identifier_to_object(struct smw_keymgr_identifier *identifier,
				     struct smw_object_descriptor *obj)
{
	int status = SMW_STATUS_OK;
	enum smw_keymgr_privacy_id privacy = identifier->privacy_id;

	if (privacy == SMW_KEYMGR_PRIVACY_ID_INVALID) {
		status = smw_keymgr_get_privacy_id(identifier->type_id,
						   &privacy);
		if (status != SMW_STATUS_OK)
			return;
	}

	switch (privacy) {
	case SMW_KEYMGR_PRIVACY_ID_PAIR:
		obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		break;
	case SMW_KEYMGR_PRIVACY_ID_PUBLIC:
		obj->type = SMW_OBJECT_TYPE_NAME_PUBLIC_KEY;
		break;
	case SMW_KEYMGR_PRIVACY_ID_PRIVATE:
	case SMW_KEYMGR_PRIVACY_ID_SHARED_SECRET:
		obj->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;
	default:
		break;
	}

	obj->attributes = identifier->attributes;
	obj->subsystem_name =
		smw_config_get_subsystem_name(identifier->subsystem_id);
	obj->key.type_name = smw_config_get_key_type_name(identifier->type_id);
	obj->key.security_size = identifier->security_size;
	obj->key.id = identifier->id;
	obj->group = identifier->group;
}

int smw_keymgr_db_create(unsigned int *id,
			 struct smw_keymgr_identifier *identifier)
{
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(identifier, &obj);

	*id = identifier->id;

	if (NXP_IS_EL2GO_OBJECT(identifier->storage_id))
		obj.label = KEY_DEFAULT_EL2GO_LABEL;
	else
		obj.label = KEY_DEFAULT_LABEL;

	return smw_object_db_create(id, identifier->attributes, &obj);
}

int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(identifier, &obj);

	return smw_object_db_update(id, identifier->attributes, &obj);
}

int smw_keymgr_db_delete(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	return smw_object_db_delete(id, identifier->attributes);
}

int smw_keymgr_db_get_info(unsigned int id,
			   struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_OK;
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(identifier, &obj);

	ret = smw_object_db_get_info(id, identifier->attributes, &obj);
	if (ret == SMW_STATUS_OK)
		ret = object_to_key_identifier(&obj, identifier);

	if (obj.label)
		free(obj.label);

	return ret;
}
