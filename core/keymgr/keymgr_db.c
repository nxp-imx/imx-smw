// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

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

	switch (obj->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
		break;
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
		break;
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;
		break;
	default:
		break;
	}

	identifier->security_size = obj->key.security_size;
	identifier->key_attributes = obj->key.attributes;
	if (SET_OVERFLOW(obj->group, identifier->group))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

static void key_identifier_to_object(unsigned int u_id,
				     struct smw_keymgr_identifier *identifier,
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

	obj->id = u_id;
	obj->key.id = u_id;

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

int smw_keymgr_db_create(unsigned int *u_id,
			 struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	struct smw_object_descriptor obj = { 0 };

	/*
	 * Create a key in database using the same id as the one define in
	 * by user. If id = 0, database will return an database id and
	 * subsystem will assign its own id.
	 */
	*u_id = identifier->s_id;

	key_identifier_to_object(*u_id, identifier, &obj);

	if (NXP_IS_EL2GO_OBJECT(identifier->key_attributes.storage_id))
		obj.label = KEY_DEFAULT_EL2GO_LABEL;
	else
		obj.label = KEY_DEFAULT_LABEL;

	status = smw_object_db_create(identifier->s_id, &obj);

	if (status == SMW_STATUS_OK)
		*u_id = obj.id;

	return status;
}

int smw_keymgr_db_update(unsigned int u_id,
			 struct smw_keymgr_identifier *identifier)
{
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	return smw_object_db_update(identifier->s_id, &obj);
}

int smw_keymgr_db_delete(unsigned int u_id,
			 struct smw_keymgr_identifier *identifier)
{
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	return smw_object_db_delete(&obj);
}

int smw_keymgr_db_get_info(unsigned int u_id,
			   struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_OK;
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	ret = smw_object_db_get_info(&identifier->s_id, &obj);
	if (ret == SMW_STATUS_OK) {
		switch (obj.type) {
		case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
			ret = object_to_key_identifier(&obj, identifier);
			break;

		default:
			ret = SMW_STATUS_UNKNOWN_ID;
			break;
		}
	}

	smw_object_db_clean_descriptor(&obj);

	return ret;
}
