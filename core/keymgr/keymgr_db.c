// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include "smw_status.h"

#include "utils.h"
#include "keymgr.h"
#include "object_db.h"

static int key_info_to_identifier(struct smw_keymgr_key_info *key_info,
				  struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	status = smw_config_get_subsystem_id(key_info->subsystem_name,
					     &identifier->subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(key_info->type_name,
					    &identifier->type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_keymgr_get_key_privacy_id(key_info->privacy_name,
					       &identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		return status;

	identifier->security_size = key_info->security_size;
	identifier->id = key_info->id;
	identifier->attributes = key_info->attributes;
	identifier->storage_id = key_info->storage_id;
	identifier->group = key_info->group;

	return status;
}

static void key_identifier_to_info(struct smw_keymgr_identifier *identifier,
				   struct smw_keymgr_key_info *key_info)
{
	key_info->subsystem_name =
		smw_config_get_subsystem_name(identifier->subsystem_id);
	key_info->type_name = smw_config_get_key_type_name(identifier->type_id);
	key_info->privacy_name =
		smw_keymgr_get_key_privacy_name(identifier->privacy_id);
	key_info->security_size = identifier->security_size;
	key_info->id = identifier->id;
	key_info->attributes = identifier->attributes;
	key_info->storage_id = identifier->storage_id;
	key_info->group = identifier->group;
}

int smw_keymgr_db_create(unsigned int *id,
			 struct smw_keymgr_identifier *identifier)
{
	union smw_object_db_info info = { 0 };

	key_identifier_to_info(identifier, &info.key_info);

	*id = info.key_info.id;

	return smw_object_db_create(id, info.key_info.attributes, &info);
}

int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	union smw_object_db_info info = { 0 };

	key_identifier_to_info(identifier, &info.key_info);

	return smw_object_db_update(id, info.key_info.attributes, &info);
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
	union smw_object_db_info info = { 0 };

	ret = smw_object_db_get_info(id, identifier->attributes, &info);

	if (ret == SMW_STATUS_OK)
		ret = key_info_to_identifier(&info.key_info, identifier);

	return ret;
}
