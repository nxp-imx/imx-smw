// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include "smw_status.h"

#include "utils.h"
#include "keymgr.h"
#include "object_db.h"

int smw_keymgr_db_create(unsigned int *id,
			 struct smw_keymgr_identifier *identifier)
{
	union smw_object_db_info info = { 0 };

	*id = identifier->id;
	info.key_identifier = *identifier;

	return smw_object_db_create(id, identifier->attributes, &info);
}

int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	union smw_object_db_info info = { 0 };

	info.key_identifier = *identifier;

	return smw_object_db_update(id, identifier->attributes, &info);
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
		*identifier = info.key_identifier;

	return ret;
}
