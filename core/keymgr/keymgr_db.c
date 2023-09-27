// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
	SMW_UTILS_MEMCPY(&info, identifier, sizeof(*identifier));

	return smw_object_db_create(id, identifier->persistence_id, &info);
}

int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	union smw_object_db_info info = { 0 };

	SMW_UTILS_MEMCPY(&info, identifier, sizeof(*identifier));

	return smw_object_db_update(id, identifier->persistence_id, &info);
}

int smw_keymgr_db_delete(unsigned int id,
			 struct smw_keymgr_identifier *identifier)

{
	return smw_object_db_delete(id, identifier->persistence_id);
}

int smw_keymgr_db_get_info(unsigned int id,
			   struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_OK;
	union smw_object_db_info info = { 0 };

	ret = smw_object_db_get_info(id, identifier->persistence_id, &info);

	if (ret == SMW_STATUS_OK)
		SMW_UTILS_MEMCPY(identifier, &info, sizeof(*identifier));

	return ret;
}
