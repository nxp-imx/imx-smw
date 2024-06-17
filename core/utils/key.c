// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "debug.h"
#include "key.h"

#define FORMAT_ID_ASSERT(id)                                                   \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SMW_KEYMGR_FORMAT_ID_NB) &&              \
			       (_id != SMW_KEYMGR_FORMAT_ID_INVALID));         \
	} while (0)

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

static const char *const format_names[] = { [SMW_KEYMGR_FORMAT_ID_HEX] = "HEX",
					    [SMW_KEYMGR_FORMAT_ID_BASE64] =
						    "BASE64" };

int smw_keymgr_get_key_format_id(const char *name,
				 enum smw_keymgr_format_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_KEYMGR_FORMAT_ID_DEFAULT;
	else
		status =
			smw_utils_get_string_index(name, format_names,
						   SMW_KEYMGR_FORMAT_ID_NB, id);

	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_FORMAT_NAME;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

const char *smw_keymgr_get_key_format_name(enum smw_keymgr_format_id format_id)
{
	unsigned int index;

	FORMAT_ID_ASSERT(format_id);

	index = format_id;

	return format_names[index];
}
