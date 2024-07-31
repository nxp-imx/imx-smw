// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "debug.h"
#include "key.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_KEY_FORMAT_ID_OFFSET                                               \
	(SMW_KEY_FORMAT_NAME_HEX - SMW_KEYMGR_FORMAT_ID_HEX)

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

int smw_keymgr_get_key_format_id(smw_key_format_t name,
				 enum smw_keymgr_format_id *id)
{
	int status = SMW_STATUS_UNKNOWN_FORMAT_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KEY_FORMAT_NAME_NONE) {
		*id = SMW_KEYMGR_FORMAT_ID_DEFAULT;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KEY_FORMAT_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_KEY_FORMAT_ID_OFFSET, (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

smw_key_format_t smw_keymgr_get_key_format_name(enum smw_keymgr_format_id id)
{
	smw_key_format_t name = SMW_KEY_FORMAT_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_KEYMGR_FORMAT_ID_NB && id != SMW_KEYMGR_FORMAT_ID_INVALID)
		(void)ADD_OVERFLOW(id, SMW_KEY_FORMAT_ID_OFFSET, (int *)&name);

	return name;
}
