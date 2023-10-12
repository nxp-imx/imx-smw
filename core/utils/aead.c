// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "config.h"
#include "debug.h"
#include "name.h"

static const char *const aead_mode_names[] = { [SMW_CONFIG_AEAD_MODE_ID_CCM] =
						       "CCM",
					       [SMW_CONFIG_AEAD_MODE_ID_GCM] =
						       "GCM" };

static const char *const aead_op_type_names[] = {
	[SMW_CONFIG_AEAD_OP_ID_ENCRYPT] = "ENCRYPT",
	[SMW_CONFIG_AEAD_OP_ID_DECRYPT] = "DECRYPT"
};

int smw_utils_aead_op_type_names(char **start, char *end, unsigned long *bitmap)
{
	return smw_config_read_names(start, end, bitmap, aead_op_type_names,
				     SMW_CONFIG_AEAD_OP_ID_NB);
}

int smw_utils_aead_mode_names(char **start, char *end, unsigned long *bitmap)
{
	return smw_config_read_names(start, end, bitmap, aead_mode_names,
				     SMW_CONFIG_AEAD_MODE_ID_NB);
}

int smw_utils_get_aead_mode_id(const char *name,
			       enum smw_config_aead_mode_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_AEAD_MODE_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, aead_mode_names,
						    SMW_CONFIG_AEAD_MODE_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_get_aead_op_type_id(const char *name,
				  enum smw_config_aead_op_type_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_AEAD_OP_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, aead_op_type_names,
						    SMW_CONFIG_AEAD_OP_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
