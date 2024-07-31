// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_status.h"

#include "config.h"
#include "debug.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_CONFIG_AEAD_MODE_ID_OFFSET                                         \
	(SMW_AEAD_MODE_NAME_CCM - SMW_CONFIG_AEAD_MODE_ID_CCM)

#define SMW_CONFIG_AEAD_OP_TYPE_OFFSET                                         \
	(SMW_AEAD_OP_TYPE_NAME_ENCRYPT - SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)

int smw_utils_get_aead_mode_id(smw_aead_mode_t name,
			       enum smw_config_aead_mode_id *id)
{
	int status = SMW_STATUS_UNKNOWN_MODE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_AEAD_MODE_NAME_NONE) {
		*id = SMW_CONFIG_AEAD_MODE_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_AEAD_MODE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_AEAD_MODE_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_get_aead_op_type_id(smw_aead_op_type_t name,
				  enum smw_config_aead_op_type_id *id)
{
	int status = SMW_STATUS_UNKNOWN_OP_TYPE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_AEAD_OP_TYPE_NAME_NONE) {
		*id = SMW_CONFIG_AEAD_OP_TYPE_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_AEAD_OP_TYPE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_AEAD_OP_TYPE_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
