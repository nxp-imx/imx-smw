// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "keymgr.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */
#define SMW_CONFIG_KEY_TYPE_ID_OFFSET                                          \
	(SMW_KEY_TYPE_NAME_SECP_R1 - SMW_CONFIG_KEY_TYPE_ID_SECP_R1)

#define SMW_CONFIG_KDF_ID_OFFSET (SMW_KDF_NAME_HKDF - SMW_CONFIG_KDF_ID_HKDF)

__export int smw_config_get_key_type_id(smw_key_type_t name,
					enum smw_config_key_type_id *id)
{
	int status = SMW_STATUS_UNKNOWN_KEY_TYPE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KEY_TYPE_NAME_NONE) {
		*id = SMW_CONFIG_KEY_TYPE_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KEY_TYPE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_KEY_TYPE_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export smw_key_type_t
smw_config_get_key_type_name(enum smw_config_key_type_id id)
{
	smw_key_type_t name = SMW_KEY_TYPE_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_CONFIG_KEY_TYPE_ID_NB &&
	    id != SMW_CONFIG_KEY_TYPE_ID_INVALID)
		(void)ADD_OVERFLOW(id, SMW_CONFIG_KEY_TYPE_ID_OFFSET,
				   (int *)&name);

	return name;
}

__export int smw_config_get_kdf_id(smw_kdf_t name, enum smw_config_kdf_id *id)
{
	int status = SMW_STATUS_UNKNOWN_KDF_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KDF_NAME_NONE) {
		*id = SMW_CONFIG_KDF_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KDF_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_KDF_ID_OFFSET, (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
