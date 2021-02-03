// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "exec.h"

static int
sign_verify_convert_args(struct smw_sign_verify_args *args,
			 struct smw_crypto_sign_verify_args *converted_args,
			 enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_get_hash_algo_id(args->algo_name,
					     &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->hashed = args->hashed;
	converted_args->message = args->message;
	converted_args->message_length = args->message_length;
	converted_args->signature = args->signature;
	converted_args->signature_length = args->signature_length;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int smw_sign_verify(enum operation_id operation_id,
			   struct smw_sign_verify_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_args sign_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = sign_verify_convert_args(args, &sign_verify_args,
					  &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(operation_id, &sign_verify_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_sign(struct smw_sign_verify_args *args)
{
	return smw_sign_verify(OPERATION_ID_SIGN, args);
}

int smw_verify(struct smw_sign_verify_args *args)
{
	return smw_sign_verify(OPERATION_ID_VERIFY, args);
}
