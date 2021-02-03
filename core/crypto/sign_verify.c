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
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto end;

	status = smw_config_get_hash_algo_id(args->algo_name,
					     &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *
smw_sign_verify_get_msg_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *message_buffer = NULL;

	if (args->pub)
		message_buffer = args->pub->message;

	return message_buffer;
}

inline unsigned int
smw_sign_verify_get_msg_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int message_length = 0;

	if (args->pub)
		message_length = args->pub->message_length;

	return message_length;
}

inline unsigned char *
smw_sign_verify_get_sign_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *signature_buffer = NULL;

	if (args->pub)
		signature_buffer = args->pub->signature;

	return signature_buffer;
}

inline unsigned int
smw_sign_verify_get_sign_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int signature_length = 0;

	if (args->pub)
		signature_length = args->pub->signature_length;

	return signature_length;
}

inline void
smw_sign_verify_copy_sign_buf(struct smw_crypto_sign_verify_args *args,
			      unsigned char *signature,
			      unsigned int signature_length)
{
	if (args->pub && args->pub->signature_length >= signature_length) {
		SMW_UTILS_MEMCPY(args->pub->signature, signature,
				 signature_length);
	}
}

inline void
smw_sign_verify_set_sign_len(struct smw_crypto_sign_verify_args *args,
			     unsigned int signature_length)
{
	if (args->pub)
		args->pub->signature_length = signature_length;
}

static int smw_sign_verify(enum operation_id operation_id,
			   struct smw_sign_verify_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_verify_args sign_verify_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->message || !args->message_length ||
	    !args->signature || !args->signature_length) {
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
