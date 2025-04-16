// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <inttypes.h>

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "asymmetric_encryption.h"

static int
asymm_encrypt_convert_attributes(smw_attr_algo_t in,
				 struct smw_asymmetric_encryption_attrs *out)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG,
		       "Asymmetric encryption attributes: 0x%" PRIx64 "\n", in);

	if (SMW_ATTR_GET_CLASS(in) != SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION)
		goto end;

	status = smw_utils_asymm_enc_attr_to_ids(in, &out->algo_id,
						 &out->mode_id, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_hash_attr_to_algo_id(in, &out->hash_id);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_key() - Check key configuration
 * @args: Pointer to internal asymmetric encryption arguments structure.
 * @subsystem_id: Subsystem ID.
 *
 * This function checks that:
 * - Key is defined as buffer or as key ID
 * - Key is linked to @subsystem_id
 *
 * Return:
 * SMW_STATUS_OK		    - Success
 * SMW_STATUS_INVALID_PARAM	- Bad key configuration
 */
static int check_key(struct smw_crypto_asymm_enc_args *args,
		     enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Key ID or key buffer must be set */
	if (!args->key_desc.identifier.id && !args->key_desc.pub->buffer)
		goto end;

	/*
	 * If key is defined as buffer security size and key type must
	 * be set.
	 */
	if (args->key_desc.pub->buffer &&
	    (args->key_desc.pub->type_name == SMW_KEY_TYPE_NAME_NONE ||
	     !args->key_desc.pub->security_size))
		goto end;

	if (args->key_desc.identifier.id &&
	    args->key_desc.identifier.subsystem_id != subsystem_id)
		goto end;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
asymm_encrypt_convert_args(struct smw_asymmetric_encryption_args *args,
			   struct smw_crypto_asymm_enc_args *converted_args,
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
					       &converted_args->key_desc, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = asymm_encrypt_convert_attributes(args->algo,
						  &converted_args->attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static enum smw_status_code
smw_asymmetric_encrypt_decrypt(enum operation_id operation_id,
			       struct smw_asymmetric_encryption_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_asymm_enc_args asymm_enc_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->input || !args->input_length ||
	    !args->key_descriptor || (args->output && !args->output_length) ||
	    (operation_id == OPERATION_ID_ASYMM_DECRYPT && !args->output))
		goto end;

	status = asymm_encrypt_convert_args(args, &asymm_enc_args,
					    &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_key(&asymm_enc_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(operation_id, &asymm_enc_args,
					     subsystem_id);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeeds and must be converted to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->output)
		status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *
smw_crypto_get_asymm_enc_input(struct smw_crypto_asymm_enc_args *args)
{
	unsigned char *input = NULL;

	if (args && args->pub)
		input = args->pub->input;

	return input;
}

inline unsigned int
smw_crypto_get_asymm_enc_input_len(struct smw_crypto_asymm_enc_args *args)
{
	unsigned int length = 0;

	if (args && args->pub)
		length = args->pub->input_length;

	return length;
}

inline unsigned char *
smw_crypto_get_asymm_enc_output(struct smw_crypto_asymm_enc_args *args)
{
	unsigned char *output = NULL;

	if (args && args->pub)
		output = args->pub->output;

	return output;
}

inline unsigned int
smw_crypto_get_asymm_enc_output_len(struct smw_crypto_asymm_enc_args *args)
{
	unsigned int length = 0;

	if (args && args->pub)
		length = args->pub->output_length;

	return length;
}

inline unsigned char *
smw_crypto_get_asymm_enc_salt(struct smw_crypto_asymm_enc_args *args)
{
	unsigned char *salt = NULL;

	if (args && args->pub)
		salt = args->pub->salt;

	return salt;
}

inline unsigned int
smw_crypto_get_asymm_enc_salt_len(struct smw_crypto_asymm_enc_args *args)
{
	unsigned int salt_length = 0;

	if (args && args->pub)
		salt_length = args->pub->salt_length;

	return salt_length;
}

inline void
smw_crypto_set_asymm_enc_output_len(struct smw_crypto_asymm_enc_args *args,
				    unsigned int len)
{
	if (args && args->pub)
		args->pub->output_length = len;
}

enum smw_status_code
smw_asymmetric_encrypt(struct smw_asymmetric_encryption_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return smw_asymmetric_encrypt_decrypt(OPERATION_ID_ASYMM_ENCRYPT, args);
}

enum smw_status_code
smw_asymmetric_decrypt(struct smw_asymmetric_encryption_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return smw_asymmetric_encrypt_decrypt(OPERATION_ID_ASYMM_DECRYPT, args);
}
