// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#include "smw_status.h"

#include "aead.h"
#include "config.h"
#include "debug.h"

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

int smw_utils_get_aead_input_data_len(struct smw_crypto_aead_args *args,
				      unsigned int *input_data_length)
{
	int status = SMW_STATUS_OK;

	*input_data_length = smw_crypto_get_aead_input_len(args);

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT &&
	    (args->op_step == SMW_OP_STEP_ONESHOT ||
	     args->op_step == SMW_OP_STEP_FINAL)) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(*input_data_length,
					 smw_crypto_get_aead_tag_len(args)))
				status = SMW_STATUS_INVALID_PARAM;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with input data length = %u\n",
		       __func__, *input_data_length);
	return status;
}

int smw_utils_get_aead_output_data_len(struct smw_crypto_aead_args *args,
				       unsigned int *output_data_length)
{
	int status = SMW_STATUS_OK;
	unsigned int input_data_length = 0;

	*output_data_length = smw_crypto_get_aead_output_len(args);
	input_data_length = smw_crypto_get_aead_input_len(args);

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT &&
	    (args->op_step == SMW_OP_STEP_ONESHOT ||
	     args->op_step == SMW_OP_STEP_FINAL)) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(*output_data_length,
					 smw_crypto_get_aead_tag_len(args)))
				status = SMW_STATUS_OUTPUT_TOO_SHORT;

			if (args->op_step == SMW_OP_STEP_ONESHOT &&
			    *output_data_length > input_data_length)
				*output_data_length = input_data_length;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with output data length = %u\n",
		       __func__, *output_data_length);

	return status;
}
