// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <inttypes.h>

#include "smw_status.h"
#include "smw_keymgr.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "keymgr_attest.h"
#include "sign_verify.h"
#include "exec.h"

static int
key_attestation_convert_attributes(smw_attr_algo_t in,
				   struct smw_sign_verify_attributes *out)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Signature attributes: 0x%" PRIx64 "\n", in);

	if (SMW_ATTR_GET_CLASS(in) != SMW_ATTR_CLASS_KEY_ATTESTATION)
		goto end;

	status = smw_utils_sign_attr_to_ids(in, &out->algo_id, &out->type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_hash_attr_to_algo_id(in, &out->hash_id);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
key_attestation_convert_args(struct smw_key_attestation_args *args,
			     struct smw_keymgr_attest_args *conv_args,
			     enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	bool new_key = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &conv_args->key_descriptor,
					       &new_key, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	new_key = false;
	status =
		smw_keymgr_convert_descriptor(args->attest_key_descriptor,
					      &conv_args->attest_key_descriptor,
					      &new_key, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status =
		key_attestation_convert_attributes(args->sign_algo,
						   &conv_args->sign_attributes);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_keymgr_get_attest_chal(struct smw_keymgr_attest_args *args)
{
	unsigned char *challenge = NULL;

	if (args->pub)
		challenge = args->pub->challenge;

	return challenge;
}

unsigned int
smw_keymgr_get_attest_chal_length(struct smw_keymgr_attest_args *args)
{
	unsigned int challenge_length = 0;

	if (args->pub)
		challenge_length = args->pub->challenge_length;

	return challenge_length;
}

unsigned char *smw_keymgr_get_attest_cert(struct smw_keymgr_attest_args *args)
{
	unsigned char *certificate = NULL;

	if (args->pub)
		certificate = args->pub->certificate;

	return certificate;
}

unsigned int
smw_keymgr_get_attest_cert_length(struct smw_keymgr_attest_args *args)
{
	unsigned int certificate_length = 0;

	if (args->pub)
		certificate_length = args->pub->certificate_length;

	return certificate_length;
}

void smw_keymgr_set_attest_cert_length(struct smw_keymgr_attest_args *args,
				       unsigned int length)
{
	if (args->pub)
		args->pub->certificate_length = length;
}

enum smw_status_code smw_key_attestation(struct smw_key_attestation_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_attest_args attest_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->key_descriptor || !args->attest_key_descriptor ||
	    !args->key_descriptor->id || !args->attest_key_descriptor->id)
		goto end;

	if (!args->challenge != !args->challenge_length)
		goto end;

	if (!args->certificate != !args->certificate_length)
		goto end;

	if (args->certificate && !args->challenge)
		goto end;

	status =
		key_attestation_convert_args(args, &attest_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_implicit(OPERATION_ID_KEY_ATTESTATION,
					    &attest_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
