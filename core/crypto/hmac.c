// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "debug.h"

enum smw_status_code smw_hmac(struct smw_hmac_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_mac_args api_mac_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args) {
		api_mac_args.version = args->version;
		api_mac_args.subsystem_name = args->subsystem_name;
		api_mac_args.key_descriptor = args->key_descriptor;
		api_mac_args.algo_name = "HMAC";
		api_mac_args.hash_name = args->algo_name;
		api_mac_args.input = args->input;
		api_mac_args.input_length = args->input_length;
		api_mac_args.mac = args->output;
		api_mac_args.mac_length = args->output_length;

		status = smw_mac(&api_mac_args);

		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			args->output_length = api_mac_args.mac_length;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
