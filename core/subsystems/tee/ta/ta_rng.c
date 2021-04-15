// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>

#include "ta_rng.h"

TEE_Result rng(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Random number buffer
	 */
	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_GenerateRandom(params[0].memref.buffer, params[0].memref.size);

	return TEE_SUCCESS;
}
