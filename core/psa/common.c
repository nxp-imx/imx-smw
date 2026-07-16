// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024, 2026 NXP
 */

#include "smw_crypto.h"

#include "common.h"
#include "debug.h"
#include "subsystems.h"
#include "config.h"

#include "util_status.h"

static psa_status_t allocate_smw_context(smw_subsystem_t subsystem,
					 struct smw_op_context **smw_ctx)
{
	psa_status_t psa_status = PSA_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_context_args ctx_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx_args.subsystem_name = subsystem;
	smw_status = smw_allocate_context(&ctx_args);
	psa_status = util_smw_to_psa_status(smw_status);

	if (psa_status == PSA_SUCCESS)
		*smw_ctx = ctx_args.context;

	return psa_status;
}

smw_subsystem_t get_psa_default_subsystem(void)
{
	struct smw_config_psa_config config = { 0 };

	smw_config_get_psa_config(&config);

	return config.subsystem_name;
}

psa_status_t call_smw_api(enum smw_status_code (*api)(void *a), void *args,
			  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_config_psa_config config = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem_name || (*subsystem_name >= SMW_SUBSYSTEM_NAME_NB))
		goto end;

	smw_config_get_psa_config(&config);

	*subsystem_name = config.subsystem_name;

	status = api(args);
	if (config.alt &&
	    (status == SMW_STATUS_OPERATION_NOT_SUPPORTED ||
	     status == SMW_STATUS_OPERATION_NOT_CONFIGURED) &&
	    *subsystem_name) {
		*subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
		status = api(args);
	}

end:
	return util_smw_to_psa_status(status);
}

psa_status_t call_smw_api_no_fallback(enum smw_status_code (*api)(void *a),
				      void *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * The subsystem is imposed by the key or operation context. Call the
	 * API directly without overriding the subsystem name and without
	 * attempting any fallback.
	 */
	return util_smw_to_psa_status(api(args));
}

psa_status_t call_smw_api_init(enum smw_status_code (*api)(void *a), void *args,
			       struct smw_op_context **smw_ctx,
			       smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_config_psa_config config = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem_name || (*subsystem_name >= SMW_SUBSYSTEM_NAME_NB) ||
	    !smw_ctx)
		goto end;

	smw_config_get_psa_config(&config);

	*subsystem_name = config.subsystem_name;
	status = allocate_smw_context(*subsystem_name, smw_ctx);
	if (status != PSA_SUCCESS)
		goto end;

	status = api(args);
	if (config.alt &&
	    (status == SMW_STATUS_OPERATION_NOT_SUPPORTED ||
	     status == SMW_STATUS_OPERATION_NOT_CONFIGURED) &&
	    *subsystem_name) {
		*subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
		status = allocate_smw_context(*subsystem_name, smw_ctx);
		if (status == PSA_SUCCESS)
			status = api(args);
	}

end:
	return util_smw_to_psa_status(status);
}

psa_status_t call_smw_api_init_with_key(enum smw_status_code (*api)(void *a),
					void *args,
					struct smw_op_context **smw_ctx)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_ctx)
		goto end;

	/*
	 * The subsystem is imposed by the key already present in the
	 * subsystem. Allocate the context with no subsystem override and
	 * call the API directly without attempting any fallback.
	 */
	psa_status = allocate_smw_context(SMW_SUBSYSTEM_NAME_NONE, smw_ctx);
	if (psa_status == PSA_SUCCESS)
		psa_status = util_smw_to_psa_status(api(args));

end:
	return psa_status;
}
