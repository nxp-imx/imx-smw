/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2024, 2026 NXP
 */

#ifndef __COMMON__H__
#define __COMMON__H__

#include "smw/names.h"
#include "smw_status.h"

#include "psa/error.h"

#define SMW_API_CAST(name) ((enum smw_status_code(*)(void *))name)

#define BYTES_TO_BITS(size) ((size) << 3)

/**
 * get_psa_default_subsystem() - Get the default subsystem name invoked with PSA API.
 *
 * This function returns the name of the default subsystem to be invoked
 * with the PSA API.
 *
 * Return:
 * The default subsystem name invoked with PSA API.
 */
smw_subsystem_t get_psa_default_subsystem(void);

/**
 * call_smw_api() - Call SMW API.
 * @api: SMW API.
 * @args: Arguments of the SMW API.
 * @subsystem_name: Pointer to the subsystem name in the arguments structure.
 *
 * This function sets the subsystem to be invoked in the arguments structure
 * as the PSA default subsystem, and then calls the SMW API.
 * If the operation is not supported and the subsystem fallback mechanism is configured,
 * the SMW API is called another time and invokes the default subsystem configured
 * for the operation.
 *
 * Return:
 * PSA error code.
 */
psa_status_t call_smw_api(enum smw_status_code (*api)(void *a), void *args,
			  smw_subsystem_t *subsystem_name);

/**
 * call_smw_api_no_fallback() - Call SMW API for an operation depending on a
 *                              key or context.
 * @api: SMW API.
 * @args: Arguments of the SMW API.
 *
 * This function calls the SMW API directly without overriding the subsystem
 * name in the arguments structure and without attempting any fallback.
 * It is intended for operations that depend on a key already present in the
 * subsystem or an operation context, the subsystem is imposed by the key or
 * context itself.
 *
 * Return:
 * PSA error code.
 */
psa_status_t call_smw_api_no_fallback(enum smw_status_code (*api)(void *a),
				      void *args);

/**
 * call_smw_api_init() - Call SMW API multipart initialization.
 * @api: SMW API.
 * @args: Arguments of the SMW API.
 * @smw_ctx: SMW context allocated if initialization success.
 * @subsystem_name: Pointer to the subsystem name in the arguments structure.
 *
 * This function sets the subsystem to be invoked in the arguments structure
 * as the PSA default subsystem, and then calls the SMW API.
 *
 * As multipart initialization, the operation context is first allocated.
 *
 * If the operation is not supported and the subsystem fallback mechanism is
 * configured, the SMW API is called another time and invokes the default
 * subsystem configured for the operation. In this case previous operation
 * context is freed by SMW API and so this function allocates another
 * operation context.
 *
 * The caller is in charge of saving the @smw_ctx in the PSA operation context.
 *
 * Return:
 * PSA error code.
 */
psa_status_t call_smw_api_init(enum smw_status_code (*api)(void *a), void *args,
			       struct smw_op_context **smw_ctx,
			       smw_subsystem_t *subsystem_name);

/**
 * call_smw_api_init_with_key() - Call SMW API multipart init for a key operation.
 * @api: SMW API.
 * @args: Arguments of the SMW API.
 * @smw_ctx: SMW context allocated if initialization success.
 *
 * This function allocates the operation context and calls the SMW API directly
 * without overriding the subsystem name in the arguments structure and without
 * attempting any fallback.
 * It is intended for multipart operations that depend on a key already present
 * in the subsystem; the subsystem is imposed by the key itself.
 *
 * The caller is in charge of saving the @smw_ctx in the PSA operation context.
 *
 * Return:
 * PSA error code.
 */
psa_status_t call_smw_api_init_with_key(enum smw_status_code (*api)(void *a),
					void *args,
					struct smw_op_context **smw_ctx);

#endif /* __COMMON__H__ */
