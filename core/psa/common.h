/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __COMMON__H__
#define __COMMON__H__

#include "smw_status.h"
#include "smw_strings.h"

#include "psa/error.h"

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

#endif /* __COMMON__H__ */
