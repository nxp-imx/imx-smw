// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#include <zephyr/device.h>

#include "fsl_common.h"

/**
 * osal_get_mu_base() - Initialize MU
 *
 * This function initializes the MU peripheral for communication with EdgeLock Enclave.
 * This function needs to be called at least once before using the MU communication functions.
 *
 * Return:
 * MU base address.
 */
void *osal_get_mu_base(void)
{
	/* Map S3MU address space for ELE communication */
	mm_reg_t regmap = 0;
	uintptr_t mu_base = MU_APPS__S3MUA_BASE;

	device_map(&regmap, mu_base, sizeof(S3MU_Type),
		   K_MEM_CACHE_NONE | K_MEM_DIRECT_MAP);

	return (void *)regmap;
}
