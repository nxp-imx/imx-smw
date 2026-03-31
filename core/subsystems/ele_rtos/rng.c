// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "common.h"

#include "ele_rng.h"

int ele_rng_init(struct hdl *hdl)
{
	status_t err = kStatus_Success;
	uint32_t trng_state = 0u;

	err = ele_start_rng(hdl->mu_base);
	if (err != kStatus_Success)
		goto end;

	do {
		err = ele_get_trng_state(hdl->mu_base, &trng_state);
	} while (((trng_state & 0xFFu) != kELE_TRNG_ready) &&
		 ((trng_state & 0xFF00u) != kELE_TRNG_CSAL_success << 8u) &&
		 err == kStatus_Success);

end:
	return err;
}
