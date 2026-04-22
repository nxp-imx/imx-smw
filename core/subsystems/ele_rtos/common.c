// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "compiler.h"
#include "smw_osal.h"

#include "config.h"
#include "debug.h"
#include "endian.h"
#include "utils.h"

#include "common.h"

__weak int ele_rng_init(struct hdl *hdl)
{
	return STATUS_SUCCESS;
}

__weak int ele_get_device_info(struct subsystem_context *ele_ctx)
{
	(void)ele_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int is_conversion_req(struct subsystem_context *ele_ctx,
			     enum smw_config_key_type_id type_id, bool *convert)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	*convert = false;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!info->edwards_be)
		goto end;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ED25519:
	case SMW_CONFIG_KEY_TYPE_ID_X25519:
	case SMW_CONFIG_KEY_TYPE_ID_ED448:
	case SMW_CONFIG_KEY_TYPE_ID_X448:
		SMW_DBG_PRINTF(VERBOSE, "%s conversion required\n", __func__);
		*convert = true;
		break;

	default:
		break;
	}

end:
	return status;
}

int check_and_convert_endian(struct subsystem_context *ele_ctx,
			     unsigned char *src, unsigned char **dst,
			     unsigned int size,
			     enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *out = NULL;
	bool convert = false;

	if (!src || size == 0)
		goto end;

	status = is_conversion_req(ele_ctx, type_id, &convert);
	if (status != SMW_STATUS_OK || !convert)
		goto end;

	if (dst) {
		*dst = SMW_UTILS_MALLOC(size);
		if (!*dst) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		out = *dst;
	}

	status = smw_utils_convert_endian(src, out, size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
