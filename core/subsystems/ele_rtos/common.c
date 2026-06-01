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

#define HASH_ALGO(_id, _ele_id, _length)                                       \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.ele_algo = ELE_##_ele_id, .length = _length                   \
	}

/*
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf table 4
 * gives the digest length corresponding to the security strenghs.
 * In case of SHAKE256, the minimum security strengh is 256 bits requesting
 * 512 bits for the digest length.
 */
static const struct ele_hash_algo hash_algos[] = {
	HASH_ALGO(MD5, MD5, 16),	   HASH_ALGO(SHA1, SHA_1, 20),
	HASH_ALGO(SHA224, SHA_224, 28),	   HASH_ALGO(SHA256, SHA_256, 32),
	HASH_ALGO(SHA384, SHA_384, 48),	   HASH_ALGO(SHA512, SHA_512, 64),
	HASH_ALGO(SHA3_224, SHA3_224, 28), HASH_ALGO(SHA3_256, SHA3_256, 32),
	HASH_ALGO(SHA3_384, SHA3_384, 48), HASH_ALGO(SHA3_512, SHA3_512, 64),
	HASH_ALGO(SM3, SM3_256, 32),	   HASH_ALGO(SHAKE256, SHAKE_256, 64)
};

const struct ele_hash_algo *
ele_get_hash_algo(enum smw_config_hash_algo_id algo_id)
{
	const struct ele_hash_algo *hash_algo = NULL;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algos[i].algo_id == algo_id) {
			hash_algo = &hash_algos[i];
			break;
		}
	}

	return hash_algo;
}

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
