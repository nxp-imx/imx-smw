// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <tee_internal_api.h>
#include <tee_subsystem.h>

#include <libsmw_ta.h>

#include "keymgr.h"
#include "hash.h"
#include "sign_verify.h"
#include "mac.h"
#include "rng.h"
#include "cipher.h"
#include "operation_context.h"

TEE_Result libsmw_detach(void)
{
	TEE_Result res;

	res = clear_key_linked_list();
	if (res) {
		EMSG("Error 0x%" PRIx32 " while cleaning key linked list", res);
		res = TEE_ERROR_GENERIC;
	}

	return res;
}

TEE_Result libsmw_dispatcher(uint32_t cmd_id, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_NOT_IMPLEMENTED;

	FMSG("Executing %s", __func__);

	switch (cmd_id) {
	case CMD_GENERATE_KEY:
		res = generate_key(param_types, params);
		break;

	case CMD_DELETE_KEY:
		res = delete_key(param_types, params);
		break;

	case CMD_IMPORT_KEY:
		res = import_key(param_types, params);
		break;

	case CMD_EXPORT_KEY:
		res = export_key(param_types, params);
		break;

	case CMD_HASH:
		res = hash(param_types, params);
		break;

	case CMD_SIGN:
	case CMD_VERIFY:
		res = sign_verify(param_types, params, cmd_id);
		break;

	case CMD_HMAC:
	case CMD_MAC_COMPUTE:
		res = mac_compute(param_types, params);
		break;

	case CMD_MAC_VERIFY:
		res = mac_verify(param_types, params);
		break;

	case CMD_RNG:
		res = rng(param_types, params);
		break;

	case CMD_CIPHER_INIT:
		res = cipher_init(param_types, params);
		break;

	case CMD_CIPHER_UPDATE:
		res = cipher_update(param_types, params);
		break;

	case CMD_CIPHER_FINAL:
		res = cipher_final(param_types, params);
		break;

	case CMD_CANCEL_OP:
		res = cancel_operation(param_types, params);
		break;

	case CMD_COPY_CTX:
		res = copy_context(param_types, params);
		break;

	case CMD_GET_KEY_LENGTHS:
		res = get_key_lengths(param_types, params);
		break;

	case CMD_GET_KEY_ATTRIBUTES:
		res = get_key_attributes(param_types, params);
		break;

	default:
		break;
	}

	FMSG("%s command %u returned 0x%" PRIx32, __func__, cmd_id, res);

	return res;
}
