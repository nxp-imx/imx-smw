// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"
#include "cipher.h"
#include "utils.h"
#include "storage.h"

#include "common.h"

static int get_mac_algo(struct smw_storage_sign_args *args,
			unsigned int *ele_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	switch (args->algo_id) {
	case SMW_CONFIG_MAC_ALGO_ID_CMAC:
		*ele_id = PERMITTED_ALGO_CMAC;
		status = SMW_STATUS_OK;
		break;

	default:
		break;
	}

	return status;
}

static int store_data_raw(struct hdl *hdl,
			  struct smw_storage_store_data_args *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_data_storage_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.data_id =
		smw_storage_get_data_identifier(&args->data_descriptor);
	op_args.data = smw_storage_get_data(&args->data_descriptor);
	op_args.data_size = smw_storage_get_data_length(&args->data_descriptor);
	op_args.flags = HSM_OP_DATA_STORAGE_FLAGS_STORE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_data_ops()\n"
		       "  op_data_storage_args_t\n"
		       "    Data\n"
		       "      - id: %d\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    flags: 0x%X\n",
		       __func__, __LINE__, op_args.data_id, op_args.data,
		       op_args.data_size, op_args.flags);

	err = hsm_data_ops(hdl->key_store, &op_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_data_ops returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_data_encrypted(struct subsystem_context *ele_ctx,
				struct smw_storage_store_data_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_err_t err = HSM_NO_ERROR;

	op_enc_data_storage_args_t op_args = { 0 };
	struct smw_storage_data_descriptor *data_descriptor =
		&args->data_descriptor;
	struct smw_storage_enc_args *enc_args = &args->enc_args;
	struct smw_storage_sign_args *sign_args = &args->sign_args;
	struct smw_keymgr_identifier *key_identifier =
		&enc_args->keys_desc[0]->identifier;
	unsigned long lifecycle_flags =
		data_descriptor->attributes.lifecycle_flags;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.data_id = smw_storage_get_data_identifier(data_descriptor);
	op_args.data = smw_storage_get_data(data_descriptor);
	op_args.data_size = smw_storage_get_data_length(data_descriptor);
	op_args.iv = smw_storage_get_iv(enc_args);

	if (SET_OVERFLOW(smw_storage_get_iv_length(enc_args), op_args.iv_size))
		goto end;

	if (smw_crypto_cipher_iv_required(args->enc_args.mode_id) &&
	    !op_args.iv && !op_args.iv_size)
		op_args.flags |= HSM_OP_ENC_DATA_STORAGE_FLAGS_RANDOM_IV;

	if (data_descriptor->attributes.rw_flags & SMW_STORAGE_READ_ONCE)
		op_args.flags |= HSM_OP_ENC_DATA_STORAGE_FLAGS_READ_ONCE;

	op_args.enc_key_id = key_identifier->id;

	status = ele_set_cipher_algo(key_identifier->type_id, enc_args->mode_id,
				     &op_args.enc_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier = &sign_args->key_descriptor.identifier;
	op_args.sign_key_id = key_identifier->id;

	status = get_mac_algo(sign_args, &op_args.sign_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	status = ele_set_lifecycle_flags(ele_ctx, lifecycle_flags,
					 &op_args.lifecycle);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_enc_data_ops()\n"
		       "  op_enc_data_storage_args_t\n"
		       "    Data\n"
		       "      - id: 0x%08X\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    IV\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Encryption\n"
		       "      - Key ID: 0x%08X\n"
		       "      - Algorithm: 0x%08X\n"
		       "    Signature\n"
		       "      - Key ID: 0x%08X\n"
		       "      - Algorithm: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    lifecyle: 0x%04X\n",
		       __func__, __LINE__, op_args.data_id, op_args.data,
		       op_args.data_size, op_args.iv, op_args.iv_size,
		       op_args.enc_key_id, op_args.enc_algo,
		       op_args.sign_key_id, op_args.sign_algo, op_args.flags,
		       op_args.lifecycle);

	err = hsm_enc_data_ops(ele_ctx->hdl.key_store, &op_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_enc_data_ops returned %d\n", err);

	status = ele_convert_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int storage_store(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_store_data_args *store_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (store_args->enc_args.mode_id == SMW_CONFIG_CIPHER_MODE_ID_INVALID &&
	    store_args->sign_args.algo_id == SMW_CONFIG_MAC_ALGO_ID_INVALID) {
		status = store_data_raw(&ele_ctx->hdl, args);
	} else {
		status = store_data_encrypted(ele_ctx, args);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int storage_retrieve(struct hdl *hdl,
			    struct smw_storage_retrieve_data_args *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_data_storage_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.data_id =
		smw_storage_get_data_identifier(&args->data_descriptor);
	op_args.data = smw_storage_get_data(&args->data_descriptor);
	op_args.data_size = smw_storage_get_data_length(&args->data_descriptor);
	op_args.flags = HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_data_ops()\n"
		       "  op_data_storage_args_t\n"
		       "    Data\n"
		       "      - id: %d\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    flags: 0x%X\n"
		       "    svc_flags: 0x%X\n",
		       __func__, __LINE__, op_args.data_id, op_args.data,
		       op_args.data_size, op_args.flags, op_args.svc_flags);

	err = hsm_data_ops(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_data_ops returned %d\n", err);

	status = ele_convert_err(err);

	smw_storage_set_data_length(&args->data_descriptor,
				    op_args.exp_output_size);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_storage_handle(struct subsystem_context *ele_ctx,
			enum operation_id operation_id, void *args, int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_STORAGE_STORE:
		*status = storage_store(ele_ctx, args);
		break;

	case OPERATION_ID_STORAGE_RETRIEVE:
		*status = storage_retrieve(&ele_ctx->hdl, args);
		break;

	case OPERATION_ID_STORAGE_DELETE:
	default:
		return false;
	}

	return true;
}
