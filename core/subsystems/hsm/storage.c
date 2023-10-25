// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"
#include "storage.h"

#include "common.h"

static hsm_err_t open_data_storage_service(struct hdl *hdl,
					   hsm_hdl_t *data_storage_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_data_storage_args_t open_svc_data_storage_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_data_storage_service(hdl->key_store,
					    &open_svc_data_storage_args,
					    data_storage_hdl);

	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "data_storage_hdl: %u\n", *data_storage_hdl);

	return err;
}

static hsm_err_t close_data_storage_service(hsm_hdl_t data_storage_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "data_storage_hdl: %u\n", data_storage_hdl);
	err = hsm_close_data_storage_service(data_storage_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);

	return err;
}

static int data_storage(struct hdl *hdl,
			struct smw_storage_data_descriptor *data_descriptor,
			bool store)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_err_t err = HSM_NO_ERROR;

	hsm_hdl_t data_storage_hdl = 0;
	op_data_storage_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (SET_OVERFLOW(smw_storage_get_data_identifier(data_descriptor),
			 op_args.data_id))
		goto end;

	op_args.data = smw_storage_get_data(data_descriptor);
	op_args.data_size = smw_storage_get_data_length(data_descriptor);
	op_args.flags = store ? HSM_OP_DATA_STORAGE_FLAGS_STORE :
				HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;

	err = open_data_storage_service(hdl, &data_storage_hdl);
	if (err != HSM_NO_ERROR) {
		status = convert_hsm_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_data_storage() - %s\n"
		       "  op_data_storage_args_t\n"
		       "    Data\n"
		       "      - id: 0x%08X\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    flags: 0x%X\n",
		       __func__, __LINE__, store ? "store" : "retrieve",
		       op_args.data_id, op_args.data, op_args.data_size,
		       op_args.flags);

	err = hsm_data_storage(data_storage_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_data_storage returned %d\n", err);

	status = convert_hsm_err(err);

	if (!store)
		smw_storage_set_data_length(data_descriptor, op_args.data_size);

	err = close_data_storage_service(data_storage_hdl);

	if (status == SMW_STATUS_OK)
		status = convert_hsm_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_data_raw(struct hdl *hdl,
			  struct smw_storage_store_data_args *args)
{
	return data_storage(hdl, &args->data_descriptor, true);
}

static int storage_store(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct smw_storage_store_data_args *store_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (store_args->enc_args.mode_id == SMW_CONFIG_CIPHER_MODE_ID_INVALID &&
	    store_args->sign_args.algo_id == SMW_CONFIG_MAC_ALGO_ID_INVALID) {
		status = store_data_raw(hdl, args);

		store_args->data_descriptor.subsystem_id = SUBSYSTEM_ID_HSM;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int storage_retrieve(struct hdl *hdl,
			    struct smw_storage_retrieve_data_args *args)
{
	return data_storage(hdl, &args->data_descriptor, false);
}

bool hsm_storage_handle(struct hdl *hdl, enum operation_id operation_id,
			void *args, int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_STORAGE_STORE:
		*status = storage_store(hdl, args);
		break;

	case OPERATION_ID_STORAGE_RETRIEVE:
		*status = storage_retrieve(hdl, args);
		break;

	case OPERATION_ID_STORAGE_DELETE:
	default:
		return false;
	}

	return true;
}
