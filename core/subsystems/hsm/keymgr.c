// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"

#include "common.h"

struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	hsm_key_type_t hsm_key_type;
}

/* Key type IDs must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest
 * for 1 given Key type ID.
 * This sorting is required to simplify the implementation of set_key_type().
 */
key_type_ids[] = { { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		     .security_size = 256,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P256 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		     .security_size = 384,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P384 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		     .security_size = 521,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P521 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		     .security_size = 256,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		     .security_size = 320,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		     .security_size = 384,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		     .security_size = 512,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
		     .security_size = 256,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
		     .security_size = 320,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
		     .security_size = 384,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
		     .security_size = 512,
		     .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_512 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		     .security_size = 128,
		     .hsm_key_type = HSM_KEY_TYPE_AES_128 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		     .security_size = 192,
		     .hsm_key_type = HSM_KEY_TYPE_AES_192 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		     .security_size = 256,
		     .hsm_key_type = HSM_KEY_TYPE_AES_256 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
		     .security_size = 256,
		     .hsm_key_type = HSM_KEY_TYPE_DSA_SM2_FP_256 },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_SM4,
		     .security_size = 128,
		     .hsm_key_type = HSM_KEY_TYPE_SM4_128 } };

static int set_key_type(enum smw_config_key_type_id key_type_id,
			unsigned short security_size, hsm_key_type_t *key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i;
	unsigned int size = ARRAY_SIZE(key_type_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (key_type_ids[i].key_type_id < key_type_id)
			continue;
		if (key_type_ids[i].key_type_id > key_type_id)
			goto end;
		if (key_type_ids[i].security_size < security_size)
			continue;
		if (key_type_ids[i].security_size > security_size)
			goto end;
		*key_type = key_type_ids[i].hsm_key_type;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "HSM Key Type: %d\n", *key_type);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__attribute__((weak)) int alloc_out_key(uint8_t **out_key, uint16_t *out_size,
					unsigned int security_size)
{
	*out_key = NULL;
	*out_size = 0;

	return SMW_STATUS_OK;
}

__attribute__((weak)) void print_out_key(uint8_t *out_key, uint16_t out_size)
{
}

__attribute__((weak)) void free_out_key(uint8_t *out_key)
{
}

static int generate_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_generate_key_args_t op_generate_key_args;

	struct smw_keymgr_generate_key_args *generate_key_args =
		(struct smw_keymgr_generate_key_args *)args;

	uint32_t key_id = 0;
	uint8_t *out_key = NULL;
	uint16_t out_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = alloc_out_key(&out_key, &out_size,
			       generate_key_args->security_size);
	if (status != SMW_STATUS_OK)
		goto end;

	op_generate_key_args.key_identifier = &key_id;
	op_generate_key_args.out_size = out_size;
	op_generate_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	status = set_key_type(generate_key_args->key_type_id,
			      generate_key_args->security_size,
			      &op_generate_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;
	op_generate_key_args.key_group = 0;
	op_generate_key_args.key_info =
		HSM_KEY_INFO_PERSISTENT | HSM_KEY_INFO_MASTER;
	op_generate_key_args.out_key = out_key;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_generate_key()\n"
		       "key_management_hdl: %d\n"
		       "op_generate_key_args_t\n"
		       "    key_identifier: %p\n"
		       "    out_size: %d\n"
		       "    flags: %x\n"
		       "    key_type: %d\n"
		       "    key_group: %d\n"
		       "    key_info: %x\n"
		       "    out_key: %p\n",
		       __func__, __LINE__, hdl->key_management,
		       op_generate_key_args.key_identifier,
		       op_generate_key_args.out_size,
		       op_generate_key_args.flags,
		       op_generate_key_args.key_type,
		       op_generate_key_args.key_group,
		       op_generate_key_args.key_info,
		       op_generate_key_args.out_key);

	err = hsm_generate_key(hdl->key_management, &op_generate_key_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_generate_key returned %d\n", err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	generate_key_args->key_identifier->subsystem_id = SUBSYSTEM_ID_HSM;
	generate_key_args->key_identifier->key_type_id =
		generate_key_args->key_type_id;
	generate_key_args->key_identifier->security_size =
		generate_key_args->security_size;
	generate_key_args->key_identifier->is_private = false;
	generate_key_args->key_identifier->id = (unsigned long)key_id;

	SMW_DBG_PRINTF(DEBUG, "HSM Key identifier: %ld\n",
		       generate_key_args->key_identifier->id);
	print_out_key(out_key, out_size);

end:
	free_out_key(out_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int derive_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement derive_key()
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement update_key()
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement import_key()
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_pub_key_recovery_args;

	struct smw_keymgr_export_key_args *export_key_args =
		(struct smw_keymgr_export_key_args *)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_pub_key_recovery_args.key_identifier =
		(uint32_t)export_key_args->key_identifier->id;
	op_pub_key_recovery_args.out_key =
		(uint8_t *)export_key_args->output_buffer;
	op_pub_key_recovery_args.out_key_size =
		(uint16_t)export_key_args->output_buffer_length;

	status = set_key_type(export_key_args->key_identifier->key_type_id,
			      export_key_args->key_identifier->security_size,
			      &op_pub_key_recovery_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;
	op_pub_key_recovery_args.flags = 0;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_pub_key_recovery()\n"
		       "  key_store_hdl: %d\n"
		       "  op_pub_key_recovery_args_t\n"
		       "    key_identifier: %d\n"
		       "    out_key: %p\n"
		       "    out_key_size: %d\n"
		       "    key_type: %d\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->key_store,
		       op_pub_key_recovery_args.key_identifier,
		       op_pub_key_recovery_args.out_key,
		       op_pub_key_recovery_args.out_key_size,
		       op_pub_key_recovery_args.key_type,
		       op_pub_key_recovery_args.flags);

	err = hsm_pub_key_recovery(hdl->key_store, &op_pub_key_recovery_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_pub_key_recovery returned %d\n",
			       err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_manage_key_args_t manage_key_args;

	struct smw_keymgr_delete_key_args *delete_key_args =
		(struct smw_keymgr_delete_key_args *)args;

	uint32_t key_id = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	manage_key_args.key_identifier = &key_id;
	manage_key_args.kek_identifier = 0;
	manage_key_args.input_size = 0;
	manage_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	status = set_key_type(delete_key_args->key_identifier->key_type_id,
			      delete_key_args->key_identifier->security_size,
			      &manage_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;
	manage_key_args.key_group = 0;
	manage_key_args.key_info = 0;
	manage_key_args.input_data = NULL;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_manage_key()\n"
		       "  key_management_hdl: %d\n"
		       "  op_manage_key_args_t\n"
		       "    key_identifier: %d\n"
		       "    kek_identifier: %d\n"
		       "    input_size: %d\n"
		       "    flags: %x\n"
		       "    key_type: %d\n"
		       "    key_group: %d\n"
		       "    key_info: %x\n"
		       "    input_data: %p\n",
		       __func__, __LINE__, hdl->key_management,
		       *manage_key_args.key_identifier,
		       manage_key_args.kek_identifier,
		       manage_key_args.input_size, manage_key_args.flags,
		       manage_key_args.key_type, manage_key_args.key_group,
		       manage_key_args.key_info, manage_key_args.input_data);

	err = hsm_manage_key(hdl->key_management, &manage_key_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_manage_key returned %d\n", err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	delete_key_args->key_identifier->id = (unsigned long)key_id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool key_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		int *status)
{
	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(hdl, args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = derive_key(hdl, args);
		break;
	case OPERATION_ID_UPDATE_KEY:
		*status = update_key(hdl, args);
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = import_key(hdl, args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(hdl, args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}
