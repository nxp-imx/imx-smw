// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"

#include "common.h"

/* Key type IDs must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest
 * for 1 given Key type ID.
 * This sorting is required to simplify the implementation of set_key_type().
 */
static const struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	hsm_key_type_t hsm_key_type;
} key_type_ids[] = { { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		       .security_size = 256,
		       .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P256 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		       .security_size = 384,
		       .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P384 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		       .security_size = 256,
		       .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		       .security_size = 384,
		       .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		       .security_size = 128,
		       .hsm_key_type = HSM_KEY_TYPE_AES_128 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		       .security_size = 192,
		       .hsm_key_type = HSM_KEY_TYPE_AES_192 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		       .security_size = 256,
		       .hsm_key_type = HSM_KEY_TYPE_AES_256 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
		       .security_size = 256,
		       .hsm_key_type = HSM_KEY_TYPE_HMAC_256 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
		       .security_size = 384,
		       .hsm_key_type = HSM_KEY_TYPE_HMAC_384 },
		     { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY,
		       .security_size = TLS12_MASTER_SECRET_SEC_SIZE,
		       /* There is no HSM master key type value */
		       .hsm_key_type = 0 } };

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

static int generate_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_generate_key_args_t op_generate_key_args = { 0 };

	struct smw_keymgr_generate_key_args *generate_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&generate_key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	enum smw_keymgr_format_id format_id = key_descriptor->format_id;
	enum smw_config_key_type_id key_type_id = key_identifier->type_id;
	unsigned int security_size = key_identifier->security_size;
	unsigned char *public_data = smw_keymgr_get_public_data(key_descriptor);
	uint32_t key_id = 0;
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(generate_key_args);

	if (public_data) {
		status =
			smw_keymgr_get_buffers_lengths(key_identifier,
						       SMW_KEYMGR_FORMAT_ID_HEX,
						       &out_size, NULL, NULL);
		if (status != SMW_STATUS_OK)
			goto end;

		if (format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
			out_key = public_data;
		} else {
			out_key = SMW_UTILS_MALLOC(out_size);
			if (!out_key) {
				SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}
		}
	}

	op_generate_key_args.key_identifier = &key_id;
	op_generate_key_args.out_size = out_size;
	op_generate_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;

	status = set_key_type(key_type_id, security_size,
			      &op_generate_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	if (generate_key_args->key_attributes.persistent_storage) {
		op_generate_key_args.key_info = HSM_KEY_INFO_PERSISTENT;
		op_generate_key_args.key_group = PERSISTENT_KEY_GROUP;
	} else {
		op_generate_key_args.key_info = HSM_KEY_INFO_TRANSIENT;
		op_generate_key_args.key_group = TRANSIENT_KEY_GROUP;
	}

	if (generate_key_args->key_attributes.flush_key)
		op_generate_key_args.flags |=
			HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;

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

	status = smw_keymgr_get_privacy_id(key_type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_HSM;
	key_identifier->id = key_id;

	SMW_DBG_PRINTF(DEBUG, "HSM Key identifier: %d\n", key_id);

	if (out_key) {
		if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			status =
				smw_utils_base64_encode(out_key, out_size,
							public_data, &out_size);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		SMW_DBG_PRINTF(DEBUG, "Out key:\n");
		SMW_DBG_HEX_DUMP(DEBUG, public_data, out_size, 4);
	}

	smw_keymgr_set_public_length(key_descriptor, out_size);

end:
	if (out_key && out_key != public_data)
		SMW_UTILS_FREE(out_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_key(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement update_key()
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement import_key()
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_export_key_config() - Check key descriptor configuration.
 * @key_descriptor: Pointer to key descriptor.
 *
 * HSM secure subsystem only exports ECDSA NIST and BR1 public key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	if (key_descriptor->identifier.type_id !=
		    SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST &&
	    key_descriptor->identifier.type_id !=
		    SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1) {
		SMW_DBG_PRINTF(ERROR, "%s: HSM unsupported exported key\n",
			       __func__);
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	if (smw_keymgr_get_private_data(key_descriptor) ||
	    !smw_keymgr_get_public_data(key_descriptor)) {
		SMW_DBG_PRINTF(ERROR, "%s: HSM only exports public key\n",
			       __func__);
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	return SMW_STATUS_OK;
}

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_pub_key_recovery_args = { 0 };

	struct smw_keymgr_export_key_args *export_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&export_key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	enum smw_keymgr_format_id format_id = key_descriptor->format_id;
	enum smw_config_key_type_id key_type_id = key_identifier->type_id;
	unsigned int security_size = key_identifier->security_size;
	unsigned char *public_data = smw_keymgr_get_public_data(key_descriptor);
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;
	unsigned int pub_data_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(export_key_args);

	status = check_export_key_config(key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_buffers_lengths(key_identifier,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&out_size, NULL, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	if (format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
		out_key = public_data;
	} else {
		out_key = SMW_UTILS_MALLOC(out_size);
		if (!out_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
	}

	op_pub_key_recovery_args.key_identifier = key_identifier->id;
	op_pub_key_recovery_args.out_key = out_key;
	op_pub_key_recovery_args.out_key_size = out_size;

	status = set_key_type(key_type_id, security_size,
			      &op_pub_key_recovery_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

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

	SMW_DBG_PRINTF(DEBUG, "HSM Key identifier: %d\n", key_identifier->id);

	/* Get public key buffer length */
	pub_data_len = smw_keymgr_get_public_length(key_descriptor);

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		status = smw_utils_base64_encode(out_key, out_size, public_data,
						 &pub_data_len);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	smw_keymgr_set_public_length(key_descriptor, pub_data_len);
	smw_keymgr_set_private_length(key_descriptor, 0);

	SMW_DBG_PRINTF(DEBUG, "Out key:\n");
	SMW_DBG_HEX_DUMP(DEBUG, public_data, pub_data_len, 4);

end:
	if (out_key && out_key != public_data)
		SMW_UTILS_FREE(out_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_manage_key_args_t manage_key_args = { 0 };

	struct smw_keymgr_delete_key_args *delete_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&delete_key_args->key_descriptor;
	uint32_t key_id = key_descriptor->identifier.id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(delete_key_args);

	manage_key_args.key_identifier = &key_id;
	manage_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;

	status = set_key_type(key_descriptor->identifier.type_id,
			      key_descriptor->identifier.security_size,
			      &manage_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_descriptor->identifier.persistent)
		manage_key_args.key_group = PERSISTENT_KEY_GROUP;
	else
		manage_key_args.key_group = TRANSIENT_KEY_GROUP;

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

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_key_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
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
