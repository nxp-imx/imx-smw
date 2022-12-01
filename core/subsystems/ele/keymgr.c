// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"

#include "common.h"

/**
 * struct ele_key_def - ELE Key definition
 * @key_type_id: SMW Key type ID
 * @security_size: Key security size
 * @ele_key_type: ELE Key type ID
 * @ele_perm_alg_def: ELE default permitted algorithm
 */
static const struct ele_key_def {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	hsm_key_type_t ele_key_type;
} ele_key_def_list[] = {
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 224,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_NIST_P224 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 256,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_NIST_P256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 384,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_NIST_P384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 521,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_NIST_P521 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .security_size = 224,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .security_size = 256,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .security_size = 384,
	  .ele_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 128,
	  .ele_key_type = HSM_KEY_TYPE_AES_128 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 192,
	  .ele_key_type = HSM_KEY_TYPE_AES_192 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 256,
	  .ele_key_type = HSM_KEY_TYPE_AES_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
	  .security_size = 224,
	  .ele_key_type = HSM_KEY_TYPE_HMAC_224 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
	  .security_size = 256,
	  .ele_key_type = HSM_KEY_TYPE_HMAC_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
	  .security_size = 384,
	  .ele_key_type = HSM_KEY_TYPE_HMAC_384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
	  .security_size = 512,
	  .ele_key_type = HSM_KEY_TYPE_HMAC_512 },
};

static int get_key_definition(enum smw_config_key_type_id key_type_id,
			      unsigned short security_size,
			      const struct ele_key_def **key_def)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i;
	unsigned int size = ARRAY_SIZE(ele_key_def_list);
	const struct ele_key_def *key = ele_key_def_list;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++, key++) {
		if (key->key_type_id == key_type_id) {
			if (key->security_size != security_size)
				continue;

			*key_def = key;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static hsm_err_t open_key_mgmt_service(struct hdl *hdl,
				       hsm_hdl_t *key_management_hdl)
{
	hsm_err_t err;
	open_svc_key_management_args_t open_svc_key_management_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_key_management_service(hdl->key_store,
					      &open_svc_key_management_args,
					      key_management_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "Open key_management_hdl: %u\n",
		       *key_management_hdl);

	return err;
}

static hsm_err_t close_key_mgt_service(hsm_hdl_t key_management_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close key_management_hdl: %u\n",
		       key_management_hdl);

	if (key_management_hdl) {
		err = hsm_close_key_management_service(key_management_hdl);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
	}

	return err;
}

static int generate_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_generate_key_args_t op_args = { 0 };

	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_attributes *key_attrs = &key_args->key_attributes;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	unsigned char *public_data = smw_keymgr_get_public_data(key_desc);
	uint32_t key_id = 0;
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;
	int policy_status = SMW_STATUS_OK;
	unsigned char *actual_policy = NULL;
	unsigned int actual_policy_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = ele_set_key_type(key_identifier->type_id,
				  key_identifier->security_size,
				  &op_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	if (public_data) {
		status =
			smw_keymgr_get_buffers_lengths(key_identifier,
						       SMW_KEYMGR_FORMAT_ID_HEX,
						       &out_size, NULL, NULL);
		if (status != SMW_STATUS_OK)
			goto end;

		if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
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

	op_args.key_identifier = &key_id;
	op_args.out_size = out_size;

	policy_status =
		ele_set_key_policy(key_attrs->policy, key_attrs->policy_len,
				   &op_args.key_usage, &op_args.permitted_algo,
				   &actual_policy, &actual_policy_len);
	if (policy_status != SMW_STATUS_OK &&
	    policy_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		status = policy_status;
		goto end;
	}

	if (key_args->key_attributes.persistent_storage) {
		op_args.key_lifetime = HSM_HW_INTERN_STORAGE_PERSISTENT;
		op_args.key_group = PERSISTENT_KEY_GROUP;
	} else {
		op_args.key_lifetime = HSM_HW_INTERN_STORAGE_VOLATILE;
		op_args.key_group = TRANSIENT_KEY_GROUP;
	}

	if (key_args->key_attributes.flush_key)
		op_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;

	op_args.out_key = out_key;

	err = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (err != HSM_NO_ERROR) {
		status = ele_convert_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_generate_key()\n"
		       "key_management_hdl: %u\n"
		       "op_generate_key_args_t\n"
		       "    flags: 0x%X\n"
		       "    key identifier: %p\n"
		       "    key policy\n"
		       "      - type: 0x%04X\n"
		       "      - group: %d\n"
		       "      - lifetime: 0x%X\n"
		       "      - usage: 0x%04X\n"
		       "      - algo: 0x%08X\n"
		       "    Public Key (output)\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.flags,
		       op_args.key_identifier, op_args.key_type,
		       op_args.key_group, op_args.key_lifetime,
		       op_args.key_usage, op_args.permitted_algo,
		       op_args.out_key, op_args.out_size);

	err = hsm_generate_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_generate_key returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_ELE;
	key_identifier->id = key_id;

	SMW_DBG_PRINTF(DEBUG, "ELE Key identifier: 0x%08X\n", key_id);

	if (out_key) {
		if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			status =
				smw_utils_base64_encode(out_key, out_size,
							public_data, &out_size);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		SMW_DBG_PRINTF(DEBUG, "Out key:\n");
		SMW_DBG_HEX_DUMP(DEBUG, public_data, out_size, 4);
	}

	smw_keymgr_set_public_length(key_desc, out_size);

end:
	err = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = ele_convert_err(err);

	if (out_key && out_key != public_data)
		SMW_UTILS_FREE(out_key);

	if (status == SMW_STATUS_OK &&
	    policy_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		status = policy_status;

	if (actual_policy) {
		if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
			smw_keymgr_set_attributes_list(key_attrs, actual_policy,
						       actual_policy_len);

		SMW_UTILS_FREE(actual_policy);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_export_key_config() - Check key descriptor configuration.
 * @key_descriptor: Pointer to key descriptor.
 *
 * EdgeLock Enclave subsystem only exports public key of an asymmetric key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (key_descriptor->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		if (smw_keymgr_get_public_data(key_descriptor) &&
		    !smw_keymgr_get_private_data(key_descriptor)) {
			status = SMW_STATUS_OK;
			break;
		}

		SMW_DBG_PRINTF(ERROR, "%s: ELE only exports public key\n",
			       __func__);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "%s: Key type %d not exportable",
			       __func__, key_descriptor->identifier.type_id);
		break;
	}

	return status;
}

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_args = { 0 };

	struct smw_keymgr_export_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	unsigned char *public_data = smw_keymgr_get_public_data(key_desc);
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;
	unsigned int pub_data_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_export_key_config(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_buffers_lengths(key_identifier,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&out_size, NULL, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
		out_key = public_data;
	} else {
		out_key = SMW_UTILS_MALLOC(out_size);
		if (!out_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
	}

	op_args.key_identifier = key_identifier->id;
	op_args.out_key = out_key;
	op_args.out_key_size = out_size;

	status = ele_set_key_type(key_identifier->type_id,
				  key_identifier->security_size,
				  &op_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_pub_key_recovery()\n"
		       "  key_store_hdl: %u\n"
		       "  op_pub_key_recovery_args_t\n"
		       "    key identifier: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Public Key\n"
		       "      - type: 0x%04X\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, hdl->key_store,
		       op_args.key_identifier, op_args.flags, op_args.key_type,
		       op_args.out_key, op_args.out_key_size);

	err = hsm_pub_key_recovery(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_pub_key_recovery returned %d\n", err);

	status = ele_convert_err(err);
	// TODO: When ELE library done, output key size too short
	if (status == SMW_STATUS_OK) {
		/* Export operation returns the public key size */
		out_size = op_args.out_key_size;

		if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			pub_data_len = smw_keymgr_get_public_length(key_desc);
			status = smw_utils_base64_encode(out_key, out_size,
							 public_data,
							 &pub_data_len);
			if (status != SMW_STATUS_OK)
				goto end;

			out_size = pub_data_len;
		}

		smw_keymgr_set_public_length(key_desc, out_size);
		smw_keymgr_set_private_length(key_desc, 0);

		SMW_DBG_PRINTF(DEBUG, "Public key:\n");
		SMW_DBG_HEX_DUMP(DEBUG, public_data, out_size, 4);
	}

end:
	if (out_key && out_key != public_data)
		SMW_UTILS_FREE(out_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_delete_key_args_t op_args = { 0 };

	struct smw_keymgr_delete_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.key_identifier = &key_desc->identifier.id;

	err = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (err != HSM_NO_ERROR) {
		status = ele_convert_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_delete_key()\n"
		       "  key_management_hdl: %u\n"
		       "  op_delete_key_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    key_group: %d\n",
		       __func__, __LINE__, key_mgt_hdl, *op_args.key_identifier,
		       op_args.flags, op_args.key_group);

	err = hsm_delete_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_delete_key returned %d\n", err);

	status = ele_convert_err(err);

	err = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = ele_convert_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_set_key_type(enum smw_config_key_type_id key_type_id,
		     unsigned short security_size, hsm_key_type_t *ele_type)
{
	int status;
	const struct ele_key_def *key_def = NULL;

	status = get_key_definition(key_type_id, security_size, &key_def);
	if (status == SMW_STATUS_OK)
		*ele_type = key_def->ele_key_type;

	return status;
}

bool ele_key_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(hdl, args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = ele_derive_key(hdl, args);
		break;
	case OPERATION_ID_UPDATE_KEY:
		*status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
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
