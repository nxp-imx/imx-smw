// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "tlv.h"
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
static const struct hsm_key_def {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	unsigned short public_key_size;
	hsm_key_type_t hsm_key_type;
} hsm_key_def_list[] = {
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 256,
	  .public_key_size = 64,
	  .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .security_size = 384,
	  .public_key_size = 96,
	  .hsm_key_type = HSM_KEY_TYPE_ECDSA_NIST_P384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .security_size = 256,
	  .public_key_size = 64,
	  .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .security_size = 384,
	  .public_key_size = 96,
	  .hsm_key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 128,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_AES_128 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 192,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_AES_192 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .security_size = 256,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_AES_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
	  .security_size = 224,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_HMAC_224 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
	  .security_size = 256,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_HMAC_256 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
	  .security_size = 384,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_HMAC_384 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
	  .security_size = 512,
	  .public_key_size = 0,
	  .hsm_key_type = HSM_KEY_TYPE_HMAC_512 },
	{ .key_type_id = SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY,
	  .security_size = TLS12_MASTER_SECRET_SEC_SIZE,
	  .public_key_size = 0,
	  /* There is no HSM master key type value */
	  .hsm_key_type = 0 }
};

static int set_key_type(enum smw_config_key_type_id key_type_id,
			unsigned int security_size, hsm_key_type_t *key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(hsm_key_def_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (hsm_key_def_list[i].key_type_id < key_type_id)
			continue;
		if (hsm_key_def_list[i].key_type_id > key_type_id)
			goto end;
		if (hsm_key_def_list[i].security_size < security_size)
			continue;
		if (hsm_key_def_list[i].security_size > security_size)
			goto end;
		*key_type = hsm_key_def_list[i].hsm_key_type;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "HSM Key Type: %d\n", *key_type);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned short hsm_public_key_length(hsm_key_type_t key_type)
{
	unsigned short length = 0;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(hsm_key_def_list);
	const struct hsm_key_def *key = hsm_key_def_list;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++, key++) {
		if (key->hsm_key_type == key_type) {
			length = key->public_key_size;
			break;
		}
	}

	SMW_DBG_PRINTF(DEBUG, "Public key size %d bytes\n", length);
	return length;
}

void hsm_set_empty_key_policy(struct smw_keymgr_attributes *key_attributes)
{
	unsigned char *attributes_list =
		key_attributes->pub_key_attributes_list;

	SMW_DBG_ASSERT(attributes_list);

	smw_tlv_set_type(&attributes_list, POLICY_STR);

	SMW_DBG_ASSERT(*key_attributes->pub_key_attributes_list_length >=
		       attributes_list -
			       key_attributes->pub_key_attributes_list);

	*key_attributes->pub_key_attributes_list_length =
		attributes_list - key_attributes->pub_key_attributes_list;
}

static int
check_reallocate_public_buffer(unsigned char **data, unsigned short *length,
			       struct smw_keymgr_descriptor *key_desc,
			       hsm_key_type_t key_type)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *public_data = NULL;
	unsigned int public_length = 0;
	unsigned char *tmp_key = NULL;
	unsigned short hsm_key_size = 0;
	unsigned int max_public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	public_data = smw_keymgr_get_public_data(key_desc);

	/* HSM require exact asymmetric public key size */
	hsm_key_size = hsm_public_key_length(key_type);
	if (!hsm_key_size) {
		if (public_data) {
			SMW_DBG_PRINTF(ERROR,
				       "Only public key can be exported\n");
			status = SMW_STATUS_INVALID_PARAM;
		} else {
			status = SMW_STATUS_OK;
		}

		goto end;
	}

	public_length = smw_keymgr_get_public_length(key_desc);

	/* First check if the user public buffer size is big enough */
	max_public_length = hsm_key_size;
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
		max_public_length = smw_utils_get_base64_len(max_public_length);

	if (public_length < max_public_length) {
		smw_keymgr_set_public_length(key_desc, max_public_length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
	} else if (public_data) {
		if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			tmp_key = SMW_UTILS_MALLOC(max_public_length);
			if (!tmp_key) {
				SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}
		} else {
			tmp_key = public_data;
		}

		*length = hsm_key_size;
		*data = tmp_key;

		status = SMW_STATUS_OK;
	}

end:
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
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (key_descriptor->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
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

static int export_key_operation(struct hdl *hdl,
				struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_export_key_args = { 0 };

	unsigned char *tmp_key = NULL;
	unsigned short hsm_key_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_export_key_config(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_key_type(key_desc->identifier.type_id,
			      key_desc->identifier.security_size,
			      &op_export_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_reallocate_public_buffer(&tmp_key, &hsm_key_size,
						key_desc,
						op_export_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	op_export_key_args.key_identifier = key_desc->identifier.id;

	op_export_key_args.out_key = tmp_key;
	op_export_key_args.out_key_size = hsm_key_size;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_pub_key_recovery()\n"
		       "  key_store_hdl: %u\n"
		       "  op_pub_key_recovery_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    out_key: %p\n"
		       "    out_key_size: %d\n"
		       "    key_type: 0x%02X\n"
		       "    flags: 0x%02X\n",
		       __func__, __LINE__, hdl->key_store,
		       op_export_key_args.key_identifier,
		       op_export_key_args.out_key,
		       op_export_key_args.out_key_size,
		       op_export_key_args.key_type, op_export_key_args.flags);

	err = hsm_pub_key_recovery(hdl->key_store, &op_export_key_args);
	status = convert_hsm_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_update_public_buffer(key_desc, tmp_key,
						 hsm_key_size);

end:
	if (tmp_key && tmp_key != smw_keymgr_get_public_data(key_desc))
		SMW_UTILS_FREE(tmp_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key_operation(struct subsystem_context *hsm_ctx,
				struct smw_keymgr_descriptor *key_desc,
				bool flush)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_manage_key_args_t manage_key_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	manage_key_args.key_identifier = &key_desc->identifier.id;
	manage_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;

	if (flush)
		manage_key_args.flags |=
			HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION;

	status = set_key_type(key_desc->identifier.type_id,
			      key_desc->identifier.security_size,
			      &manage_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	manage_key_args.key_group = key_desc->identifier.group;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_manage_key()\n"
		       "  key_management_hdl: %u\n"
		       "  op_manage_key_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    input_size: %d\n"
		       "    flags: 0x%02X\n"
		       "    key_type: %d\n"
		       "    key_group: %d\n"
		       "    key_info: 0x%04X\n"
		       "    input_data: %p\n",
		       __func__, __LINE__, hsm_ctx->hdl.key_management,
		       *manage_key_args.key_identifier,
		       manage_key_args.input_size, manage_key_args.flags,
		       manage_key_args.key_type, manage_key_args.key_group,
		       manage_key_args.key_info, manage_key_args.input_data);

	err = hsm_manage_key(hsm_ctx->hdl.key_management, &manage_key_args);
	status = convert_hsm_err(err);

	if (status != SMW_STATUS_OK)
		goto end;

	/* Let assume there is place to add a new key */
	status = hsm_set_key_group_state(hsm_ctx, key_desc->identifier.group,
					 key_desc->identifier.persistence_id,
					 false);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key(struct subsystem_context *hsm_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_generate_key_args_t op_generate_key_args = { 0 };

	struct smw_keymgr_generate_key_args *generate_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&generate_key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	unsigned char *public_data = NULL;
	uint32_t key_id = 0;
	unsigned char *tmp_key = NULL;
	unsigned short hsm_key_size = 0;
	hsm_key_type_t hsm_key_type = 0;
	bool persistent_grp = false;
	unsigned int key_group = 0;
	bool flush_key = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = set_key_type(key_identifier->type_id,
			      key_identifier->security_size, &hsm_key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	public_data = smw_keymgr_get_public_data(key_descriptor);
	if (public_data) {
		status = check_reallocate_public_buffer(&tmp_key, &hsm_key_size,
							key_descriptor,
							hsm_key_type);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	op_generate_key_args.key_identifier = &key_id;
	op_generate_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;

	op_generate_key_args.key_type = hsm_key_type;
	op_generate_key_args.out_key = tmp_key;
	op_generate_key_args.out_size = hsm_key_size;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (generate_key_args->key_attributes.flush_key) {
		flush_key = true;
		op_generate_key_args.flags |=
			HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	}

	switch (generate_key_args->key_attributes.persistence_id) {
	case SMW_OBJECT_PERSISTENCE_ID_PERSISTENT:
		op_generate_key_args.key_info = HSM_KEY_INFO_PERSISTENT;
		key_group = HSM_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_OBJECT_PERSISTENCE_ID_PERMANENT:
		op_generate_key_args.key_info = HSM_KEY_INFO_PERMANENT;
		key_group = HSM_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	default:
		op_generate_key_args.key_info = HSM_KEY_INFO_TRANSIENT;
		key_group = HSM_FIRST_TRANSIENT_KEY_GROUP;
		break;
	}

	do {
		status = hsm_get_key_group(hsm_ctx, persistent_grp, &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_generate_key_args.key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_generate_key()\n"
			       "key_management_hdl: %u\n"
			       "op_generate_key_args_t\n"
			       "    key_identifier: @%p\n"
			       "    out_size: %d\n"
			       "    flags: 0x%02X\n"
			       "    key_type: %d\n"
			       "    key_group: %d\n"
			       "    key_info: 0x%04X\n"
			       "    out_key: %p\n",
			       __func__, __LINE__, hsm_ctx->hdl.key_management,
			       op_generate_key_args.key_identifier,
			       op_generate_key_args.out_size,
			       op_generate_key_args.flags,
			       op_generate_key_args.key_type,
			       op_generate_key_args.key_group,
			       op_generate_key_args.key_info,
			       op_generate_key_args.out_key);

		err = hsm_generate_key(hsm_ctx->hdl.key_management,
				       &op_generate_key_args);

		/*
		 * There is no specific HSM error code indicating that the
		 * NVM Storage is full, hence let's assume that the NVM_KEY_STORE_ERROR
		 * will be returned only in case of key group full.
		 */
		if (err == HSM_KEY_STORE_ERROR) {
			status = hsm_set_key_group_state(hsm_ctx, key_group,
							 persistent_grp, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_STORE_ERROR);

	status = convert_hsm_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_HSM;
	key_identifier->id = key_id;
	key_identifier->group = key_group;

	SMW_DBG_PRINTF(DEBUG, "HSM Key identifier: 0x%08X\n", key_id);

	if (public_data) {
		status = smw_keymgr_update_public_buffer(key_descriptor,
							 tmp_key, hsm_key_size);
		if (status != SMW_STATUS_OK) {
			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(hsm_ctx, key_descriptor,
						   flush_key);
		}
	}

	if (generate_key_args->key_attributes.policy) {
		hsm_set_empty_key_policy(&generate_key_args->key_attributes);
		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

end:
	if (tmp_key && tmp_key != public_data)
		SMW_UTILS_FREE(tmp_key);

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

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args *export_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&export_key_args->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = export_key_operation(hdl, key_descriptor);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct subsystem_context *hsm_ctx, void *args)
{
	struct smw_keymgr_delete_key_args *delete_key_args = args;

	return delete_key_operation(hsm_ctx, &delete_key_args->key_descriptor,
				    delete_key_args->key_attributes.flush_key);
}

static int get_key_lengths(struct hdl *hdl, void *args)
{
	(void)hdl;

	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_desc = NULL;
	unsigned int public_length = 0;
	hsm_key_type_t hsm_key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = args;

	/*
	 * HSM subsystem doesn't expose services to get the key id attributes
	 * Let assume user key descriptor is correct to get the type and if
	 * key type is asymmetric key, get the public key size.
	 */
	status =
		set_key_type(key_desc->identifier.type_id,
			     key_desc->identifier.security_size, &hsm_key_type);

	if (status == SMW_STATUS_OK) {
		public_length = hsm_public_key_length(hsm_key_type);
		if (!public_length) {
			SMW_DBG_PRINTF(VERBOSE, "%s: No public key\n",
				       __func__);
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
			goto end;
		}

		/*
		 * Only public key is available, private or symmetric key
		 * are never exported.
		 */
		status = smw_keymgr_update_public_buffer(key_desc, NULL,
							 public_length);

		tmp_status =
			smw_keymgr_update_private_buffer(key_desc, NULL, 0);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int commit_key_storage(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int hsm_export_public_key(struct hdl *hdl,
			  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int public_length = 0;
	hsm_key_type_t hsm_key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * HSM subsystem doesn't expose services to get the key id attributes
	 * Let assume user key descriptor is correct to get the type and if
	 * key type is asymmetric key, get the public key size.
	 */
	status =
		set_key_type(key_desc->identifier.type_id,
			     key_desc->identifier.security_size, &hsm_key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	public_length = hsm_public_key_length(hsm_key_type);
	if (!public_length) {
		SMW_DBG_PRINTF(VERBOSE, "%s: No public key\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_desc->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	/* Allocate key descriptor's keypair buffer and its public data */
	status = smw_keymgr_alloc_keypair_buffer(key_desc, public_length, 0);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Export the public key */
	status = export_key_operation(hdl, key_desc);

end:
	if (status != SMW_STATUS_OK && key_desc->pub)
		(void)smw_keymgr_free_keypair_buffer(key_desc);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_key_handle(struct subsystem_context *hsm_ctx,
		    enum operation_id operation_id, void *args, int *status)
{
	struct hdl *hdl = NULL;

	SMW_DBG_ASSERT(hsm_ctx && args);

	hdl = &hsm_ctx->hdl;

	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(hsm_ctx, args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = hsm_derive_key(hsm_ctx, args);
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
		*status = delete_key(hsm_ctx, args);
		break;
	case OPERATION_ID_GET_KEY_LENGTHS:
		*status = get_key_lengths(hdl, args);
		break;
	case OPERATION_ID_GET_KEY_ATTRIBUTES:
		*status = get_key_attributes(hdl, args);
		break;
	case OPERATION_ID_COMMIT_KEY_STORAGE:
		*status = commit_key_storage();
		break;
	default:
		return false;
	}

	return true;
}
