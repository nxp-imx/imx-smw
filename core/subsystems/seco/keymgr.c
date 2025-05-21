// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "object_query.h"

#include "common.h"

/* There is no SECO master key type value */
#define HSM_KEY_TYPE_TLS_MASTER 0

#define KEY_DEF(_key_type_id, _security_size, _public_key_size, _key_type)     \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_size = _security_size,                               \
		.public_key_size = _public_key_size,                           \
		.key_type = HSM_KEY_TYPE_##_key_type                           \
	}

/* Key type IDs must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest
 * for 1 given Key type ID.
 * This sorting is required to simplify the implementation of set_key_type().
 */
static const struct key_def {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	unsigned short public_key_size;
	hsm_key_type_t key_type;
} key_def_list[] = { KEY_DEF(SECP_R1, 256, 64, ECDSA_NIST_P256),
		     KEY_DEF(SECP_R1, 384, 96, ECDSA_NIST_P384),
		     KEY_DEF(BRAINPOOL_R1, 256, 64, ECDSA_BRAINPOOL_R1_256),
		     KEY_DEF(BRAINPOOL_R1, 384, 96, ECDSA_BRAINPOOL_R1_384),
		     KEY_DEF(AES, 128, 0, AES_128),
		     KEY_DEF(AES, 192, 0, AES_192),
		     KEY_DEF(AES, 256, 0, AES_256),
		     KEY_DEF(HMAC, 224, 0, HMAC_224),
		     KEY_DEF(HMAC, 256, 0, HMAC_256),
		     KEY_DEF(HMAC, 384, 0, HMAC_384),
		     KEY_DEF(HMAC, 512, 0, HMAC_512),
		     KEY_DEF(TLS_MASTER, TLS12_MASTER_SECRET_SEC_SIZE, 0,
			     TLS_MASTER) };

static int set_key_type(enum smw_config_key_type_id key_type_id,
			unsigned int security_size, hsm_key_type_t *key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_def_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (key_def_list[i].key_type_id < key_type_id)
			continue;
		if (key_def_list[i].key_type_id > key_type_id)
			goto end;
		if (key_def_list[i].security_size < security_size)
			continue;
		if (key_def_list[i].security_size > security_size)
			goto end;
		*key_type = key_def_list[i].key_type;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "Key Type: %d\n", *key_type);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned short get_public_key_length(hsm_key_type_t key_type)
{
	unsigned short length = 0;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_def_list);
	const struct key_def *key = key_def_list;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++, key++) {
		if (key->key_type == key_type) {
			length = key->public_key_size;
			break;
		}
	}

	SMW_DBG_PRINTF(DEBUG, "Public key size %d bytes\n", length);
	return length;
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
	unsigned short key_size = 0;
	unsigned int max_public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	public_data = smw_keymgr_get_public_data(key_desc);

	/* SECO requires exact asymmetric public key size */
	key_size = get_public_key_length(key_type);
	if (!key_size) {
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
	max_public_length = key_size;
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

		*length = key_size;
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
 * SECO secure subsystem only exports Secp R1 and Brainpool R1 public key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (key_descriptor->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_SECP_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_R1:
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
	unsigned short key_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_export_key_config(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_key_type(key_desc->identifier.type_id,
			      key_desc->identifier.security_size,
			      &op_export_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_reallocate_public_buffer(&tmp_key, &key_size, key_desc,
						op_export_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	op_export_key_args.key_identifier = key_desc->identifier.id;

	op_export_key_args.out_key = tmp_key;
	op_export_key_args.out_key_size = key_size;

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
	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_update_public_buffer(key_desc, tmp_key, key_size);

end:
	if (tmp_key && tmp_key != smw_keymgr_get_public_data(key_desc))
		SMW_UTILS_FREE(tmp_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key_operation(struct subsystem_context *seco_ctx,
				struct smw_keymgr_identifier *key_identifier)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	struct smw_key_attributes *key_attributes =
		&key_identifier->key_attributes;

	hsm_err_t err = HSM_NO_ERROR;

	hsm_hdl_t key_mgt_hdl = 0;
	op_manage_key_args_t manage_key_args = { 0 };
	bool is_transient = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	manage_key_args.key_identifier = &key_identifier->id;
	manage_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;

	if (SMW_ATTR_IS_PERSISTENT(key_attributes->attributes) ||
	    SMW_ATTR_IS_PERMANENT(key_attributes->attributes))
		manage_key_args.flags |=
			HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION;

	status = set_key_type(key_identifier->type_id,
			      key_identifier->security_size,
			      &manage_key_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	manage_key_args.key_group = key_identifier->group;

	status = seco_open_key_mgmt_service(&seco_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_manage_key()\n"
		       "  op_manage_key_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    input_size: %d\n"
		       "    flags: 0x%02X\n"
		       "    key_type: %d\n"
		       "    key_group: %d\n"
		       "    key_info: 0x%04X\n"
		       "    input_data: %p\n",
		       __func__, __LINE__, *manage_key_args.key_identifier,
		       manage_key_args.input_size, manage_key_args.flags,
		       manage_key_args.key_type, manage_key_args.key_group,
		       manage_key_args.key_info, manage_key_args.input_data);

	err = hsm_manage_key(key_mgt_hdl, &manage_key_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_manage_key returned %d\n", err);

	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Let assume there is place to add a new key */
	is_transient = SMW_ATTR_IS_TRANSIENT(key_attributes->attributes);
	status = seco_set_key_group_state(seco_ctx, key_identifier->group,
					  !is_transient, false);

end:
	tmp_status = seco_close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key(struct subsystem_context *seco_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	hsm_hdl_t key_mgt_hdl = 0;
	op_generate_key_args_t op_generate_key_args = { 0 };

	struct smw_keymgr_generate_key_args *generate_key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&generate_key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	struct smw_key_attributes *key_attributes =
		&key_identifier->key_attributes;
	unsigned char *public_data = NULL;
	uint32_t key_id = 0;
	unsigned char *tmp_key = NULL;
	unsigned short key_size = 0;
	hsm_key_type_t key_type = 0;
	smw_attr_attributes_t persistence = 0;
	bool persistent_grp = false;
	unsigned int key_group = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = set_key_type(key_identifier->type_id,
			      key_identifier->security_size, &key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	public_data = smw_keymgr_get_public_data(key_descriptor);
	if (public_data) {
		status = check_reallocate_public_buffer(&tmp_key, &key_size,
							key_descriptor,
							key_type);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	op_generate_key_args.key_identifier = &key_id;
	op_generate_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;

	op_generate_key_args.key_type = key_type;
	op_generate_key_args.out_key = tmp_key;
	op_generate_key_args.out_size = key_size;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	persistence = key_identifier->key_attributes.attributes;
	persistence = SMW_ATTR_GET_PERSISTENCE(persistence);

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
		op_generate_key_args.key_info = HSM_KEY_INFO_PERSISTENT;
		/* Force persistent key to be written in NVM */
		op_generate_key_args.flags |=
			HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = SECO_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_PERMANENT:
		op_generate_key_args.key_info = HSM_KEY_INFO_PERMANENT;
		/* Force permanent key to be written in NVM */
		op_generate_key_args.flags |=
			HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = SECO_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		op_generate_key_args.key_info = HSM_KEY_INFO_TRANSIENT;
		key_group = SECO_FIRST_TRANSIENT_KEY_GROUP;
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = seco_open_key_mgmt_service(&seco_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	do {
		status = seco_get_key_group(seco_ctx, persistent_grp,
					    &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_generate_key_args.key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_generate_key()\n"
			       "op_generate_key_args_t\n"
			       "    key_identifier: @%p\n"
			       "    out_size: %d\n"
			       "    flags: 0x%02X\n"
			       "    key_type: %d\n"
			       "    key_group: %d\n"
			       "    key_info: 0x%04X\n"
			       "    out_key: %p\n",
			       __func__, __LINE__,
			       op_generate_key_args.key_identifier,
			       op_generate_key_args.out_size,
			       op_generate_key_args.flags,
			       op_generate_key_args.key_type,
			       op_generate_key_args.key_group,
			       op_generate_key_args.key_info,
			       op_generate_key_args.out_key);

		err = hsm_generate_key(key_mgt_hdl, &op_generate_key_args);
		SMW_DBG_PRINTF(DEBUG, "hsm_generate_key returned %d\n", err);

		/*
		 * There is no specific SECO error code indicating that the
		 * NVM Storage is full, hence let's assume that the NVM_KEY_STORE_ERROR
		 * will be returned only in case of key group full.
		 */
		if (err == HSM_KEY_STORE_ERROR) {
			status = seco_set_key_group_state(seco_ctx, key_group,
							  persistent_grp, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_STORE_ERROR);

	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_SECO;
	key_identifier->id = key_id;
	key_identifier->group = key_group;

	SMW_DBG_PRINTF(DEBUG, "Key identifier: 0x%08X\n", key_id);

	if (public_data) {
		status = smw_keymgr_update_public_buffer(key_descriptor,
							 tmp_key, key_size);
		if (status != SMW_STATUS_OK) {
			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(seco_ctx,
						   &key_descriptor->identifier);
			goto end;
		}
	}

	/*
	 * SECO handles neither key permitted algorithm nor usage.
	 * Keep the user permitted algorithm define as input to allow
	 * user to find the key per algorithm.
	 * If usage is not set, set all usages.
	 * TODO in future, add SW management of permitted algorithm and usages.
	 */
	if (!key_attributes->usage_flags) {
		key_attributes->usage_flags =
			SMW_ATTR_USAGE_DECRYPT | SMW_ATTR_USAGE_ENCRYPT |
			SMW_ATTR_USAGE_SIGN_HASH | SMW_ATTR_USAGE_SIGN_MESSAGE |
			SMW_ATTR_USAGE_VERIFY_HASH |
			SMW_ATTR_USAGE_VERIFY_MESSAGE | SMW_ATTR_USAGE_DERIVE;

		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

end:
	if (tmp_key && tmp_key != public_data)
		SMW_UTILS_FREE(tmp_key);

	tmp_status = seco_close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
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

static int delete_key(struct subsystem_context *seco_ctx, void *args)
{
	struct smw_keymgr_delete_key_args *delete_key_args = args;
	struct smw_keymgr_identifier *key_identifier =
		&delete_key_args->key_descriptor.identifier;

	return delete_key_operation(seco_ctx, key_identifier);
}

static int get_key_lengths(struct hdl *hdl, void *args)
{
	(void)hdl;

	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_desc = NULL;
	unsigned int public_length = 0;
	hsm_key_type_t key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = args;

	/*
	 * SECO subsystem doesn't expose services to get the key id attributes
	 * Let assume user key descriptor is correct to get the type and if
	 * key type is asymmetric key, get the public key size.
	 */
	status = set_key_type(key_desc->identifier.type_id,
			      key_desc->identifier.security_size, &key_type);

	if (status == SMW_STATUS_OK) {
		public_length = get_public_key_length(key_type);
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

	int status = SMW_STATUS_OK;

	struct smw_keymgr_get_key_attributes_args *key_args = args;
	struct smw_keymgr_identifier *identifier = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	identifier = &key_args->key_descriptor.identifier;

	identifier->key_attributes.usage_flags =
		SMW_ATTR_USAGE_DECRYPT | SMW_ATTR_USAGE_ENCRYPT |
		SMW_ATTR_USAGE_SIGN_HASH | SMW_ATTR_USAGE_SIGN_MESSAGE |
		SMW_ATTR_USAGE_VERIFY_HASH | SMW_ATTR_USAGE_VERIFY_MESSAGE |
		SMW_ATTR_USAGE_DERIVE;

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

static bool key_is_present(void *args, int *status)
{
	struct smw_object_query *obj_query = args;
	bool handled = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!obj_query) {
		*status = SMW_STATUS_INVALID_PARAM;
		handled = true;
		goto end;
	}

	if (obj_query->type == SMW_QUERY_TYPE_KEY) {
		/*
		 * Because of SECO limitation, there is no way to know if
		 * a key is present or not.
		 * Return SMW_STATUS_UNKNOWN_ID.
		 */
		*status = SMW_STATUS_UNKNOWN_ID;
		handled = true;
	}

end:
	SMW_DBG_PRINTF_COND(VERBOSE, handled, "%s returned %d\n", __func__,
			    *status);
	return handled;
}

int seco_export_public_key(struct hdl *hdl,
			   struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int public_length = 0;
	hsm_key_type_t key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * SECO subsystem doesn't expose services to get the key id attributes
	 * Let assume user key descriptor is correct to get the type and if
	 * key type is asymmetric key, get the public key size.
	 */
	status = set_key_type(key_desc->identifier.type_id,
			      key_desc->identifier.security_size, &key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	public_length = get_public_key_length(key_type);
	if (!public_length) {
		SMW_DBG_PRINTF(VERBOSE, "%s: No public key\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_desc->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	/* Allocate key descriptor's keypair buffer and its public data */
	status = smw_keymgr_alloc_keypair_buffer(key_desc, public_length, 0, 0);
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

bool seco_key_handle(struct subsystem_context *seco_ctx,
		     enum operation_id operation_id, void *args, int *status)
{
	struct hdl *hdl = NULL;

	SMW_DBG_ASSERT(seco_ctx && args);

	hdl = &seco_ctx->hdl;

	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(seco_ctx, args);
		// coverity[missing_unlock]
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = seco_derive_key(seco_ctx, args);
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = import_key(hdl, args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(hdl, args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(seco_ctx, args);
		// coverity[missing_unlock]
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
	case OPERATION_ID_IS_OBJECT_PRESENT:
		return key_is_present(args, status);
	default:
		return false;
	}

	return true;
}
