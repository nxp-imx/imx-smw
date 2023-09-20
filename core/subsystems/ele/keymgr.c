// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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

#define ELE_MAX_KEY_GROUP	       100U
#define ELE_FIRST_PERSISTENT_KEY_GROUP 0U
#define ELE_FIRST_TRANSIENT_KEY_GROUP  (ELE_MAX_KEY_GROUP / 2)
#define ELE_LAST_PERSISTENT_KEY_GROUP  (ELE_FIRST_TRANSIENT_KEY_GROUP - 1)
#define ELE_LAST_TRANSIENT_KEY_GROUP   (ELE_MAX_KEY_GROUP - 1)

struct key_group {
	bool persistent;
	bool full;
};

static int ecc_public_key_length(unsigned int security_size);

/*
 * OEM SRKH Key Identifier - Hardcoded value
 * This object is imported by EL2GO as RAW Type but must use the import key
 * operation.
 */
#define ELE_OEM_SRKH_KEY_ID 0x7FFF817A

/*
 * Bit mask identifing the key category, asymmetric public, keypair
 * symmetric key and raw key.
 */
#define ELE_KEY_CATEGORY_MASK	      ((unsigned int)(BIT(14) | BIT(13) | BIT(12)))
#define ELE_ASYM_KEY_TYPE_MASK	      BIT(14)
#define ELE_ASYM_PUBLIC_KEY_TYPE_MASK BIT(14)
#define ELE_ASYM_KEYPAIR_TYPE_MASK    ((unsigned int)(BIT(14) | BIT(13) | BIT(12)))
#define ELE_SYM_KEY_TYPE_MASK	      BIT(13)
#define ELE_RAW_KEY_TYPE_MASK	      BIT(12)

/*
 * Key lifetime encoding
 */
#define ELE_KEY_TRANSIENT  0x0
#define ELE_KEY_PERSISTENT 0x1
#define ELE_KEY_PERMANENT  0xFF

#define ELE_KEY_LIFETIME_PERSISTENCE_MASK 0xFF
#define ELE_KEY_LIFETIME_PERSISTENCE_GET(val)                                  \
	((val) & (ELE_KEY_LIFETIME_PERSISTENCE_MASK))
#define ELE_KEY_LIFETIME_LOCATION_MASK	0xFFFFFF
#define ELE_KEY_LIFETIME_LOCATION_SHIFT 8
#define ELE_KEY_LIFETIME_LOCATION_GET(val)                                     \
	(((val) >> ELE_KEY_LIFETIME_LOCATION_SHIFT) &                          \
	 ELE_KEY_LIFETIME_LOCATION_MASK)

/*
 * Macro setting the ELE key type category
 */
#define ELE_ASYM_PUBLIC_KEY_TYPE(type)                                         \
	SET_CLEAR_MASK(type, ELE_ASYM_PUBLIC_KEY_TYPE_MASK,                    \
		       ELE_KEY_CATEGORY_MASK)

#define ELE_ASYM_KEYPAIR_KEY_TYPE(type)                                        \
	SET_CLEAR_MASK(type, ELE_ASYM_KEYPAIR_TYPE_MASK, ELE_KEY_CATEGORY_MASK)

/**
 * struct ele_key_def - ELE Key definition
 * @smw_key_type: SMW Key type ID
 * @ele_key_type: ELE full key type ID (keypair, symmetric or raw)
 * @public_length: Function pointer calculating the public key length in bytes
 */
static const struct ele_key_def {
	enum smw_config_key_type_id smw_key_type;
	unsigned int ele_key_type;
	int (*public_length)(unsigned int security_size);
} ele_key_def_list[] = {
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .ele_key_type = HSM_KEY_TYPE_ECC_NIST,
	  .public_length = ecc_public_key_length },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .ele_key_type = HSM_KEY_TYPE_ECC_BP_R1,
	  .public_length = ecc_public_key_length },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .ele_key_type = HSM_KEY_TYPE_AES,
	  .public_length = NULL },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC,
	  .ele_key_type = HSM_KEY_TYPE_HMAC,
	  .public_length = NULL },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
	  .ele_key_type = HSM_KEY_TYPE_HMAC,
	  .public_length = NULL },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
	  .ele_key_type = HSM_KEY_TYPE_HMAC,
	  .public_length = NULL },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
	  .ele_key_type = HSM_KEY_TYPE_HMAC,
	  .public_length = NULL },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
	  .ele_key_type = HSM_KEY_TYPE_HMAC,
	  .public_length = NULL },
};

static int ecc_public_key_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size) * 2;
}

static const struct ele_key_def *
get_key_def_by_smw_type(enum smw_config_key_type_id key_type_id)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(ele_key_def_list);
	const struct ele_key_def *key = ele_key_def_list;
	const struct ele_key_def *ret_key = NULL;

	for (; i < size; i++, key++) {
		if (key->smw_key_type == key_type_id) {
			ret_key = key;
			break;
		}
	}

	return ret_key;
}

static const struct ele_key_def *get_key_def_by_ele_type(unsigned int key_type)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(ele_key_def_list);
	const struct ele_key_def *key = ele_key_def_list;
	const struct ele_key_def *ret_key = NULL;

	unsigned int full_key_type = key_type;

	if (key_type & ELE_ASYM_KEY_TYPE_MASK)
		full_key_type = ELE_ASYM_KEYPAIR_KEY_TYPE(key_type);

	for (; i < size; i++, key++) {
		if (key->ele_key_type == full_key_type) {
			ret_key = key;
			break;
		}
	}

	return ret_key;
}

static enum smw_keymgr_privacy_id
get_key_privacy_by_ele_type(unsigned int key_type)
{
	enum smw_keymgr_privacy_id privacy = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	if (key_type & ELE_ASYM_KEYPAIR_TYPE_MASK)
		privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if (key_type & ELE_ASYM_PUBLIC_KEY_TYPE_MASK)
		privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;

	return privacy;
}

static int get_full_ele_key_type(enum smw_config_key_type_id key_type_id,
				 hsm_key_type_t *ele_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	const struct ele_key_def *key_def = NULL;
	unsigned int key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_def = get_key_def_by_smw_type(key_type_id);
	if (key_def) {
		key_type = key_def->ele_key_type;
		if (!SET_OVERFLOW(key_type, *ele_type))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static enum smw_keymgr_persistence_id
get_key_persistence(hsm_key_lifetime_t lifetime)
{
	enum smw_keymgr_persistence_id persistence =
		SMW_KEYMGR_PERSISTENCE_ID_INVALID;

	switch (ELE_KEY_LIFETIME_PERSISTENCE_GET(lifetime)) {
	case ELE_KEY_TRANSIENT:
		persistence = SMW_KEYMGR_PERSISTENCE_ID_TRANSIENT;
		break;

	case ELE_KEY_PERSISTENT:
		persistence = SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT;
		break;

	case ELE_KEY_PERMANENT:
		persistence = SMW_KEYMGR_PERSISTENCE_ID_PERMANENT;
		break;

	default:
		break;
	}

	return persistence;
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

static int open_key_mgmt_service(struct hdl *hdl, hsm_hdl_t *key_management_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_management_args_t open_svc_key_management_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_key_management_service(hdl->key_store,
					      &open_svc_key_management_args,
					      key_management_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "Open key_management_hdl: %u\n",
		       *key_management_hdl);

	return ele_convert_err(err);
}

static int close_key_mgt_service(hsm_hdl_t key_management_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close key_management_hdl: %u\n",
		       key_management_hdl);

	if (key_management_hdl) {
		err = hsm_close_key_management_service(key_management_hdl);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
	}

	return ele_convert_err(err);
}

static int delete_key_operation(hsm_hdl_t key_mgt_hdl,
				struct smw_keymgr_identifier *key_identifier)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	op_delete_key_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.key_identifier = key_identifier->id;
	if (key_identifier->persistence_id ==
		    SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT ||
	    key_identifier->persistence_id ==
		    SMW_KEYMGR_PERSISTENCE_ID_PERMANENT)
		op_args.flags = HSM_OP_DEL_KEY_FLAGS_STRICT_OPERATION;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_delete_key()\n"
		       "  key_management_hdl: %u\n"
		       "  op_delete_key_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    flags: 0x%X\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.key_identifier,
		       op_args.flags);

	err = hsm_delete_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_delete_key returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes_operation(struct hdl *hdl,
					op_get_key_attr_args_t *key_attrs)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_get_key_attr()\n"
		       "  key_management_hdl: %u\n"
		       "  op_get_key_attr_args_t\n"
		       "    key_identifier: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl,
		       key_attrs->key_identifier);

	err = hsm_get_key_attr(key_mgt_hdl, key_attrs);
	SMW_DBG_PRINTF(DEBUG, "hsm_get_key_attr returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key_operation(struct hdl *hdl,
				struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_args = { 0 };

	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	unsigned char *public_data = NULL;
	unsigned char *tmp_key = NULL;
	unsigned int public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_export_key_config(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set the operation public key with user arguments */
	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);

	if (SET_OVERFLOW(public_length, op_args.out_key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.out_key = public_data;

	if (public_data && key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/*
		 * Assume the user buffer length is big enough, ELE subsystem
		 * will return the real public buffer length exported
		 */
		tmp_key = SMW_UTILS_MALLOC(op_args.out_key_size);
		if (!tmp_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_args.out_key = tmp_key;
	}

	op_args.key_identifier = key_identifier->id;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_pub_key_recovery()\n"
		       "  key_store_hdl: %u\n"
		       "  op_pub_key_recovery_args_t\n"
		       "    key identifier: 0x%08X\n"
		       "    Public Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, hdl->key_store,
		       op_args.key_identifier, op_args.out_key,
		       op_args.out_key_size);

	err = hsm_pub_key_recovery(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_pub_key_recovery returned %d\n", err);

	status = ele_convert_err(err);

	public_length = op_args.exp_out_key_size;

	if (status == SMW_STATUS_OK) {
		status = smw_keymgr_update_public_buffer(key_desc,
							 op_args.out_key,
							 public_length);
	} else if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status = smw_keymgr_update_public_buffer(key_desc, NULL,
							     public_length);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	if (tmp_key)
		SMW_UTILS_FREE(tmp_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int append_key_group(struct smw_utils_list *key_grp_list,
			    unsigned int grp, bool persistent, bool full)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct key_group *key_grp = NULL;

	key_grp = SMW_UTILS_MALLOC(sizeof(*key_grp));
	if (key_grp) {
		key_grp->persistent = persistent;
		key_grp->full = full;
		if (!smw_utils_list_append_data(key_grp_list, key_grp, grp,
						NULL)) {
			SMW_UTILS_FREE(key_grp);
			status = SMW_STATUS_ALLOC_FAILURE;
		} else {
			status = SMW_STATUS_OK;
		}
	}

	return status;
}

static int get_key_group(struct subsystem_context *ele_ctx, bool persistent,
			 unsigned int *out_grp)
{
	int status = SMW_STATUS_MUTEX_LOCK_FAILURE;

	struct node *node = NULL;
	struct key_group *key_grp = NULL;
	unsigned int grp = 0;
	unsigned int first_grp = *out_grp;
	unsigned int last_grp = ELE_LAST_TRANSIENT_KEY_GROUP;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(ele_ctx->key_grp_mutex))
		goto end;

	if (persistent)
		last_grp = ELE_LAST_PERSISTENT_KEY_GROUP;

	status = SMW_STATUS_OPERATION_FAILURE;
	for (grp = first_grp; grp <= last_grp; grp++) {
		node = smw_utils_list_find_first(&ele_ctx->key_grp_list, &grp);
		if (node) {
			key_grp = smw_utils_list_get_data(node);
			if (!key_grp) {
				status = SMW_STATUS_OPERATION_FAILURE;
				break;
			}

			if (key_grp->persistent == persistent &&
			    !key_grp->full) {
				*out_grp = grp;
				status = SMW_STATUS_OK;
				break;
			}
		} else {
			/* Create a new node entry in the list */
			status = append_key_group(&ele_ctx->key_grp_list, grp,
						  persistent, false);
			break;
		}
	}

	if (smw_utils_mutex_unlock(ele_ctx->key_grp_mutex) &&
	    status == SMW_STATUS_OK)
		status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s key group #%d returned %d\n", __func__,
		       *out_grp, status);
	return status;
}

static int set_key_group_state(struct subsystem_context *ele_ctx,
			       unsigned int grp, bool persistent, bool full)
{
	int status = SMW_STATUS_MUTEX_LOCK_FAILURE;

	struct node *node = NULL;
	struct key_group *key_grp = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(ele_ctx->key_grp_mutex))
		goto end;

	node = smw_utils_list_find_first(&ele_ctx->key_grp_list, &grp);
	if (node) {
		key_grp = smw_utils_list_get_data(node);
		if (key_grp && key_grp->persistent == persistent) {
			key_grp->full = full;
			status = SMW_STATUS_OK;
		} else {
			SMW_DBG_PRINTF(ERROR,
				       "%s: key group %u list data error (%p)",
				       __func__, grp, key_grp);
			status = SMW_STATUS_OPERATION_FAILURE;
		}

	} else {
		/* Create a new node entry in the list */
		status = append_key_group(&ele_ctx->key_grp_list, grp,
					  persistent, full);
	}

	if (smw_utils_mutex_unlock(ele_ctx->key_grp_mutex) &&
	    status == SMW_STATUS_OK)
		status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s key group #%d returned %d\n", __func__, grp,
		       status);
	return status;
}

static int generate_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_generate_key_args_t op_args = { 0 };

	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_attributes *key_attrs = &key_args->key_attributes;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	unsigned char *public_data = NULL;
	uint32_t key_id = 0;
	unsigned char *tmp_key = NULL;
	int policy_status = SMW_STATUS_KEY_POLICY_ERROR;
	unsigned char *actual_policy = NULL;
	unsigned int actual_policy_len = 0;
	unsigned int public_length = 0;
	bool persistent_grp = false;
	unsigned int key_group = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_full_ele_key_type(key_identifier->type_id,
				       &op_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set the operation public key with user arguments */
	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);
	if (SET_OVERFLOW(public_length, op_args.out_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.out_key = public_data;

	if (public_data && key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/*
		 * Assume the user buffer length is big enough, ELE subsystem
		 * will return the real public buffer length exported
		 */
		tmp_key = SMW_UTILS_MALLOC(op_args.out_size);
		if (!tmp_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_args.out_key = tmp_key;
	}

	op_args.key_identifier = &key_id;
	if (SET_OVERFLOW(key_identifier->security_size, op_args.bit_key_sz)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	policy_status =
		ele_set_key_policy(key_attrs->policy, key_attrs->policy_len,
				   &op_args.key_usage, &op_args.permitted_algo,
				   &actual_policy, &actual_policy_len);
	if (policy_status != SMW_STATUS_OK &&
	    policy_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		status = policy_status;
		goto end;
	}

	switch (key_args->key_attributes.persistence) {
	case SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
		/* Force persistent key to be written in NVM */
		op_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_KEYMGR_PERSISTENCE_ID_PERMANENT:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_PERS_PERM;
		/* Force permanant key to be written in NVM */
		op_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	default:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_group = ELE_FIRST_TRANSIENT_KEY_GROUP;
		break;
	}

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	do {
		/*
		 * Set the expected key identifier in case of ELE returns
		 * NVM storage group full. ELE erases the key identifier of
		 * the operation argument.
		 */
		key_id = key_identifier->id;

		status = get_key_group(ele_ctx, persistent_grp, &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_args.key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_generate_key()\n"
			       "key_management_hdl: %u\n"
			       "op_generate_key_args_t\n"
			       "    flags: 0x%X\n"
			       "    key identifier (%p): 0x%08X\n"
			       "    key policy\n"
			       "      - type: 0x%04X\n"
			       "      - size (bits): %d\n"
			       "      - group: %d\n"
			       "      - lifetime: 0x%X\n"
			       "      - usage: 0x%04X\n"
			       "      - algo: 0x%08X\n"
			       "    Public Key (output)\n"
			       "      - buffer: %p\n"
			       "      - size: %d\n",
			       __func__, __LINE__, key_mgt_hdl, op_args.flags,
			       op_args.key_identifier, *op_args.key_identifier,
			       op_args.key_type, op_args.bit_key_sz,
			       op_args.key_group, op_args.key_lifetime,
			       op_args.key_usage, op_args.permitted_algo,
			       op_args.out_key, op_args.out_size);

		err = hsm_generate_key(key_mgt_hdl, &op_args);
		SMW_DBG_PRINTF(DEBUG, "hsm_generate_key returned %d\n", err);

		if (err == HSM_KEY_GROUP_FULL) {
			status = set_key_group_state(ele_ctx, key_group,
						     persistent_grp, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_GROUP_FULL);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status =
			smw_keymgr_update_public_buffer(key_desc, NULL,
							op_args.exp_out_size);

		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_ELE;
	key_identifier->id = key_id;
	key_identifier->group = key_group;

	SMW_DBG_PRINTF(DEBUG, "ELE Key identifier: 0x%08X\n", key_id);

	if (public_data) {
		status = smw_keymgr_update_public_buffer(key_desc,
							 op_args.out_key,
							 op_args.exp_out_size);

		if (status != SMW_STATUS_OK) {
			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(key_mgt_hdl, key_identifier);
		}
	}

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	if (tmp_key)
		SMW_UTILS_FREE(tmp_key);

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

static int import_el2go_key(struct hdl *hdl,
			    struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	hsm_hdl_t key_mgt_hdl = 0;
	op_import_key_args_t op_args = { 0 };

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto exit;

	op_args.input_lsb_addr = smw_keymgr_get_private_data(key_desc);
	op_args.input_size = smw_keymgr_get_private_length(key_desc);
	op_args.flags = HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV |
			HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_import_key()\n"
		       "  key_store_hdl: 0x%x\n"
		       "  op_import_key_args_t (EdgeLock 2GO)\n"
		       "    Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.input_lsb_addr,
		       op_args.input_size);

	err = hsm_import_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_import_key returned %d\n", err);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OK) {
		SMW_DBG_PRINTF(DEBUG, "hsm_import_key key id 0x%08X\n",
			       op_args.key_identifier);
		key_desc->identifier.id = op_args.key_identifier;
	}

exit:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	return status;
}

static int import_el2go_data(struct hdl *hdl,
			     struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_data_storage_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.data_id = key_desc->identifier.id;
	op_args.data = smw_keymgr_get_private_data(key_desc);
	op_args.data_size = smw_keymgr_get_private_length(key_desc);
	op_args.flags = HSM_OP_DATA_STORAGE_FLAGS_STORE |
			HSM_OP_DATA_STORAGE_FLAGS_EL2GO;

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

static int import_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct smw_keymgr_import_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = NULL;
	unsigned int storage_id = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = &key_args->key_descriptor;
	storage_id = key_desc->identifier.storage_id;

	if (!NXP_IS_EL2GO_OBJECT(storage_id)) {
		SMW_DBG_PRINTF(ERROR,
			       "Support only EdgeLock 2GO key/data import");
		goto end;
	}

	if (!smw_keymgr_get_private_data(key_desc)) {
		SMW_DBG_PRINTF(ERROR, "EdgeLock 2GO import key missing buffer");
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (NXP_IS_EL2GO_KEY(storage_id) ||
	    (NXP_IS_EL2GO_OBJECT(storage_id) &&
	     key_desc->identifier.id == ELE_OEM_SRKH_KEY_ID))
		status = import_el2go_key(hdl, key_desc);
	else
		status = import_el2go_data(hdl, key_desc);
end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = export_key_operation(hdl, &key_args->key_descriptor);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_hdl_t key_mgt_hdl = 0;

	struct smw_keymgr_delete_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	status = delete_key_operation(key_mgt_hdl, &key_desc->identifier);

	tmp_status = close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK) {
		status = tmp_status;

		/* Let assume there is place to add a new key */
		tmp_status =
			set_key_group_state(ele_ctx, key_desc->identifier.group,
					    key_desc->identifier.persistence_id,
					    false);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_lengths(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_desc = NULL;
	op_get_key_attr_args_t key_attrs = { 0 };

	const struct ele_key_def *key_def = NULL;
	unsigned int public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = args;

	key_attrs.key_identifier = key_desc->identifier.id;

	status = get_key_attributes_operation(hdl, &key_attrs);

	if (status == SMW_STATUS_OK) {
		key_def = get_key_def_by_ele_type(key_attrs.key_type);
		if (key_def && key_def->public_length)
			public_length =
				key_def->public_length(key_attrs.bit_key_sz);

		/*
		 * Only public key is available, private or symmetric key
		 * are never exported.
		 * RSA key are not supported.
		 */
		status = smw_keymgr_update_public_buffer(key_desc, NULL,
							 public_length);

		tmp_status =
			smw_keymgr_update_private_buffer(key_desc, NULL, 0);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_get_key_attributes_args *key_attrs = NULL;
	op_get_key_attr_args_t op_key_attrs = { 0 };
	const struct ele_key_def *key_def = NULL;
	unsigned char *policy_list = NULL;
	unsigned char *lifecycle_list = NULL;
	unsigned int policy_list_length = 0;
	unsigned int lifecycle_list_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_attrs = args;

	op_key_attrs.key_identifier = key_attrs->identifier.id;

	status = get_key_attributes_operation(hdl, &op_key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	key_def = get_key_def_by_ele_type(op_key_attrs.key_type);
	if (!key_def) {
		status = SMW_STATUS_KEY_INVALID;
		goto end;
	}

	key_attrs->identifier.type_id = key_def->smw_key_type;
	key_attrs->identifier.security_size = op_key_attrs.bit_key_sz;
	key_attrs->identifier.privacy_id =
		get_key_privacy_by_ele_type(op_key_attrs.key_type);
	key_attrs->identifier.persistence_id =
		get_key_persistence(op_key_attrs.key_lifetime);
	key_attrs->identifier.storage_id =
		ELE_KEY_LIFETIME_LOCATION_GET(op_key_attrs.key_lifetime);

	if (key_attrs->pub) {
		status = ele_get_key_policy(&policy_list, &policy_list_length,
					    op_key_attrs.key_usage,
					    op_key_attrs.permitted_algo);

		if (status == SMW_STATUS_OK)
			status = ele_get_lifecycle(&lifecycle_list,
						   &lifecycle_list_length,
						   op_key_attrs.lifecycle);

		if (status == SMW_STATUS_OK) {
			smw_keymgr_set_policy(key_attrs, policy_list,
					      policy_list_length);
			smw_keymgr_set_lifecycle(key_attrs, lifecycle_list,
						 lifecycle_list_length);
		} else {
			if (policy_list)
				SMW_UTILS_FREE(policy_list);

			if (lifecycle_list)
				SMW_UTILS_FREE(lifecycle_list);
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int commit_key_storage(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_manage_key_group_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.flags = HSM_OP_MANAGE_KEY_GROUP_FLAGS_MONOTONIC |
			HSM_OP_MANAGE_KEY_GROUP_FLAGS_SYNC_KEYSTORE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_manage_key_group()\n"
		       "  key_management_hdl: %u\n"
		       "  op_manage_key_group_args_t\n"
		       "    key_group: 0x%08X\n"
		       "    flags: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.key_group,
		       op_args.flags);

	err = hsm_manage_key_group(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_manage_key_group returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_set_pubkey_type(enum smw_config_key_type_id key_type_id,
			hsm_pubkey_type_t *ele_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	const struct ele_key_def *key_def = NULL;
	unsigned int type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_def = get_key_def_by_smw_type(key_type_id);
	if (key_def) {
		type = ELE_ASYM_PUBLIC_KEY_TYPE(key_def->ele_key_type);
		if (!SET_OVERFLOW(type, *ele_type))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_export_public_key(struct hdl *hdl,
			  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int public_length = 0;
	op_get_key_attr_args_t key_attrs = { 0 };
	const struct ele_key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* First get the key attributes */
	key_attrs.key_identifier = key_desc->identifier.id;
	status = get_key_attributes_operation(hdl, &key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get the ELE key definition */
	key_def = get_key_def_by_ele_type(key_attrs.key_type);
	if (!key_def) {
		SMW_DBG_PRINTF(VERBOSE,
			       "%s: ELE key type 0x%08x not supported\n",
			       __func__, key_attrs.key_type);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (key_def->smw_key_type == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		SMW_DBG_PRINTF(VERBOSE, "%s: RSA key not supported\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (!key_def->public_length) {
		SMW_DBG_PRINTF(VERBOSE, "%s: No public key\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_desc->identifier.type_id = key_def->smw_key_type;
	key_desc->identifier.security_size = key_attrs.bit_key_sz;
	key_desc->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	public_length = key_def->public_length(key_attrs.bit_key_sz);

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

bool ele_key_handle(struct subsystem_context *ele_ctx,
		    enum operation_id operation_id, void *args, int *status)
{
	struct hdl *hdl = NULL;

	SMW_DBG_ASSERT(ele_ctx && args);

	hdl = &ele_ctx->hdl;

	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(ele_ctx, args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = ele_derive_key(hdl, args);
		break;
	case OPERATION_ID_UPDATE_KEY:
		*status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = import_key(hdl, args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(hdl, args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(ele_ctx, args);
		break;
	case OPERATION_ID_GET_KEY_LENGTHS:
		*status = get_key_lengths(hdl, args);
		break;
	case OPERATION_ID_GET_KEY_ATTRIBUTES:
		*status = get_key_attributes(hdl, args);
		break;
	case OPERATION_ID_COMMIT_KEY_STORAGE:
		*status = commit_key_storage(hdl);
		break;
	default:
		return false;
	}

	return true;
}
